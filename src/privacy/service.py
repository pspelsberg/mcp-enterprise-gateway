from __future__ import annotations

import hmac
import secrets

from .detector import Entity, RegexDetector, assign_placeholders
from .vault import SessionVault
from src.core.models import DLPPolicyViolationError

_MAX_TERM_BYTES = 100
_MAX_TERMS = 50
_MAX_CUSTOM_MATCHES = 1_000
_MAX_ENTITIES = 1_000
_SECRET_ENTITY_TYPES = frozenset({
    "AWS_KEY", "ANTHROPIC_KEY", "OPENAI_KEY", "GITHUB_TOKEN", "PRIVATE_KEY",
    "JWT_TOKEN", "CONNECTION_STRING",
})


def _validate_terms(name: str, terms: list[str] | None) -> tuple[str, ...]:
    if terms is None:
        return ()
    if not isinstance(terms, list) or len(terms) > _MAX_TERMS:
        raise ValueError(f"{name} must contain at most 50 entries")
    if any(not isinstance(term, str) or not term or len(term.encode("utf-8")) > _MAX_TERM_BYTES for term in terms):
        raise ValueError(f"{name} terms must contain 1-100 UTF-8 bytes")
    return tuple(dict.fromkeys(terms))


def _literal_matches(text: str, terms: tuple[str, ...]) -> list[tuple[int, int]]:
    """Find literal client terms with a hard aggregate work bound."""
    matches: list[tuple[int, int]] = []
    for term in terms:
        start = 0
        while True:
            start = text.find(term, start)
            if start < 0:
                break
            matches.append((start, start + len(term)))
            if len(matches) > _MAX_CUSTOM_MATCHES:
                raise ValueError("too many whitelist or blacklist matches")
            start += len(term)
    return matches


def _overlaps(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < other_end and other_start < end for other_start, other_end in ranges)


class PrivacyService:
    def __init__(self, detector=None, vault=None, hash_key: bytes | None = None):
        self.detector = detector or RegexDetector()
        self.vault = vault or SessionVault()
        # A per-process secret prevents offline dictionary recovery of the hash
        # strategy while retaining stable replacement for repeated values.
        self._hash_key = hash_key or secrets.token_bytes(32)

    def anonymize(self, prompt, language="de", strategy="placeholder", whitelist=None, blacklist=None, on_secret="mask", principal_id: str | None = None):
        if not isinstance(prompt, str) or not isinstance(language, str) or not prompt:
            raise ValueError("prompt and language must be non-empty strings")
        if len(prompt.encode("utf-8")) > 100 * 1024:
            raise ValueError("prompt exceeds 100 KiB")
        if language not in getattr(self.detector, "languages", {"de", "en"}):
            raise ValueError("unsupported language")
        if strategy not in {"placeholder", "redact", "hash"}:
            raise ValueError("unsupported masking strategy")
        if on_secret not in {"mask", "block"}:
            raise ValueError("unsupported secret policy")
        whitelist_terms = _validate_terms("whitelist", whitelist)
        blacklist_terms = _validate_terms("blacklist", blacklist)

        whitelist_ranges = _literal_matches(prompt, whitelist_terms)
        blacklist_ranges = _literal_matches(prompt, blacklist_terms)
        detected = self.detector.detect(prompt, language)
        if len(detected) > _MAX_ENTITIES:
            raise ValueError("too many detected entities")
        technical_secrets = [entity for entity in detected if entity.entity_type in _SECRET_ENTITY_TYPES]
        if on_secret == "block" and technical_secrets:
            raise DLPPolicyViolationError("prohibited secret detected")

        # A PII whitelist is never a secret-release mechanism.  Client-provided
        # secret text is untrusted and must remain masked in every strategy.
        entities = [
            entity for entity in detected
            if entity.entity_type in _SECRET_ENTITY_TYPES
            or not _overlaps(entity.start, entity.end, whitelist_ranges)
        ]
        # Blacklist wins over whitelist and detector output. Longest terms first
        # make overlapping client-supplied terms deterministic.
        custom_entities = [Entity("CUSTOM", prompt[start:end], start, end) for start, end in blacklist_ranges]
        custom_entities = [
            Entity(entity.entity_type, entity.value, entity.start, entity.end, f"<CUSTOM_{index}>")
            for index, entity in enumerate(sorted(custom_entities, key=lambda item: item.start))
        ]
        selected = [entity for entity in entities if not _overlaps(entity.start, entity.end, blacklist_ranges)]
        selected.extend(custom_entities)
        selected = sorted(selected, key=lambda entity: (-(entity.end - entity.start), entity.start))
        non_overlapping: list[Entity] = []
        occupied: list[tuple[int, int]] = []
        for entity in selected:
            if not _overlaps(entity.start, entity.end, occupied):
                non_overlapping.append(entity)
                occupied.append((entity.start, entity.end))
        entities = assign_placeholders(sorted(non_overlapping, key=lambda entity: entity.start))

        result = prompt
        for entity in sorted(entities, key=lambda item: item.start, reverse=True):
            if entity.entity_type == "CUSTOM" or strategy == "placeholder":
                replacement = entity.placeholder
            elif strategy == "redact":
                replacement = f"[REDACTED_{entity.entity_type}]"
            else:
                digest = hmac.digest(self._hash_key, entity.value.encode("utf-8"), "sha256").hex()[:16]
                replacement = f"<HASH_{entity.entity_type}_{digest}>"
            result = result[:entity.start] + replacement + result[entity.end:]
        response = {"anonymized_prompt": result, "pii_count": len(entities)}
        if strategy == "placeholder" and entities:
            response["session_id"] = self.vault.create(entities, principal_id)
        else:
            # No mapping is useful for an empty PII result or a non-reversible strategy.
            self.vault.record_anonymization(entities)
            response["strategy"] = strategy
        return response

    def deanonymize(self, text, session_id, principal_id: str | None = None):
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if len(text.encode("utf-8")) > 100 * 1024:
            raise ValueError("text exceeds 100 KiB")
        return {"restored_text": self.vault.restore(session_id, text, principal_id)}

    def stats(self):
        languages = list(getattr(self.detector, "languages", ("de", "en")))
        modes = ({lang: self.detector.mode_for(lang) for lang in languages}
                 if hasattr(self.detector, "mode_for")
                 else {lang: self.detector.mode for lang in languages})
        return self.vault.stats_snapshot(self.detector.mode, languages, modes)
