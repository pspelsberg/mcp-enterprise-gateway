from __future__ import annotations

import hashlib

from .detector import Entity, RegexDetector, assign_placeholders
from .vault import SessionVault
from src.core.models import DLPPolicyViolationError

_MAX_TERM_BYTES = 100
_MAX_TERMS = 50


def _validate_terms(name: str, terms: list[str] | None) -> tuple[str, ...]:
    if terms is None:
        return ()
    if not isinstance(terms, list) or len(terms) > _MAX_TERMS:
        raise ValueError(f"{name} must contain at most 50 entries")
    if any(not isinstance(term, str) or not term or len(term) > _MAX_TERM_BYTES for term in terms):
        raise ValueError(f"{name} terms must contain 1-100 characters")
    return tuple(dict.fromkeys(terms))


def _literal_matches(text: str, terms: tuple[str, ...]) -> list[tuple[int, int]]:
    """Find literal terms without compiling user input as a regex."""
    matches: list[tuple[int, int]] = []
    for term in terms:
        start = 0
        while True:
            start = text.find(term, start)
            if start < 0:
                break
            matches.append((start, start + len(term)))
            start += len(term)
    return matches


def _overlaps(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < other_end and other_start < end for other_start, other_end in ranges)


class PrivacyService:
    def __init__(self, detector=None, vault=None):
        self.detector = detector or RegexDetector()
        self.vault = vault or SessionVault()

    def anonymize(self, prompt, language="de", strategy="placeholder", whitelist=None, blacklist=None, on_secret="mask"):

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
        technical_secrets = [entity for entity in detected if entity.entity_type in {"AWS_KEY", "PRIVATE_KEY", "CONNECTION_STRING"}]
        if on_secret == "block" and technical_secrets:
            raise DLPPolicyViolationError("prohibited secret detected")
        entities: list[Entity] = []
        for entity in detected:
            if not _overlaps(entity.start, entity.end, whitelist_ranges):
                entities.append(entity)
        # Blacklist wins over whitelist and detector output. Longest terms first
        # make overlapping client-supplied terms deterministic.
        custom_entities = [Entity("CUSTOM", prompt[start:end], start, end) for index, (start, end) in enumerate(blacklist_ranges)]
        custom_entities = [Entity(entity.entity_type, entity.value, entity.start, entity.end, f"<CUSTOM_{index}>") for index, entity in enumerate(sorted(custom_entities, key=lambda item: item.start))]
        selected = [entity for entity in entities if not _overlaps(entity.start, entity.end, blacklist_ranges)]
        selected.extend(custom_entities)
        selected = sorted(selected, key=lambda entity: (-(entity.end - entity.start), entity.start))
        non_overlapping: list[Entity] = []
        for entity in selected:
            if not _overlaps(entity.start, entity.end, [(item.start, item.end) for item in non_overlapping]):
                non_overlapping.append(entity)
        entities = assign_placeholders(sorted(non_overlapping, key=lambda entity: entity.start))

        result = prompt
        mappings = entities if strategy == "placeholder" else []
        for entity in sorted(entities, key=lambda item: item.start, reverse=True):
            if entity.entity_type == "CUSTOM":
                # Blacklist is an unconditional policy override, independent
                # of the selected PII masking strategy.
                replacement = entity.placeholder
            elif strategy == "placeholder":
                replacement = entity.placeholder
            elif strategy == "redact":
                replacement = f"[REDACTED_{entity.entity_type}]"
            else:
                digest = hashlib.sha256(entity.value.encode("utf-8")).hexdigest()[:8]
                replacement = f"<HASH_{entity.entity_type}_{digest}>"
            result = result[:entity.start] + replacement + result[entity.end:]
        response = {"anonymized_prompt": result, "pii_count": len(entities)}
        if strategy == "placeholder":
            response["session_id"] = self.vault.create(mappings)
        else:
            response["strategy"] = strategy
        return response

    def deanonymize(self, text, session_id):
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if len(text.encode("utf-8")) > 100 * 1024:
            raise ValueError("text exceeds 100 KiB")
        return {"restored_text": self.vault.restore(session_id, text)}

    def stats(self):
        languages = list(getattr(self.detector, "languages", ("de", "en")))
        modes = ({lang: self.detector.mode_for(lang) for lang in languages}
                 if hasattr(self.detector, "mode_for")
                 else {lang: self.detector.mode for lang in languages})
        return self.vault.stats_snapshot(self.detector.mode, languages, modes)
