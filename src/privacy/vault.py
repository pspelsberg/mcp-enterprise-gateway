from dataclasses import dataclass, field
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import threading
import uuid
from .detector import Entity
from src.core.models import SessionCapacityError, SessionNotFoundError, ResourceTooLargeError, UnauthorizedSessionError

@dataclass
class Session:
    mappings: dict[str, str]
    created_at: datetime
    size_bytes: int
    principal_id: str | None = None

@dataclass
class SessionVault:
    max_sessions: int = 1000
    ttl_seconds: int = 3600
    max_bytes: int = 100 * 1024 * 1024
    max_restore_bytes: int = 100 * 1024
    max_sessions_per_principal: int = 100
    sessions: dict[str, Session] = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: {"total_anonymizations": 0, "total_deanonymizations": 0, "total_pii_entities": 0, "entities_by_type": {}, "blocked_pii_types": {}, "expired_sessions": 0, "failed_deanonymizations": 0})
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _bytes: int = field(default=0, init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.max_sessions, int) or self.max_sessions < 1:
            raise ValueError("max_sessions must be positive")
        if not isinstance(self.ttl_seconds, int) or self.ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        if not isinstance(self.max_bytes, int) or self.max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        if not isinstance(self.max_restore_bytes, int) or self.max_restore_bytes < 1:
            raise ValueError("max_restore_bytes must be positive")
        if not isinstance(self.max_sessions_per_principal, int) or self.max_sessions_per_principal < 1:
            raise ValueError("max_sessions_per_principal must be positive")

    def _purge(self):
        now = datetime.now(timezone.utc)
        expired = [sid for sid, s in self.sessions.items() if now - s.created_at > timedelta(seconds=self.ttl_seconds)]
        for sid in expired:
            session = self.sessions.pop(sid, None)
            if session: self._bytes -= session.size_bytes
        self.stats["expired_sessions"] += len(expired)

    def create(self, entities: list[Entity], principal_id: str | None = None) -> str:
        with self._lock:
            self._purge()
            mappings = {e.placeholder: e.value for e in entities}
            size = sum(len(k.encode()) + len(v.encode()) for k, v in mappings.items())
            if size > self.max_bytes:
                raise ResourceTooLargeError("session mapping exceeds byte budget")
            principal_sessions = sum(session.principal_id == principal_id for session in self.sessions.values())
            if principal_sessions >= self.max_sessions_per_principal:
                raise SessionCapacityError("privacy session capacity exhausted")
            # Never let a noisy client silently evict a still-valid PII mapping.
            if len(self.sessions) >= self.max_sessions or self._bytes + size > self.max_bytes:
                raise SessionCapacityError("privacy session capacity exhausted")
            sid = str(uuid.uuid4())
            self.sessions[sid] = Session(mappings, datetime.now(timezone.utc), size, principal_id)
            self._bytes += size
            self._record_anonymization(entities)
            return sid

    def _record_anonymization(self, entities: list[Entity]) -> None:
        self.stats["total_anonymizations"] += 1
        self.stats["total_pii_entities"] += len(entities)
        for entity in entities:
            self.stats["entities_by_type"][entity.entity_type] = self.stats["entities_by_type"].get(entity.entity_type, 0) + 1
            self.stats["blocked_pii_types"][entity.entity_type] = self.stats["blocked_pii_types"].get(entity.entity_type, 0) + 1

    def record_anonymization(self, entities: list[Entity]) -> None:
        """Record a non-reversible anonymization without retaining mappings."""
        with self._lock:
            self._purge()
            self._record_anonymization(entities)

    def restore(self, sid: str, text: str, principal_id: str | None = None) -> str:
        with self._lock:
            self._purge()
            if not isinstance(text, str) or len(text.encode("utf-8")) > self.max_restore_bytes:
                self.stats["failed_deanonymizations"] += 1
                raise ResourceTooLargeError("restored response exceeds size limit")
            if not isinstance(sid, str) or len(sid) != 36:
                parsed = None
            else:
                try:
                    parsed = uuid.UUID(sid)
                except (ValueError, AttributeError, TypeError):
                    parsed = None
            if parsed is None or parsed.version != 4 or str(parsed) != sid:
                self.stats["failed_deanonymizations"] += 1
                raise SessionNotFoundError("session is unknown or expired")
            session = self.sessions.get(sid)
            if not session:
                self.stats["failed_deanonymizations"] += 1
                raise SessionNotFoundError("session is unknown or expired")
            if session.principal_id is not None and session.principal_id != principal_id:
                self.stats["failed_deanonymizations"] += 1
                raise UnauthorizedSessionError("session is not authorized")
            for placeholder, value in sorted(session.mappings.items(), key=lambda x: -len(x[0])):
                text = text.replace(placeholder, value)
                if len(text.encode("utf-8")) > self.max_restore_bytes:
                    self.stats["failed_deanonymizations"] += 1
                    raise ResourceTooLargeError("restored response exceeds size limit")
            self.stats["total_deanonymizations"] += 1
            return text

    def stats_snapshot(self, detector_mode: str, languages: list[str], detector_modes: dict[str, str] | None = None) -> dict:
        with self._lock:
            self._purge()
            snapshot = deepcopy(self.stats)
            return {**snapshot, "active_sessions": len(self.sessions), "detector_mode": detector_mode, "detector_modes": detector_modes or {}, "supported_languages": list(languages)}
