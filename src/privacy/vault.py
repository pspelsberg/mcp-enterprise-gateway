from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import uuid
from .detector import Entity
from src.core.models import SessionNotFoundError

@dataclass
class Session:
    mappings: dict[str, str]
    created_at: datetime

@dataclass
class SessionVault:
    max_sessions: int = 1000
    ttl_seconds: int = 3600
    sessions: dict[str, Session] = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: {"total_anonymizations": 0, "total_deanonymizations": 0, "total_pii_entities": 0, "entities_by_type": {}, "expired_sessions": 0, "failed_deanonymizations": 0})

    def _purge(self):
        now=datetime.now(timezone.utc)
        expired=[sid for sid,s in self.sessions.items() if now-s.created_at > timedelta(seconds=self.ttl_seconds)]
        for sid in expired: self.sessions.pop(sid, None)
        self.stats["expired_sessions"] += len(expired)
    def create(self, entities: list[Entity]) -> str:
        self._purge()
        while len(self.sessions) >= self.max_sessions: self.sessions.pop(next(iter(self.sessions)))
        sid=str(uuid.uuid4()); self.sessions[sid]=Session({e.placeholder:e.value for e in entities}, datetime.now(timezone.utc))
        self.stats["total_anonymizations"] += 1; self.stats["total_pii_entities"] += len(entities)
        for e in entities: self.stats["entities_by_type"][e.entity_type]=self.stats["entities_by_type"].get(e.entity_type,0)+1
        return sid
    def restore(self, sid: str, text: str) -> str:
        self._purge(); session=self.sessions.get(sid)
        if not session: self.stats["failed_deanonymizations"] += 1; raise SessionNotFoundError("session is unknown or expired")
        self.stats["total_deanonymizations"] += 1
        for placeholder,value in sorted(session.mappings.items(), key=lambda x: -len(x[0])): text=text.replace(placeholder,value)
        return text
    def stats_snapshot(self, detector_mode: str, languages: list[str]) -> dict:
        self._purge(); return {**self.stats, "active_sessions":len(self.sessions), "detector_mode":detector_mode, "supported_languages":languages}
