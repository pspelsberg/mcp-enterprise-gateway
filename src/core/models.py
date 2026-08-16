from typing import Literal
import re
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_TEXT_BYTES = 100 * 1024

class GatewayInput(BaseModel):
    # Reject unknown fields at the MCP boundary; silently ignored fields make
    # contracts ambiguous and can enable mass-assignment mistakes.
    model_config = ConfigDict(extra="forbid")

class AnonymizeInput(GatewayInput):
    prompt: str = Field(min_length=1)
    language: str = "de"
    strategy: Literal["placeholder", "redact", "hash"] = "placeholder"
    on_secret: Literal["mask", "block"] = "mask"
    whitelist: list[str] | None = Field(default=None, max_length=50)
    blacklist: list[str] | None = Field(default=None, max_length=50)
    @field_validator("prompt")
    @classmethod
    def prompt_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("prompt exceeds 100 KiB")
        return v
    @field_validator("language")
    @classmethod
    def lang(cls, v: str) -> str:
        if v not in {"de", "en", "fr", "it", "es"}: raise ValueError("unsupported language")
        return v

    @field_validator("whitelist", "blacklist")
    @classmethod
    def terms(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        if len(values) > 50 or any(not isinstance(value, str) or not value or len(value) > 100 for value in values):
            raise ValueError("whitelist and blacklist terms must contain 1-100 characters and at most 50 entries")
        return values

class DeanonymizeInput(GatewayInput):
    text: str = Field(min_length=1)
    session_id: str
    @field_validator("session_id")
    @classmethod
    def valid_session_id(cls, v: str) -> str:
        if len(v) != 36:
            raise ValueError("session_id must be a UUIDv4")
        try:
            parsed = uuid.UUID(v)
        except (ValueError, AttributeError):
            raise ValueError("session_id must be a UUID")
        if parsed.version != 4 or str(parsed) != v:
            raise ValueError("session_id must be a canonical UUIDv4")
        return v
    @field_validator("text")
    @classmethod
    def text_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("text exceeds 100 KiB")
        return v

class QueryInput(GatewayInput):
    query: str = Field(min_length=1)
    project_id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$", max_length=128)
    top_k: int = Field(default=5, ge=1, le=50)
    search_mode: Literal["vector", "hybrid"] = "vector"
    @field_validator("query")
    @classmethod
    def query_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("query exceeds 100 KiB")
        return v

class ExecuteInput(GatewayInput):
    code: str = Field(min_length=1)
    language: str = "python"
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    @field_validator("code")
    @classmethod
    def code_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("code exceeds 100 KiB")
        return v
    @field_validator("language")
    @classmethod
    def language_allowed(cls, v: str) -> str:
        if v not in {"python", "javascript"}: raise ValueError("language must be python or javascript")
        return v

class GatewayError(Exception):
    code = "gateway_error"
    def __init__(self, message: str): self.message = message; super().__init__(message)

class SessionNotFoundError(GatewayError): code = "session_not_found"
class DLPPolicyViolationError(GatewayError): code = "prohibited_secret_detected"
class SandboxTimeoutError(GatewayError): code = "sandbox_timeout"
class UnsupportedLanguageError(GatewayError): code = "unsupported_language"
class SandboxImageIntegrityError(GatewayError): code = "sandbox_image_integrity_error"
class ResourceTooLargeError(GatewayError): code = "resource_too_large"
class UnauthorizedProjectError(GatewayError): code = "project_not_authorized"
class UnauthorizedSessionError(GatewayError): code = "session_not_authorized"
class RateLimitExceededError(GatewayError): code = "rate_limit_exceeded"
class SessionCapacityError(GatewayError): code = "privacy_session_capacity_exhausted"
class DockerDaemonUnavailableError(GatewayError): code = "docker_daemon_unavailable"
class SandboxExecutionError(GatewayError): code = "sandbox_execution_error"
class SandboxCapacityError(GatewayError): code = "sandbox_capacity_exhausted"
class KnowledgeUnavailableError(GatewayError): code = "knowledge_unavailable"
class KnowledgeHybridUnavailableError(KnowledgeUnavailableError): code = "knowledge_hybrid_unavailable"
class ConceptNotFoundError(GatewayError): code = "concept_not_found"

class SafeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
