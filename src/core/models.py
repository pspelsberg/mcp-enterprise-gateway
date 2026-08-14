from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_TEXT_BYTES = 100 * 1024

class AnonymizeInput(BaseModel):
    prompt: str = Field(min_length=1)
    language: str = "de"
    @field_validator("prompt")
    @classmethod
    def prompt_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("prompt exceeds 100 KiB")
        return v
    @field_validator("language")
    @classmethod
    def lang(cls, v: str) -> str:
        if v not in {"de", "en"}: raise ValueError("language must be 'de' or 'en'")
        return v

class DeanonymizeInput(BaseModel):
    text: str = Field(min_length=1)
    session_id: str
    @field_validator("text")
    @classmethod
    def text_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("text exceeds 100 KiB")
        return v

class QueryInput(BaseModel):
    query: str = Field(min_length=1)
    project_id: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    top_k: int = Field(default=5, ge=1, le=50)
    @field_validator("query")
    @classmethod
    def query_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_TEXT_BYTES: raise ValueError("query exceeds 100 KiB")
        return v

class ExecuteInput(BaseModel):
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
class DockerDaemonUnavailableError(GatewayError): code = "docker_daemon_unavailable"
class SandboxExecutionError(GatewayError): code = "sandbox_execution_error"
class KnowledgeUnavailableError(GatewayError): code = "knowledge_unavailable"
class ConceptNotFoundError(GatewayError): code = "concept_not_found"

class SafeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
