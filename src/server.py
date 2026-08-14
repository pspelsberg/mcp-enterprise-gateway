import argparse, json, os, sys, hmac, re
from typing import Literal
from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier
from starlette.requests import Request
from starlette.responses import JSONResponse
from pydantic import ValidationError
from src.core.models import AnonymizeInput, DeanonymizeInput, QueryInput, ExecuteInput, GatewayError
from src.privacy.service import PrivacyService
from src.privacy.detector import PresidioDetector
from src.knowledge.lancedb_adapter import LanceDBAdapter
from src.knowledge.okf_resource import OKFResourceProvider
from src.knowledge.embedding import LocalHashEmbedder
from src.sandbox.docker_runner import DockerRunner
from src.security_prompt.template import security_audit_prompt, dsgvo_pii_risk_audit_prompt

def _sse_auth():
    token = os.getenv("MCP_SSE_TOKEN")
    return StaticTokenVerifier({token: {"client_id": "local-client", "scopes": []}}) if token and len(token) >= 32 else None


def _configured_sse_port() -> int:
    raw = os.getenv("MCP_SSE_PORT", "8000")
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError("MCP_SSE_PORT must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise ValueError("MCP_SSE_PORT must be between 1024 and 65535")
    return port

mcp=FastMCP("Enterprise Gateway", mask_error_details=True, auth=_sse_auth())

def _privacy_service():
    # Model discovery is local-only. A missing model intentionally selects regex fallback.
    try:
        import spacy
        if not spacy.util.is_package("de_core_news_sm"):
            return PrivacyService(PresidioDetector())
        from presidio_analyzer import AnalyzerEngine
        return PrivacyService(PresidioDetector(AnalyzerEngine(), presidio_languages={"de", "en"}))
    except Exception:
        return PrivacyService(PresidioDetector())

privacy=_privacy_service()
def _allowed_projects():
    raw = os.getenv("MCP_ALLOWED_PROJECTS")
    if not raw:
        return None
    projects = {item.strip() for item in raw.split(",") if item.strip()}
    if not projects or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", item) for item in projects):
        raise ValueError("MCP_ALLOWED_PROJECTS contains an invalid project identifier")
    return projects
def _knowledge_adapter():
    path = os.getenv("LANCEDB_PATH")
    table_name = os.getenv("LANCEDB_TABLE", "knowledge")
    allowed_projects = _allowed_projects()
    if not path: return LanceDBAdapter(allowed_projects=allowed_projects)
    # A configured shared vector store must have an explicit tenant/project
    # allowlist.  Never silently turn a deployment typo into global search.
    if not allowed_projects:
        raise ValueError("MCP_ALLOWED_PROJECTS is required with LANCEDB_PATH")
    try:
        import lancedb
        table = lancedb.connect(path).open_table(table_name)
        return LanceDBAdapter(table, LocalHashEmbedder(), allowed_projects)
    except Exception as exc:
        # Configured storage failures are startup errors, never a silent
        # degraded mode that could hide tenant-isolation or schema mistakes.
        raise RuntimeError("configured LanceDB initialization failed") from exc
knowledge = _knowledge_adapter()
_sandbox_images = {"python": os.getenv("MCP_PYTHON_IMAGE", "python:3.11-slim@sha256:" + "0" * 64), "javascript": os.getenv("MCP_NODE_IMAGE", "node:20-alpine@sha256:" + "0" * 64)}
# Release policy is immutable: mutable-tag execution cannot be enabled via an
# environment variable.  Digest references are verified by DockerRunner.
sandbox = DockerRunner(images=_sandbox_images, require_digests=True)
okf=OKFResourceProvider(os.getenv("OKF_ROOT", str(__import__("pathlib").Path(__file__).resolve().parents[1] / "okf")))

def safe(call):
    try: return call()
    except GatewayError as exc: return {"error":{"code":exc.code,"message":exc.message}}
    except (ValidationError, ValueError): return {"error":{"code":"validation_error","message":"invalid input"}}
    except Exception: return {"error":{"code":"internal_error","message":"internal error"}}

def _anonymize_prompt(
    prompt: str,
    language: str = "de",
    strategy: Literal["placeholder", "redact", "hash"] = "placeholder",
    on_secret: Literal["mask", "block"] = "mask",
    whitelist: list[str] | None = None,
    blacklist: list[str] | None = None,
) -> dict:
    return safe(lambda: privacy.anonymize(**AnonymizeInput(
        prompt=prompt, language=language, strategy=strategy, on_secret=on_secret,
        whitelist=whitelist, blacklist=blacklist,
    ).model_dump()))
def _deanonymize_response(text: str, session_id: str) -> dict:
    return safe(lambda: privacy.deanonymize(DeanonymizeInput(text=text,session_id=session_id).text,session_id))
def _query_lancedb_vector(query: str, project_id: str, top_k: int=5, search_mode: str="vector") -> list:
    return safe(lambda: knowledge.query(**QueryInput(query=query,project_id=project_id,top_k=top_k,search_mode=search_mode).model_dump()))
def _execute_docker_code(code: str, language: str="python", timeout_seconds: int=10) -> dict:
    return safe(lambda: sandbox.run(**ExecuteInput(code=code,language=language,timeout_seconds=timeout_seconds).model_dump()))

@mcp.tool()
def anonymize_prompt(
    prompt: str,
    language: str = "de",
    strategy: Literal["placeholder", "redact", "hash"] = "placeholder",
    on_secret: Literal["mask", "block"] = "mask",
    whitelist: list[str] | None = None,
    blacklist: list[str] | None = None,
) -> dict:
    return _anonymize_prompt(prompt, language, strategy, on_secret, whitelist, blacklist)
@mcp.tool()
def deanonymize_response(text: str, session_id: str) -> dict: return _deanonymize_response(text, session_id)
@mcp.tool()
def query_lancedb_vector(query: str, project_id: str, top_k: int=5, search_mode: str="vector") -> list: return _query_lancedb_vector(query, project_id, top_k, search_mode)
@mcp.tool()
def execute_docker_code(code: str, language: str="python", timeout_seconds: int=10) -> dict: return _execute_docker_code(code, language, timeout_seconds)
@mcp.resource("okf://wiki/{concept_id}")
def okf_wiki(concept_id: str) -> str: return safe(lambda: okf.read(concept_id))
@mcp.resource("privacy://audit_stats")
def audit_stats() -> str: return safe(lambda: json.dumps(privacy.stats(),ensure_ascii=False))

@mcp.resource("gateway://health")
def gateway_health() -> str:
    """Bounded, non-sensitive local readiness/status snapshot."""
    knowledge_ready = knowledge.table is not None
    sandbox_ready = all("@sha256:" in image for image in (sandbox.images or {}).values())
    return json.dumps({
        "status": "ok" if knowledge_ready and sandbox_ready else "degraded",
        "liveness": "ok",
        "readiness": "ready" if knowledge_ready and sandbox_ready else "degraded",
        "detector_mode": privacy.detector.mode,
        "active_sessions": privacy.stats().get("active_sessions", 0),
        "knowledge_configured": knowledge_ready,
        "sandbox_policy": "digest-pinned" if sandbox_ready else "invalid",
    }, ensure_ascii=False, sort_keys=True)

@mcp.custom_route("/privacy/audit_stats", methods=["GET"], include_in_schema=False)
async def privacy_audit_stats_http(request: Request):
    """Authenticated loopback companion endpoint for the optional Audit Studio."""
    token = os.getenv("MCP_SSE_TOKEN")
    authorization = request.headers.get("authorization", "")
    expected = f"Bearer {token}" if token else ""
    if not token or len(token) < 32 or not hmac.compare_digest(authorization, expected):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(privacy.stats(), headers={"Cache-Control": "no-store"})


@mcp.prompt()
def grill_me_security_audit(architecture_description: str) -> str: return security_audit_prompt(architecture_description)

@mcp.prompt()
def dsgvo_pii_risk_audit(schema_description: str) -> str:
    return dsgvo_pii_risk_audit_prompt(schema_description)

def main():
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(); group.add_argument("--stdio",action="store_true"); group.add_argument("--sse",action="store_true"); args=parser.parse_args()
    if args.sse:
        token = os.getenv("MCP_SSE_TOKEN")
        if not token or len(token) < 32:
            parser.error("--sse requires MCP_SSE_TOKEN with at least 32 characters")
        print("WARNING: authenticated localhost SSE enabled; never expose it publicly.", file=sys.stderr)
        if not os.getenv("MCP_ALLOWED_PROJECTS"):
            parser.error("--sse requires MCP_ALLOWED_PROJECTS for project isolation")
        try:
            port = _configured_sse_port()
        except ValueError as exc:
            parser.error(str(exc))
        mcp.run(transport="sse", host="127.0.0.1", port=port)
    else: mcp.run(transport="stdio")
if __name__=="__main__": main()
