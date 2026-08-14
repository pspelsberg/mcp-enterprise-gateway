import argparse, json, os, sys
from fastmcp import FastMCP
from pydantic import ValidationError
from src.core.models import AnonymizeInput, DeanonymizeInput, QueryInput, ExecuteInput, GatewayError
from src.privacy.service import PrivacyService
from src.knowledge.lancedb_adapter import LanceDBAdapter
from src.knowledge.okf_resource import OKFResourceProvider
from src.sandbox.docker_runner import DockerRunner
from src.security_prompt.template import security_audit_prompt

mcp=FastMCP("Enterprise Gateway")
privacy=PrivacyService(); knowledge=LanceDBAdapter(); sandbox=DockerRunner(); okf=OKFResourceProvider(os.getenv("OKF_ROOT","okf"))

def safe(call):
    try: return call()
    except GatewayError as exc: return {"error":{"code":exc.code,"message":exc.message}}
    except (ValidationError, ValueError) as exc: return {"error":{"code":"validation_error","message":"invalid input"}}

def _anonymize_prompt(prompt: str, language: str="de") -> dict:
    return safe(lambda: privacy.anonymize(AnonymizeInput(prompt=prompt,language=language).prompt,language))
def _deanonymize_response(text: str, session_id: str) -> dict:
    return safe(lambda: privacy.deanonymize(DeanonymizeInput(text=text,session_id=session_id).text,session_id))
def _query_lancedb_vector(query: str, project_id: str, top_k: int=5) -> list:
    return safe(lambda: knowledge.query(**QueryInput(query=query,project_id=project_id,top_k=top_k).model_dump()))
def _execute_docker_code(code: str, language: str="python", timeout_seconds: int=10) -> dict:
    return safe(lambda: sandbox.run(**ExecuteInput(code=code,language=language,timeout_seconds=timeout_seconds).model_dump()))

@mcp.tool()
def anonymize_prompt(prompt: str, language: str="de") -> dict: return _anonymize_prompt(prompt, language)
@mcp.tool()
def deanonymize_response(text: str, session_id: str) -> dict: return _deanonymize_response(text, session_id)
@mcp.tool()
def query_lancedb_vector(query: str, project_id: str, top_k: int=5) -> list: return _query_lancedb_vector(query, project_id, top_k)
@mcp.tool()
def execute_docker_code(code: str, language: str="python", timeout_seconds: int=10) -> dict: return _execute_docker_code(code, language, timeout_seconds)
@mcp.resource("okf://wiki/{concept_id}")
def okf_wiki(concept_id: str) -> str: return safe(lambda: okf.read(concept_id))
@mcp.resource("privacy://audit_stats")
def audit_stats() -> str: return json.dumps(privacy.stats(),ensure_ascii=False)
@mcp.prompt()
def grill_me_security_audit(architecture_description: str) -> str: return security_audit_prompt(architecture_description)

def main():
    parser=argparse.ArgumentParser(); group=parser.add_mutually_exclusive_group(); group.add_argument("--stdio",action="store_true"); group.add_argument("--sse",action="store_true"); args=parser.parse_args()
    if args.sse:
        print("WARNING: SSE is localhost-only and unauthenticated; do not expose it publicly.",file=sys.stderr)
        mcp.run(transport="sse",host="127.0.0.1",port=int(os.getenv("MCP_SSE_PORT","8000")))
    else: mcp.run(transport="stdio")
if __name__=="__main__": main()
