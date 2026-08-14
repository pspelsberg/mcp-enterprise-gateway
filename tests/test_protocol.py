import asyncio
from fastmcp import Client
from src.server import mcp

def test_F_MCP_protocol_registry_and_dispatch():
    async def run():
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            assert tools == {"anonymize_prompt", "deanonymize_response", "query_lancedb_vector", "execute_docker_code"}
            resources = {str(r.uri) for r in await client.list_resources()}
            assert "privacy://audit_stats" in resources
            prompts = {p.name for p in await client.list_prompts()}
            assert {"grill_me_security_audit", "dsgvo_pii_risk_audit"} <= prompts
            resources = {str(r.uri) for r in await client.list_resources()}
            assert "gateway://health" in resources
            health = await client.read_resource("gateway://health")
            assert '"liveness": "ok"' in str(health) and '"readiness":' in str(health)
            prompt = await client.get_prompt("dsgvo_pii_risk_audit", {"schema_description": "email: string"})
            assert "untrusted data" in str(prompt).lower()
            result = await client.call_tool("anonymize_prompt", {"prompt": "a@example.com"})
            assert not result.is_error and result.data["pii_count"] == 1
    asyncio.run(run())
