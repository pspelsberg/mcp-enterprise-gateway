"""Minimal local MCP smoke test. Requires the project environment and stdio server."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    root = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "src.server", "--stdio"],
        cwd=str(root),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "anonymize_prompt", {"prompt": "Kontakt a@example.com"}
            )
            # Do not print the bearer-like session_id in shell transcripts.
            print({"is_error": result.isError, "content_count": len(result.content)})


if __name__ == "__main__":
    asyncio.run(main())
