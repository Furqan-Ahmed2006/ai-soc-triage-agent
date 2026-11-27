import asyncio
import concurrent.futures
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_SCRIPT = Path(__file__).with_name("mcp_server.py")


def _server_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_SCRIPT)],
    )


async def _list_tools_async() -> List[Dict[str, Any]]:
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            tools: List[Dict[str, Any]] = []
            for tool in result.tools:
                raw_schema = (
                    getattr(tool, "input_schema", None)
                    or getattr(tool, "inputSchema", None)
                    or {"type": "object", "properties": {}}
                )
                schema = raw_schema.model_dump() if hasattr(raw_schema, "model_dump") else raw_schema
                tools.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": schema,
                    },
                })
            return tools


async def _call_tool_async(tool_name: str, arguments: Dict[str, Any]) -> str:
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments or {})
            blocks: List[str] = []
            for item in result.content:
                if hasattr(item, "text"):
                    blocks.append(item.text)
                else:
                    blocks.append(json.dumps(item, default=str))
            return "\n".join(blocks) if blocks else "{}"


def _run_coro(coro: Any) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def discover_mcp_tools() -> List[Dict[str, Any]]:
    return _run_coro(_list_tools_async())


def invoke_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    return _run_coro(_call_tool_async(tool_name, arguments))