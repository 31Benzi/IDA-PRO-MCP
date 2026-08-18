from __future__ import annotations

import logging
import os
import sys

from mcp.server import MCPServer

from .rpc_client import IdaRpcClient, RpcError
from .protocol import DEFAULT_HOST, DEFAULT_PORT
from .tools import (
    register_analysis_tools,
    register_navigation_tools,
    register_modification_tools,
    register_search_tools,
    register_debugger_tools,
    register_advanced_tools,
    register_introspection_tools,
    register_database_tools,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("ida-mcp")

mcp = MCPServer(
    "ida-mcp",
    description="MCP server for IDA Pro — AI-assisted reverse engineering via Claude Code",
)

host = os.environ.get("IDA_MCP_HOST", DEFAULT_HOST)
port = int(os.environ.get("IDA_MCP_PORT", str(DEFAULT_PORT)))
client = IdaRpcClient(host=host, port=port)

register_analysis_tools(mcp, client)
register_navigation_tools(mcp, client)
register_modification_tools(mcp, client)
register_search_tools(mcp, client)
register_debugger_tools(mcp, client)
register_advanced_tools(mcp, client)
register_introspection_tools(mcp, client)
register_database_tools(mcp, client)


@mcp.tool()
async def get_binary_info() -> str:
    """Get metadata about the currently loaded binary (filename, architecture, bitness, entry point)."""
    import json
    result = await client.call("get_binary_info")
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_analysis_status() -> str:
    """Check if IDA's auto-analysis has completed. Some tools may return incomplete results if analysis is still running."""
    result = await client.call("get_analysis_status")
    if result["complete"]:
        return "Auto-analysis is complete. All tools should return accurate results."
    return "Auto-analysis is still in progress. Results may be incomplete."


@mcp.tool()
async def ping() -> str:
    """Check connectivity to IDA Pro. Returns 'Connected' if the IDA plugin is running and reachable."""
    connected = await client.ping()
    if connected:
        return f"Connected to IDA Pro at {host}:{port}"
    return f"Cannot reach IDA Pro at {host}:{port}. Make sure IDA is running with the ida_mcp_plugin loaded."


@mcp.resource("ida://binary/info")
async def binary_info_resource() -> str:
    """Current binary metadata from IDA Pro."""
    import json
    try:
        result = await client.call("get_binary_info")
        return json.dumps(result, indent=2)
    except RpcError:
        return '{"error": "Not connected to IDA Pro"}'


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
