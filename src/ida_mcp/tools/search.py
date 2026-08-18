from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_search_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def search_text(query: str, max_results: int = 100) -> str:
        """Search through disassembly text for a string. Matches against instruction mnemonics, operands, and comments."""
        results = await client.call("search_text", query=query, max_results=max_results)
        if not results:
            return f"No matches for '{query}'"
        lines = [f"Search results for '{query}':", ""]
        for r in results:
            func_info = f" [{r['function']}]" if r.get("function") else ""
            lines.append(f"  {r['address']}{func_info}: {r['line']}")
        lines.append(f"\nTotal: {len(results)} matches")
        return "\n".join(lines)

    @mcp.tool()
    async def search_bytes(pattern: str, max_results: int = 100) -> str:
        """Search for a byte pattern in the binary. Pass hex bytes with optional spaces (e.g. '90 90 90' or 'CC CC' or '48 8B 05')."""
        results = await client.call("search_bytes_pattern", pattern=pattern, max_results=max_results)
        if not results:
            return f"No matches for pattern '{pattern}'"
        lines = [f"Byte pattern matches for '{pattern}':", ""]
        for r in results:
            func_info = f" [{r['function']}]" if r.get("function") else ""
            lines.append(f"  {r['address']}{func_info}")
        lines.append(f"\nTotal: {len(results)} matches")
        return "\n".join(lines)
