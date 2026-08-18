from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_analysis_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def decompile_function(identifier: str) -> str:
        """Decompile a function using the Hex-Rays decompiler. Pass a function name or hex address (e.g. '0x401000' or 'main'). Returns C-like pseudocode."""
        result = await client.call("decompile_function", identifier=identifier)
        header = f"Function: {result['function_name']} @ {result['address']}"
        return f"{header}\n{'=' * len(header)}\n\n{result['pseudocode']}"

    @mcp.tool()
    async def disassemble_function(identifier: str) -> str:
        """Get the assembly listing of a function. Pass a function name or hex address (e.g. '0x401000' or 'main')."""
        result = await client.call("disassemble_function", identifier=identifier)
        header = f"Function: {result['function_name']} @ {result['address']}"
        return f"{header}\n{'=' * len(header)}\n\n{result['assembly']}"

    @mcp.tool()
    async def disassemble_range(start_address: str, end_address: str) -> str:
        """Disassemble an arbitrary address range. Pass hex addresses (e.g. '0x401000', '0x401100')."""
        result = await client.call("disassemble_range", start=start_address, end=end_address)
        return result["assembly"]

    @mcp.tool()
    async def get_bytes(address: str, size: int = 16) -> str:
        """Read raw bytes from an address. Returns hex dump. Default reads 16 bytes."""
        result = await client.call("get_bytes_at", address=address, size=size)
        hex_str = result["hex"]
        formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        return f"Address: {result['address']}\nSize: {result['size']}\nHex: {formatted}"
