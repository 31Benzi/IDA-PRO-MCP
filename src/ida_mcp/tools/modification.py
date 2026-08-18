from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_modification_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def rename_function(identifier: str, new_name: str) -> str:
        """Rename a function. Pass the current name or hex address, and the new name."""
        result = await client.call("rename_function", identifier=identifier, new_name=new_name)
        if result["success"]:
            return f"Renamed function at {result['address']} to '{new_name}'"
        return f"Failed to rename function at {result['address']}"

    @mcp.tool()
    async def rename_address(address: str, new_name: str) -> str:
        """Rename any address (global variable, label, etc). Pass hex address and new name."""
        result = await client.call("rename_address", address=address, new_name=new_name)
        if result["success"]:
            return f"Renamed {result['address']} to '{new_name}'"
        return f"Failed to rename {result['address']}"

    @mcp.tool()
    async def set_comment(address: str, comment: str, is_repeatable: bool = False) -> str:
        """Set a comment at an address. Use is_repeatable=True for repeatable comments that propagate to xrefs."""
        result = await client.call("set_comment", address=address, comment=comment, is_repeatable=is_repeatable)
        kind = "repeatable " if is_repeatable else ""
        if result["success"]:
            return f"Set {kind}comment at {result['address']}: {comment}"
        return f"Failed to set comment at {result['address']}"

    @mcp.tool()
    async def set_function_type(identifier: str, prototype: str) -> str:
        """Set a function's type/prototype. Pass function name or address, and C-style prototype (e.g. 'int __cdecl func(int a, char *b)')."""
        result = await client.call("set_function_prototype", identifier=identifier, prototype=prototype)
        if result["success"]:
            return f"Set prototype at {result['address']}: {prototype}"
        return f"Failed to set prototype at {result['address']}"

    @mcp.tool()
    async def set_type(address: str, type_str: str) -> str:
        """Set the type at an address. Pass hex address and C-style type declaration."""
        result = await client.call("set_type_at", address=address, type_str=type_str)
        if result["success"]:
            return f"Set type at {result['address']}: {type_str}"
        return f"Failed to set type at {result['address']}"

    @mcp.tool()
    async def create_struct(name: str, fields: list[dict]) -> str:
        """Create a new structure type. Pass a name and list of fields, each with 'name' and 'type' keys. Example fields: [{"name": "size", "type": "int"}, {"name": "data", "type": "char *"}]"""
        result = await client.call("create_struct", name=name, fields=fields)
        if result["success"]:
            return f"Created struct '{result['name']}'"
        return f"Failed to create struct '{name}'"
