from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_advanced_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def patch_bytes(address: str, hex_bytes: str) -> str:
        """Patch bytes at an address in the IDA database. Pass hex bytes with optional spaces (e.g. '90 90 90' for NOP sled, 'EB 05' for short jump)."""
        result = await client.call("patch_bytes_at", address=address, hex_bytes=hex_bytes)
        if result["success"]:
            return f"Patched {result['size']} bytes at {result['address']}: {result['patched']}"
        return f"Failed to patch bytes at {address}"

    @mcp.tool()
    async def execute_idapython(code: str) -> str:
        """Execute arbitrary IDAPython code inside the IDA session. Set 'result' or 'output' variable in your script to return data. Example: 'import idc; result = idc.get_screen_ea()'"""
        result = await client.call("execute_script", code=code)
        if "result" in result and result["result"] is not None:
            return f"Result: {json.dumps(result['result'], indent=2, default=str)}"
        if "output" in result and result["output"] is not None:
            return f"Output: {result['output']}"
        return "Script executed successfully (no return value)."

    @mcp.tool()
    async def load_type_library(path: str) -> str:
        """Load a type information library (.til) file into the current database."""
        result = await client.call("load_til_file", path=path)
        if result["success"]:
            return f"Loaded TIL: {result['path']}"
        return f"Failed to load TIL: {path}"

    @mcp.tool()
    async def list_type_libraries() -> str:
        """List all loaded type information libraries (TILs) in the current database."""
        tils = await client.call("list_til")
        if not tils:
            return "No type libraries loaded."
        lines = ["Loaded Type Libraries:", ""]
        for t in tils:
            desc = f" — {t['desc']}" if t.get("desc") else ""
            lines.append(f"  {t['name']}{desc}")
        return "\n".join(lines)

    @mcp.tool()
    async def apply_callee_type(address: str, prototype: str) -> str:
        """Apply a type signature to a call site (callee). Useful when the function pointer type is unknown at a call instruction."""
        result = await client.call("apply_callee_type", address=address, prototype=prototype)
        if result["success"]:
            return f"Applied callee type at {result['address']}: {prototype}"
        return f"Failed to apply callee type at {address}"

    @mcp.tool()
    async def get_function_callers(identifier: str) -> str:
        """Get all functions that call a given function. Higher-level than xrefs — groups by calling function and shows call sites."""
        callers = await client.call("get_function_callers", identifier=identifier)
        if not callers:
            return f"No callers found for {identifier}"
        lines = [f"Functions calling {identifier}:", ""]
        for c in callers:
            sites = ", ".join(c["call_sites"])
            lines.append(f"  {c['name']} ({c['address']})")
            lines.append(f"    call sites: {sites}")
        lines.append(f"\nTotal: {len(callers)} callers")
        return "\n".join(lines)

    @mcp.tool()
    async def get_function_callees(identifier: str) -> str:
        """Get all functions called by a given function. Shows what a function depends on."""
        callees = await client.call("get_function_callees", identifier=identifier)
        if not callees:
            return f"No callees found for {identifier}"
        lines = [f"Functions called by {identifier}:", ""]
        for c in callees:
            sites = ", ".join(c["call_sites"])
            lines.append(f"  {c['name']} ({c['address']})")
            lines.append(f"    call sites: {sites}")
        lines.append(f"\nTotal: {len(callees)} callees")
        return "\n".join(lines)

    @mcp.tool()
    async def make_code(address: str, size: int = 0) -> str:
        """Convert bytes at an address into code (disassembled instruction). Optionally undefine 'size' bytes first."""
        result = await client.call("make_code", address=address, size=size)
        if result["success"]:
            return f"Created instruction at {result['address']} ({result['instruction_size']} bytes)"
        return f"Failed to create code at {address}"

    @mcp.tool()
    async def make_data(address: str, size: int = 1, data_type: str = "byte") -> str:
        """Convert bytes at an address into data. Types: byte, word, dword, qword, float, double."""
        result = await client.call("make_data", address=address, size=size, data_type=data_type)
        if result["success"]:
            return f"Created {data_type} data at {result['address']}"
        return f"Failed to create data at {address}"

    @mcp.tool()
    async def make_string(address: str, length: int = 0) -> str:
        """Define a C-style string at an address. Pass length=0 to auto-detect (null-terminated)."""
        result = await client.call("make_string", address=address, length=length)
        if result["success"]:
            return f"Created string at {result['address']}"
        return f"Failed to create string at {address}"

    @mcp.tool()
    async def undefine(address: str, size: int = 1) -> str:
        """Undefine (delete) items at an address, reverting them to raw bytes."""
        result = await client.call("undefine", address=address, size=size)
        if result["success"]:
            return f"Undefined {size} bytes at {result['address']}"
        return f"Failed to undefine at {address}"

    @mcp.tool()
    async def define_function(start_address: str, end_address: str = "") -> str:
        """Create a new function at a given address range. If end_address is empty, IDA will auto-detect the function boundary."""
        result = await client.call("define_function", start=start_address, end=end_address)
        if result["success"]:
            return f"Function created at {result['address']}"
        return f"Failed to create function at {start_address}"

    @mcp.tool()
    async def undefine_function(address: str) -> str:
        """Delete/undefine a function at an address. The code remains but is no longer treated as a function."""
        result = await client.call("undefine_function", address=address)
        if result["success"]:
            return f"Function undefined at {result['address']}"
        return f"Failed to undefine function at {address}"

    @mcp.tool()
    async def add_bookmark(address: str, description: str = "") -> str:
        """Add a bookmark at an address with optional description. Bookmarks persist in the IDA database."""
        result = await client.call("add_bookmark", address=address, description=description)
        if result["success"]:
            return f"Bookmark added at {result['address']} (slot {result['slot']})"
        return f"Failed to add bookmark at {address}"

    @mcp.tool()
    async def list_bookmarks() -> str:
        """List all bookmarks in the IDA database."""
        bookmarks = await client.call("list_bookmarks")
        if not bookmarks:
            return "No bookmarks set."
        lines = [f"{'Slot':>4}  {'Address':<18} {'Description'}"]
        lines.append("-" * 60)
        for b in bookmarks:
            lines.append(f"{b['slot']:>4}  {b['address']:<18} {b['description']}")
        return "\n".join(lines)

    @mcp.tool()
    async def delete_bookmark(slot: int) -> str:
        """Delete a bookmark by slot number (get slot numbers from list_bookmarks)."""
        result = await client.call("delete_bookmark", slot=slot)
        if result["success"]:
            return f"Bookmark slot {result['slot']} deleted."
        return f"Failed to delete bookmark slot {slot}"

    @mcp.tool()
    async def get_local_variables(identifier: str) -> str:
        """Get all local variables and arguments of a decompiled function. Requires Hex-Rays. Pass function name or address."""
        result = await client.call("get_local_variables", identifier=identifier)
        lines = [f"Variables for {result['function']} @ {result['address']}:", ""]
        args = [v for v in result["variables"] if v["is_arg"]]
        locals_ = [v for v in result["variables"] if not v["is_arg"]]
        if args:
            lines.append("  Arguments:")
            for v in args:
                stack = " [stack]" if v["is_stk"] else ""
                lines.append(f"    {v['type']:<20} {v['name']}{stack}")
        if locals_:
            lines.append("  Locals:")
            for v in locals_:
                stack = " [stack]" if v["is_stk"] else ""
                lines.append(f"    {v['type']:<20} {v['name']}{stack}")
        return "\n".join(lines)

    @mcp.tool()
    async def rename_local_variable(function_identifier: str, old_name: str, new_name: str) -> str:
        """Rename a local variable or argument in a decompiled function. Requires Hex-Rays."""
        result = await client.call(
            "rename_local_variable",
            func_identifier=function_identifier,
            old_name=old_name,
            new_name=new_name,
        )
        if result["success"]:
            return f"Renamed '{result['old_name']}' to '{result['new_name']}'"
        return f"Failed to rename variable '{old_name}'"

    @mcp.tool()
    async def get_global_variables(filter: str = "") -> str:
        """List named global data variables in the binary. Optionally filter by substring."""
        variables = await client.call("get_global_variables", filter=filter)
        if not variables:
            return "No global variables found."
        lines = [f"{'Address':<18} {'Size':>6}  {'Name'}"]
        lines.append("-" * 60)
        for v in variables:
            lines.append(f"{v['address']:<18} {v['size']:>6}  {v['name']}")
        lines.append(f"\nTotal: {len(variables)} variables")
        return "\n".join(lines)
