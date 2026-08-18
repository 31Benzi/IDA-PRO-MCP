from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_navigation_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def list_functions(filter: str = "") -> str:
        """List all functions in the binary. Optionally pass a filter string to match function names (case-insensitive)."""
        functions = await client.call("get_function_list", filter=filter)
        if not functions:
            return "No functions found."
        lines = [f"{'Name':<50} {'Address':<18} {'Size':>8}"]
        lines.append("-" * 78)
        for f in functions:
            lines.append(f"{f['name']:<50} {f['start_ea']:<18} {f['size']:>8}")
        lines.append(f"\nTotal: {len(functions)} functions")
        return "\n".join(lines)

    @mcp.tool()
    async def get_function_info(identifier: str) -> str:
        """Get detailed information about a function. Pass a function name or hex address."""
        result = await client.call("get_function_by_name", name=identifier)
        if result is None:
            result = await client.call("get_function_by_address", address=identifier)
        if result is None:
            return f"No function found for: {identifier}"
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def list_segments() -> str:
        """List all segments (sections) in the binary with their permissions and sizes."""
        segments = await client.call("list_segments")
        if not segments:
            return "No segments found."
        lines = [f"{'Name':<20} {'Start':<18} {'End':<18} {'Size':>10} {'Perms':<6} {'Type':<10}"]
        lines.append("-" * 84)
        for s in segments:
            lines.append(
                f"{s['name']:<20} {s['start']:<18} {s['end']:<18} "
                f"{s['size']:>10} {s['permissions']:<6} {s.get('type', ''):<10}"
            )
        return "\n".join(lines)

    @mcp.tool()
    async def get_xrefs_to(address: str) -> str:
        """Get all cross-references TO an address (who calls/references this location). Pass hex address or name."""
        xrefs = await client.call("get_xrefs_to", address=address)
        if not xrefs:
            return f"No cross-references to {address}"
        lines = [f"Cross-references to {address}:", ""]
        for x in xrefs:
            func_info = f" (in {x['from_func']})" if x.get("from_func") else ""
            lines.append(f"  {x['from_addr']}{func_info} [{x['type']}]")
        lines.append(f"\nTotal: {len(xrefs)} xrefs")
        return "\n".join(lines)

    @mcp.tool()
    async def get_xrefs_from(address: str) -> str:
        """Get all cross-references FROM an address (what does this location call/reference). Pass hex address or name."""
        xrefs = await client.call("get_xrefs_from", address=address)
        if not xrefs:
            return f"No cross-references from {address}"
        lines = [f"Cross-references from {address}:", ""]
        for x in xrefs:
            lines.append(f"  {x['to_addr']} [{x['type']}]")
        lines.append(f"\nTotal: {len(xrefs)} xrefs")
        return "\n".join(lines)

    @mcp.tool()
    async def list_strings(filter: str = "") -> str:
        """List all defined strings in the binary. Optionally filter by substring (case-insensitive)."""
        strings = await client.call("list_strings", filter=filter)
        if not strings:
            return "No strings found."
        lines = [f"{'Address':<18} {'Length':>6}  {'Value'}"]
        lines.append("-" * 80)
        for s in strings:
            value = s["value"]
            if len(value) > 80:
                value = value[:77] + "..."
            lines.append(f"{s['address']:<18} {s['length']:>6}  {value}")
        lines.append(f"\nTotal: {len(strings)} strings")
        return "\n".join(lines)

    @mcp.tool()
    async def get_imports() -> str:
        """List all imported functions grouped by module."""
        imports = await client.call("get_imports")
        if not imports:
            return "No imports found."
        by_module: dict[str, list] = {}
        for imp in imports:
            mod = imp.get("module", "unknown")
            by_module.setdefault(mod, []).append(imp)
        lines = []
        for module, imps in sorted(by_module.items()):
            lines.append(f"\n[{module}]")
            for imp in imps:
                lines.append(f"  {imp['address']}: {imp['name']}")
        lines.append(f"\nTotal: {len(imports)} imports from {len(by_module)} modules")
        return "\n".join(lines)

    @mcp.tool()
    async def get_exports() -> str:
        """List all exported functions/symbols."""
        exports = await client.call("get_exports")
        if not exports:
            return "No exports found."
        lines = [f"{'Address':<18} {'Ordinal':>8}  {'Name'}"]
        lines.append("-" * 60)
        for e in exports:
            lines.append(f"{e['address']:<18} {e['ordinal']:>8}  {e['name']}")
        lines.append(f"\nTotal: {len(exports)} exports")
        return "\n".join(lines)

    @mcp.tool()
    async def list_structs() -> str:
        """List all defined structures/unions in the IDA database with their members."""
        structs = await client.call("list_structs")
        if not structs:
            return "No structures defined."
        lines = []
        for s in structs:
            kind = "union" if s.get("is_union") else "struct"
            lines.append(f"\n{kind} {s['name']} (size: {s['size']})")
            for m in s.get("members", []):
                lines.append(f"  +{m['offset']:04X} {m['type']:<20} {m['name']}")
        return "\n".join(lines)

    @mcp.tool()
    async def list_enums() -> str:
        """List all defined enumerations in the IDA database."""
        enums = await client.call("list_enums")
        if not enums:
            return "No enums defined."
        lines = []
        for e in enums:
            lines.append(f"\nenum {e['name']}")
            for m in e.get("members", []):
                lines.append(f"  {m['name']} = {m['value']}")
        return "\n".join(lines)
