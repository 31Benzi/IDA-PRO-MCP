from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_database_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def save_database(path: str = "") -> str:
        """Save the IDA database. Pass a path to save to a specific location, or leave empty to save in-place."""
        result = await client.call("save_database", path=path)
        if result["success"]:
            return "Database saved successfully."
        return "Failed to save database."

    @mcp.tool()
    async def apply_flirt_signature(sig_name: str) -> str:
        """Apply a FLIRT signature file (.sig) to identify library functions in stripped binaries. Pass the signature name (e.g. 'vc64rtf' for MSVC runtime)."""
        result = await client.call("apply_sig", sig_name=sig_name)
        if result["success"]:
            return f"FLIRT signature '{result['signature']}' applied successfully."
        return f"Failed to apply signature '{sig_name}'"

    @mcp.tool()
    async def list_flirt_signatures() -> str:
        """List all FLIRT signatures currently applied to the database."""
        sigs = await client.call("list_applied_sigs")
        if not sigs:
            return "No FLIRT signatures applied."
        lines = ["Applied FLIRT Signatures:", ""]
        for s in sigs:
            lines.append(f"  {s}")
        return "\n".join(lines)

    @mcp.tool()
    async def create_segment(name: str, start_address: str, end_address: str, seg_class: str = "DATA", permissions: int = 7) -> str:
        """Create a new memory segment. permissions: bitmask (4=read, 2=write, 1=execute, 7=rwx). seg_class: CODE, DATA, BSS, STACK, etc."""
        result = await client.call("create_segment", name=name, start=start_address, end=end_address, seg_class=seg_class, permissions=permissions)
        if result["success"]:
            return f"Segment '{result['name']}' created: {result['start']}–{result['end']}"
        return f"Failed to create segment"

    @mcp.tool()
    async def delete_segment(address: str) -> str:
        """Delete the segment containing the given address. The data is kept but the segment definition is removed."""
        result = await client.call("delete_segment", address=address)
        if result["success"]:
            return f"Segment at {result['address']} deleted."
        return f"Failed to delete segment"

    @mcp.tool()
    async def set_segment_permissions(address: str, read: bool = True, write: bool = True, execute: bool = True) -> str:
        """Change the read/write/execute permissions of the segment containing the given address."""
        result = await client.call("set_segment_permissions", address=address, read=read, write=write, execute=execute)
        perms = f"{'r' if read else '-'}{'w' if write else '-'}{'x' if execute else '-'}"
        if result["success"]:
            return f"Segment '{result['segment']}' permissions set to {perms}"
        return f"Failed to set permissions"

    @mcp.tool()
    async def create_array(address: str, count: int, element_type: str = "byte") -> str:
        """Create an array at an address. element_type: byte, word, dword, qword. count: number of elements."""
        result = await client.call("create_array", address=address, count=count, element_type=element_type)
        if result["success"]:
            return f"Array of {result['count']} {result['element_type']}s created at {result['address']}"
        return f"Failed to create array"

    @mcp.tool()
    async def navigate_to(address: str) -> str:
        """Jump IDA's cursor to an address. This moves the user's view in the IDA GUI to the specified location."""
        result = await client.call("navigate_to", address=address)
        if result["success"]:
            return f"Navigated to {result['address']}"
        return f"Failed to navigate to {address}"

    @mcp.tool()
    async def produce_asm(identifier: str) -> str:
        """Produce a clean assembly listing for a function, suitable for copy-paste or file export."""
        result = await client.call("produce_asm_file", identifier=identifier)
        return f"; Function: {result['function']}\n{result['asm']}"

    @mcp.tool()
    async def produce_c(identifier: str) -> str:
        """Produce clean C pseudocode for a function, suitable for copy-paste or file export. Requires Hex-Rays."""
        result = await client.call("produce_c_file", identifier=identifier)
        return f"// Function: {result['function']}\n{result['c_code']}"

    @mcp.tool()
    async def run_idc_script(code: str) -> str:
        """Execute IDC script code (IDA's native scripting language). Returns the evaluation result."""
        result = await client.call("run_idc", code=code)
        if result.get("result"):
            return f"Result: {result['result']}"
        return "IDC script executed."

    @mcp.tool()
    async def run_ida_action(action_name: str) -> str:
        """Trigger a registered IDA UI action by name (e.g. 'ToggleBnds', 'MakeCode'). Use list_ida_actions to see available actions."""
        result = await client.call("run_ida_action", action_name=action_name)
        if result["success"]:
            return f"Action '{result['action']}' executed."
        return f"Action '{action_name}' failed or not found."

    @mcp.tool()
    async def list_ida_actions() -> str:
        """List all registered IDA UI actions that can be triggered with run_ida_action."""
        actions = await client.call("list_ida_actions")
        if not actions:
            return "No registered actions."
        lines = [f"Registered IDA Actions ({len(actions)} total):", ""]
        for a in actions:
            lines.append(f"  {a}")
        return "\n".join(lines)

    @mcp.tool()
    async def list_debugger_threads() -> str:
        """List all threads in the debugged process. Requires active debugger."""
        threads = await client.call("list_debugger_threads")
        if not threads:
            return "No threads."
        lines = [f"{'TID':>8}  {'State':<12} {'Name'}"]
        lines.append("-" * 40)
        for t in threads:
            lines.append(f"{t['tid']:>8}  {t['state']:<12} {t.get('name', '')}")
        return "\n".join(lines)

    @mcp.tool()
    async def switch_thread(tid: int) -> str:
        """Switch the debugger's active thread. Pass the thread ID from list_debugger_threads."""
        result = await client.call("switch_debugger_thread", tid=tid)
        if result["success"]:
            return f"Switched to thread {result['tid']}"
        return f"Failed to switch to thread {tid}"

    @mcp.tool()
    async def add_watchpoint(address: str, size: int = 4, watch_type: str = "write") -> str:
        """Set a hardware watchpoint (data breakpoint). Triggers when memory at address is accessed. watch_type: write, read, execute."""
        result = await client.call("add_watchpoint", address=address, size=size, watch_type=watch_type)
        if result["success"]:
            return f"Watchpoint ({result['type']}) set at {result['address']} ({result['size']} bytes)"
        return f"Failed to set watchpoint at {address}"
