from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_introspection_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def get_flowchart(identifier: str) -> str:
        """Get the control flow graph (basic blocks and edges) of a function. Shows predecessors and successors for each block. Essential for understanding branch logic."""
        result = await client.call("get_flowchart", identifier=identifier)
        lines = [f"Flowchart for {result['function']} @ {result['address']}", f"Basic blocks: {result['block_count']}", ""]
        for b in result["blocks"]:
            lines.append(f"  Block {b['start']}–{b['end']} ({b['size']} bytes)")
            if b["predecessors"]:
                lines.append(f"    ← from: {', '.join(b['predecessors'])}")
            if b["successors"]:
                lines.append(f"    → to:   {', '.join(b['successors'])}")
            lines.append("")
        return "\n".join(lines)

    @mcp.tool()
    async def get_comment(address: str, is_repeatable: bool = False) -> str:
        """Read the comment at an address. Set is_repeatable=True for repeatable comments."""
        result = await client.call("get_comment", address=address, is_repeatable=is_repeatable)
        if result["comment"]:
            kind = "Repeatable" if result["is_repeatable"] else "Regular"
            return f"{kind} comment at {result['address']}: {result['comment']}"
        return f"No {'repeatable ' if is_repeatable else ''}comment at {result['address']}"

    @mcp.tool()
    async def get_all_comments(identifier: str) -> str:
        """Get all comments within a function (both regular and repeatable). Pass function name or address."""
        comments = await client.call("get_all_comments_in_function", identifier=identifier)
        if not comments:
            return f"No comments in function {identifier}"
        lines = [f"Comments in {identifier}:", ""]
        for c in comments:
            kind = "[R]" if c["is_repeatable"] else "   "
            lines.append(f"  {c['address']} {kind} {c['comment']}")
        lines.append(f"\nTotal: {len(comments)} comments")
        return "\n".join(lines)

    @mcp.tool()
    async def get_function_comment(identifier: str, is_repeatable: bool = False) -> str:
        """Read the function-level comment (appears above/below the function header in disassembly)."""
        result = await client.call("get_function_comment", identifier=identifier, is_repeatable=is_repeatable)
        if result["comment"]:
            return f"Function comment for {result['function']}: {result['comment']}"
        return f"No function comment for {result['function']}"

    @mcp.tool()
    async def set_function_comment(identifier: str, comment: str, is_repeatable: bool = False) -> str:
        """Set a function-level comment. These appear above (anterior) or below (posterior) the function header."""
        result = await client.call("set_function_comment", identifier=identifier, comment=comment, is_repeatable=is_repeatable)
        if result["success"]:
            return f"Function comment set at {result['address']}"
        return f"Failed to set function comment"

    @mcp.tool()
    async def get_stack_frame(identifier: str) -> str:
        """Get the complete stack frame layout of a function — all stack variables, their offsets, sizes, and the overall frame geometry."""
        result = await client.call("get_stack_frame", identifier=identifier)
        lines = [
            f"Stack frame for {result['function']} @ {result['address']}",
            f"  Total frame size: {result.get('frame_size', 0)} bytes",
            f"  Local vars: {result.get('local_size', 0)} bytes",
            f"  Saved regs: {result.get('saved_regs', 0)} bytes",
            f"  Arguments: {result.get('args_size', 0)} bytes",
            "",
        ]
        members = result.get("members", [])
        if members:
            lines.append(f"  {'Offset':>8}  {'Size':>6}  {'Name'}")
            lines.append("  " + "-" * 40)
            for m in members:
                lines.append(f"  {m['offset']:>8}  {m['size']:>6}  {m['name']}")
        else:
            lines.append("  No stack frame members.")
        return "\n".join(lines)

    @mcp.tool()
    async def set_operand_type(address: str, operand_num: int, display_type: str) -> str:
        """Change how an operand is displayed. operand_num: 0 for first, 1 for second. display_type: hex, decimal, octal, binary, char, default."""
        result = await client.call("set_operand_type", address=address, operand_num=operand_num, display_type=display_type)
        if result["success"]:
            return f"Operand {result['operand']} at {result['address']} set to {result['type']}"
        return f"Failed to set operand type"

    @mcp.tool()
    async def set_local_variable_type(function_identifier: str, variable_name: str, type_string: str) -> str:
        """Change the type of a local variable in a decompiled function. Requires Hex-Rays. Pass C-style type (e.g. 'SOCKET', 'struct sockaddr_in *')."""
        result = await client.call(
            "set_local_variable_type",
            func_identifier=function_identifier,
            var_name=variable_name,
            type_str=type_string,
        )
        if result["success"]:
            return f"Variable '{result['variable']}' retyped to '{result['new_type']}'"
        return f"Failed to retype variable"

    @mcp.tool()
    async def get_color(address: str, item_type: str = "instruction") -> str:
        """Get the color of an instruction, function, or segment. Returns hex RGB value."""
        result = await client.call("get_color", address=address, item_type=item_type)
        if result["color"]:
            return f"Color at {result['address']}: {result['color']}"
        return f"No custom color at {result['address']} (using default)"

    @mcp.tool()
    async def set_color(address: str, color: int, item_type: str = "instruction") -> str:
        """Set the color of an instruction, function, or segment. Color is RGB as integer (e.g. 0xFF0000 for red, 0x00FF00 for green). item_type: instruction, function, segment."""
        result = await client.call("set_color", address=address, color=color, item_type=item_type)
        if result["success"]:
            return f"Color set at {result['address']}: {result['color']}"
        return f"Failed to set color"

    @mcp.tool()
    async def get_function_hash(identifier: str, algorithm: str = "md5") -> str:
        """Calculate a hash of a function's raw bytes. Useful for identifying identical/similar functions across binaries. Algorithms: md5, sha1, sha256."""
        result = await client.call("get_function_hash", identifier=identifier, algorithm=algorithm)
        return f"{result['function']} @ {result['address']} ({result['size']} bytes)\n{result['algorithm'].upper()}: {result['hash']}"

    @mcp.tool()
    async def get_exception_info(identifier: str) -> str:
        """Check if a function contains exception handling (try/catch/throw). Returns the decompiled code if exception handling is found."""
        result = await client.call("get_exception_info", identifier=identifier)
        lines = [f"Exception info for {result['function']}:"]
        lines.append(f"  Has try:   {'yes' if result['has_try'] else 'no'}")
        lines.append(f"  Has catch: {'yes' if result['has_catch'] else 'no'}")
        lines.append(f"  Has throw: {'yes' if result['has_throw'] else 'no'}")
        if result.get("pseudocode"):
            lines.append(f"\nDecompiled code:\n{result['pseudocode']}")
        return "\n".join(lines)

    @mcp.tool()
    async def get_microcode(identifier: str, maturity: str = "preoptimized") -> str:
        """Get the Hex-Rays intermediate representation (microcode) for a function. Maturity levels: generated, preoptimized, locopt, calls, glbopt1, glbopt2, glbopt3, lvars."""
        result = await client.call("get_microcode", identifier=identifier, maturity=maturity)
        header = f"Microcode for {result['function']} (maturity: {result['maturity']}, {result['block_count']} blocks)"
        return f"{header}\n{'=' * len(header)}\n\n{result['microcode']}"
