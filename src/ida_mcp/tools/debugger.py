from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server import MCPServer
    from ..rpc_client import IdaRpcClient


def register_debugger_tools(mcp: MCPServer, client: IdaRpcClient) -> None:

    @mcp.tool()
    async def start_debugger(args: str = "", path: str = "") -> str:
        """Start the debugger for the currently loaded binary. Optionally pass command-line arguments and binary path."""
        result = await client.call("start_debugger", args=args, path=path)
        if result["success"]:
            return "Debugger started successfully."
        return "Failed to start debugger."

    @mcp.tool()
    async def get_debugger_status() -> str:
        """Check if the debugger is currently active and whether execution is suspended."""
        result = await client.call("get_debugger_status")
        if not result["active"]:
            return "Debugger is not active."
        if result["suspended"]:
            return "Debugger is active and execution is suspended (ready for commands)."
        return "Debugger is active and process is running."

    @mcp.tool()
    async def set_breakpoint(address: str) -> str:
        """Set a breakpoint at an address. Pass hex address or function name."""
        result = await client.call("set_breakpoint", address=address)
        if result["success"]:
            return f"Breakpoint set at {result['address']}"
        return f"Failed to set breakpoint at {address}"

    @mcp.tool()
    async def delete_breakpoint(address: str) -> str:
        """Delete a breakpoint at an address."""
        result = await client.call("delete_breakpoint", address=address)
        if result["success"]:
            return f"Breakpoint deleted at {result['address']}"
        return f"Failed to delete breakpoint at {address}"

    @mcp.tool()
    async def list_breakpoints() -> str:
        """List all currently set breakpoints with their status."""
        bpts = await client.call("list_breakpoints")
        if not bpts:
            return "No breakpoints set."
        lines = [f"{'Address':<18} {'Type':<10} {'Enabled'}"]
        lines.append("-" * 40)
        for b in bpts:
            lines.append(f"{b['address']:<18} {b['type']:<10} {'yes' if b['enabled'] else 'no'}")
        return "\n".join(lines)

    @mcp.tool()
    async def enable_breakpoint(address: str, enable: bool = True) -> str:
        """Enable or disable a breakpoint without removing it."""
        result = await client.call("enable_breakpoint", address=address, enable=enable)
        action = "enabled" if enable else "disabled"
        if result["success"]:
            return f"Breakpoint at {result['address']} {action}"
        return f"Failed to {action[:-1]} breakpoint at {address}"

    @mcp.tool()
    async def step_into() -> str:
        """Step into the next instruction (follows calls into functions)."""
        result = await client.call("step_into")
        if result["success"]:
            return "Stepped into next instruction."
        return "Step into failed."

    @mcp.tool()
    async def step_over() -> str:
        """Step over the next instruction (executes calls without entering them)."""
        result = await client.call("step_over")
        if result["success"]:
            return "Stepped over next instruction."
        return "Step over failed."

    @mcp.tool()
    async def continue_execution() -> str:
        """Continue process execution until the next breakpoint or event."""
        result = await client.call("continue_execution")
        if result["success"]:
            return "Execution continued."
        return "Continue failed."

    @mcp.tool()
    async def suspend_debugger() -> str:
        """Suspend (pause) the running process."""
        result = await client.call("suspend_debugger")
        if result["success"]:
            return "Process suspended."
        return "Failed to suspend process."

    @mcp.tool()
    async def exit_debugger() -> str:
        """Terminate the debugged process and stop the debugger."""
        result = await client.call("exit_debugger")
        if result["success"]:
            return "Debugger exited."
        return "Failed to exit debugger."

    @mcp.tool()
    async def get_registers() -> str:
        """Read all CPU register values. Requires the debugger to be active and suspended."""
        import json
        regs = await client.call("get_registers")
        lines = ["CPU Registers:", ""]
        gp_order = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"]
        ext_order = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        special = ["rip", "rflags"]
        for group_name, group in [("General Purpose", gp_order), ("Extended", ext_order), ("Special", special)]:
            group_regs = {k: v for k, v in regs.items() if k in group}
            if group_regs:
                lines.append(f"  [{group_name}]")
                for name in group:
                    if name in regs:
                        lines.append(f"    {name:<8} = {regs[name]}")
                lines.append("")
        x86_regs = {k: v for k, v in regs.items() if k in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]}
        if x86_regs and not any(k in regs for k in gp_order):
            lines.append("  [x86 Registers]")
            for name, val in x86_regs.items():
                lines.append(f"    {name:<8} = {val}")
        return "\n".join(lines)

    @mcp.tool()
    async def read_debug_memory(address: str, size: int = 64) -> str:
        """Read memory from the debugged process. Requires active debugger. Returns hex dump."""
        result = await client.call("read_debug_memory", address=address, size=size)
        hex_str = result["hex"]
        lines = [f"Memory at {result['address']} ({result['size']} bytes):", ""]
        offset = 0
        while offset < len(hex_str):
            chunk = hex_str[offset:offset+32]
            hex_display = " ".join(chunk[i:i+2] for i in range(0, len(chunk), 2))
            ascii_display = ""
            for i in range(0, len(chunk), 2):
                byte_val = int(chunk[i:i+2], 16)
                ascii_display += chr(byte_val) if 32 <= byte_val < 127 else "."
            addr = int(result["address"], 16) + offset // 2
            lines.append(f"  {hex(addr)}: {hex_display:<48} {ascii_display}")
            offset += 32
        return "\n".join(lines)

    @mcp.tool()
    async def get_stack_trace() -> str:
        """Get the current call stack trace. Requires active debugger."""
        frames = await client.call("get_stack_trace")
        if not frames:
            return "No stack frames."
        lines = ["Call Stack:", ""]
        for f in frames:
            func_info = f" ({f['function']})" if f.get("function") else ""
            lines.append(f"  #{f['index']}: {f['caller']}{func_info}")
        return "\n".join(lines)
