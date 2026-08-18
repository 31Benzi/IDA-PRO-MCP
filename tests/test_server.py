import asyncio
import pytest
from ida_mcp.server import mcp


@pytest.mark.asyncio
async def test_tool_registration_count():
    tools = await mcp.list_tools()
    assert len(tools) == 87, f"Expected 87 tools, got {len(tools)}"


@pytest.mark.asyncio
async def test_essential_tools_present():
    tools = await mcp.list_tools()
    tool_names = {t.name for t in tools}

    essential_tools = [
        "decompile_function",
        "disassemble_function",
        "list_functions",
        "get_xrefs_to",
        "get_xrefs_from",
        "list_strings",
        "rename_function",
        "set_comment",
        "patch_bytes",
        "execute_idapython",
        "start_debugger",
        "set_breakpoint",
        "get_registers",
        "get_flowchart",
        "get_stack_frame",
        "save_database",
        "ping",
    ]

    for tool in essential_tools:
        assert tool in tool_names, f"Missing essential tool: {tool}"


@pytest.mark.asyncio
async def test_all_tools_have_descriptions():
    tools = await mcp.list_tools()
    for t in tools:
        assert t.description, f"Tool {t.name} is missing a description"
        assert len(t.description.strip()) > 10, f"Tool {t.name} has a description that is too short"
