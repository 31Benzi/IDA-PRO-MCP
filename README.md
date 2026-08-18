# IDA Pro MCP Server for Claude Code

Bridge Claude Code (CLI and Editor Extensions like VS Code, Cursor, Windsurf) with **IDA Pro 9.0+** for AI-assisted reverse engineering. **87 tools** covering virtually everything IDA Pro can do.

---

## Architecture

```
Claude Code / Cursor / VS Code (MCP Client)
               │ (stdio)
               ▼
        ida-mcp Server
               │ (JSON-RPC over localhost:13337)
               ▼
   IDA Pro Plugin (ida_mcp_plugin.py)
               │ (IDAPython API on main thread)
               ▼
         IDA Pro 9.0+
```

---

## Installation & Setup

### 1. Install the IDA Plugin
Copy `ida_plugin/ida_mcp_plugin.py` into your IDA Pro `plugins` directory:
- **macOS**: `~/idapro-9.0/plugins/` or `/Applications/IDA Professional 9.0.app/Contents/MacOS/plugins/`
- **Windows**: `%APPDATA%\Hex-Rays\IDA Pro\plugins\` or `C:\Program Files\IDA Professional 9.0\plugins\`
- **Linux**: `~/.idapro/plugins/` or `/opt/idapro-9.0/plugins/`

When you open any binary in IDA Pro, the plugin starts a JSON-RPC server on `127.0.0.1:13337`.

### 2. Configure Claude Code CLI
```bash
claude mcp add ida-pro -- uv run --directory "/Users/benzi/Documents/IDA MCP" ida-mcp
```

### 3. Configure VS Code / Cursor / Windsurf
Add to `.mcp.json` or your editor's MCP configuration:
```json
{
  "mcpServers": {
    "ida-pro": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/benzi/Documents/IDA MCP", "ida-mcp"]
    }
  }
}
```

### Environment Variables
- `IDA_MCP_HOST` — Override host (default: `127.0.0.1`)
- `IDA_MCP_PORT` — Override port (default: `13337`)

---

## Available Tools (87 Total)

### Analysis (4)
| Tool | Description |
|:---|:---|
| `decompile_function` | Hex-Rays C pseudocode decompilation |
| `disassemble_function` | Full assembly listing for a function |
| `disassemble_range` | Assembly between two addresses |
| `get_bytes` | Read raw hex bytes from an address |

### Navigation & Discovery (14)
| Tool | Description |
|:---|:---|
| `list_functions` | List all functions with optional filter |
| `get_function_info` | Detailed function metadata |
| `list_segments` | Memory segments with permissions |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `list_strings` | Defined strings with optional filter |
| `get_imports` | Imported functions by module |
| `get_exports` | Exported functions and entry points |
| `list_structs` | Structures, unions, member layouts |
| `list_enums` | Enumerations and values |
| `create_struct` | Create a new struct type |
| `get_function_callers` | Functions calling a target (with call sites) |
| `get_function_callees` | Functions called by a target |
| `make_string` | Define a C-style string at address |

### Introspection (14)
| Tool | Description |
|:---|:---|
| `get_flowchart` | Control flow graph — basic blocks with predecessors/successors |
| `get_comment` | Read comment at an address |
| `get_all_comments` | Read all comments within a function |
| `get_function_comment` | Read function-level comment |
| `set_function_comment` | Set function-level comment |
| `get_stack_frame` | Full stack frame layout (locals, args, saved regs) |
| `set_operand_type` | Change operand display (hex/decimal/binary/char) |
| `set_local_variable_type` | Retype a local variable in decompilation |
| `get_color` | Get instruction/function/segment color |
| `set_color` | Set instruction/function/segment color (RGB) |
| `get_function_hash` | Hash function bytes (MD5/SHA1/SHA256) |
| `get_exception_info` | Detect try/catch/throw in a function |
| `get_microcode` | Hex-Rays intermediate representation at any maturity level |

### Modifications (7)
| Tool | Description |
|:---|:---|
| `rename_function` | Rename a function |
| `rename_address` | Rename a label, variable, or address |
| `set_comment` | Set regular or repeatable comment |
| `set_function_type` | Set C function signature/prototype |
| `set_type` | Set type at address |
| `rename_local_variable` | Rename local variable (Hex-Rays) |
| `apply_callee_type` | Apply type at call site |

### Search (2)
| Tool | Description |
|:---|:---|
| `search_text` | Text search through disassembly |
| `search_bytes` | Byte pattern/signature search |

### Debugger (17)
| Tool | Description |
|:---|:---|
| `start_debugger` | Start debugging the binary |
| `get_debugger_status` | Check debugger active/suspended state |
| `set_breakpoint` | Set software breakpoint |
| `delete_breakpoint` | Remove a breakpoint |
| `list_breakpoints` | List all breakpoints |
| `enable_breakpoint` | Enable/disable breakpoint |
| `step_into` | Step into next instruction |
| `step_over` | Step over next instruction |
| `continue_execution` | Continue until next breakpoint |
| `suspend_debugger` | Pause execution |
| `exit_debugger` | Terminate process |
| `get_registers` | Read CPU registers |
| `read_debug_memory` | Read memory from debugged process (hex dump with ASCII) |
| `get_stack_trace` | Call stack trace |
| `list_debugger_threads` | List all process threads |
| `switch_thread` | Switch active debugger thread |
| `add_watchpoint` | Set hardware watchpoint (read/write/execute) |

### Advanced (14)
| Tool | Description |
|:---|:---|
| `patch_bytes` | Patch bytes in the IDA database |
| `execute_idapython` | Run arbitrary IDAPython code |
| `load_type_library` | Load .til type information library |
| `list_type_libraries` | List loaded TILs |
| `make_code` | Convert bytes to code (instruction) |
| `make_data` | Convert bytes to typed data |
| `undefine` | Revert to raw undefined bytes |
| `define_function` | Create function at address range |
| `undefine_function` | Delete function definition |
| `add_bookmark` | Add persistent bookmark |
| `list_bookmarks` | List all bookmarks |
| `delete_bookmark` | Remove bookmark |
| `get_local_variables` | List local variables and arguments |
| `get_global_variables` | List named global data variables |

### Database & Export (12)
| Tool | Description |
|:---|:---|
| `save_database` | Save the IDA database |
| `apply_flirt_signature` | Apply FLIRT .sig for library identification |
| `list_flirt_signatures` | List applied FLIRT signatures |
| `create_segment` | Create new memory segment |
| `delete_segment` | Delete segment definition |
| `set_segment_permissions` | Change segment rwx permissions |
| `create_array` | Define typed arrays |
| `navigate_to` | Jump IDA cursor to address |
| `produce_asm` | Export clean assembly listing |
| `produce_c` | Export clean C pseudocode |
| `run_idc_script` | Execute IDC script code |
| `run_ida_action` | Trigger registered IDA UI action |
| `list_ida_actions` | List all available IDA actions |

### Meta (3)
| Tool | Description |
|:---|:---|
| `get_binary_info` | File path, arch, bitness, entry point |
| `get_analysis_status` | Check auto-analysis completion |
| `ping` | Check IDA connectivity |
