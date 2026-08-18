import json
import socket
import threading
import traceback
from typing import Any, Callable

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_name
import ida_segment
import ida_nalt
import ida_entry
import ida_lines
import ida_typeinf
import ida_auto
import ida_ida
import ida_loader
import idc

try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False

DEFAULT_PORT = 13337
BUFFER_SIZE = 1024 * 1024


def execute_on_main_thread(func: Callable, *args, **kwargs) -> Any:
    result_container = [None]
    error_container = [None]

    def wrapper():
        try:
            result_container[0] = func(*args, **kwargs)
        except Exception as e:
            error_container[0] = e

    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_READ)

    if error_container[0] is not None:
        raise error_container[0]
    return result_container[0]


def execute_write_on_main_thread(func: Callable, *args, **kwargs) -> Any:
    result_container = [None]
    error_container = [None]

    def wrapper():
        try:
            result_container[0] = func(*args, **kwargs)
        except Exception as e:
            error_container[0] = e

    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)

    if error_container[0] is not None:
        raise error_container[0]
    return result_container[0]


def parse_address(identifier: str) -> int | None:
    if isinstance(identifier, int):
        return identifier
    identifier = identifier.strip()
    try:
        if identifier.startswith("0x") or identifier.startswith("0X"):
            return int(identifier, 16)
        return int(identifier)
    except ValueError:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, identifier)
        if ea != ida_idaapi.BADADDR:
            return ea
        return None


class RpcMethodRegistry:
    def __init__(self):
        self._methods: dict[str, Callable] = {}

    def register(self, name: str | None = None):
        def decorator(func):
            method_name = name or func.__name__
            self._methods[method_name] = func
            return func
        return decorator

    def get(self, name: str) -> Callable | None:
        return self._methods.get(name)

    def list_methods(self) -> list[str]:
        return list(self._methods.keys())


registry = RpcMethodRegistry()


@registry.register()
def ping() -> str:
    return "pong"


@registry.register()
def get_binary_info() -> dict:
    def _impl():
        info = ida_idaapi.get_inf_structure()
        return {
            "filename": ida_nalt.get_input_file_path(),
            "filetype": ida_loader.get_file_type_name(),
            "processor": info.procname,
            "bits": 64 if info.is_64bit() else (32 if info.is_32bit() else 16),
            "entry_point": hex(info.start_ea),
            "base_address": hex(info.min_ea),
            "size": info.max_ea - info.min_ea,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def get_analysis_status() -> dict:
    def _impl():
        return {"complete": ida_auto.auto_is_ok()}
    return execute_on_main_thread(_impl)


@registry.register()
def get_function_list(filter: str = "") -> list[dict]:
    def _impl():
        functions = []
        for i in range(ida_funcs.get_func_qty()):
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            name = ida_funcs.get_func_name(func.start_ea)
            if filter and filter.lower() not in name.lower():
                continue
            functions.append({
                "name": name,
                "start_ea": hex(func.start_ea),
                "end_ea": hex(func.end_ea),
                "size": func.end_ea - func.start_ea,
            })
        return functions
    return execute_on_main_thread(_impl)


@registry.register()
def get_function_by_name(name: str) -> dict | None:
    def _impl():
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        if ea == ida_idaapi.BADADDR:
            return None
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def get_function_by_address(address: str) -> dict | None:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            return None
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return {
            "name": ida_funcs.get_func_name(func.start_ea),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def decompile_function(identifier: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")

        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve identifier: {identifier}")

        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at address {identifier}")

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")

        if cfunc is None:
            raise RuntimeError(f"Decompilation returned None for {identifier}")

        return {
            "function_name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "pseudocode": str(cfunc),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def disassemble_function(identifier: str) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve identifier: {identifier}")

        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at address {identifier}")

        lines = []
        current = func.start_ea
        while current < func.end_ea:
            disasm = idc.generate_disasm_line(current, 0)
            if disasm:
                lines.append(f"{hex(current)}: {disasm}")
            current = idc.next_head(current, func.end_ea)
            if current == ida_idaapi.BADADDR:
                break

        return {
            "function_name": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "assembly": "\n".join(lines),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def disassemble_range(start: str, end: str) -> dict:
    def _impl():
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        if start_ea is None:
            raise ValueError(f"Invalid start address: {start}")
        if end_ea is None:
            raise ValueError(f"Invalid end address: {end}")

        lines = []
        current = start_ea
        while current < end_ea:
            disasm = idc.generate_disasm_line(current, 0)
            if disasm:
                lines.append(f"{hex(current)}: {disasm}")
            current = idc.next_head(current, end_ea)
            if current == ida_idaapi.BADADDR:
                break

        return {"assembly": "\n".join(lines)}
    return execute_on_main_thread(_impl)


@registry.register()
def get_xrefs_to(address: str) -> list[dict]:
    def _impl():
        import ida_xref
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")

        xrefs = []
        xref = ida_xref.get_first_cref_to(ea)
        while xref != ida_idaapi.BADADDR:
            func = ida_funcs.get_func(xref)
            xrefs.append({
                "from_addr": hex(xref),
                "from_func": ida_funcs.get_func_name(func.start_ea) if func else None,
                "type": "code",
            })
            xref = ida_xref.get_next_cref_to(ea, xref)

        xref = ida_xref.get_first_dref_to(ea)
        while xref != ida_idaapi.BADADDR:
            func = ida_funcs.get_func(xref)
            xrefs.append({
                "from_addr": hex(xref),
                "from_func": ida_funcs.get_func_name(func.start_ea) if func else None,
                "type": "data",
            })
            xref = ida_xref.get_next_dref_to(ea, xref)

        return xrefs
    return execute_on_main_thread(_impl)


@registry.register()
def get_xrefs_from(address: str) -> list[dict]:
    def _impl():
        import ida_xref
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")

        xrefs = []
        xref = ida_xref.get_first_cref_from(ea)
        while xref != ida_idaapi.BADADDR:
            xrefs.append({"to_addr": hex(xref), "type": "code"})
            xref = ida_xref.get_next_cref_from(ea, xref)

        xref = ida_xref.get_first_dref_from(ea)
        while xref != ida_idaapi.BADADDR:
            xrefs.append({"to_addr": hex(xref), "type": "data"})
            xref = ida_xref.get_next_dref_from(ea, xref)

        return xrefs
    return execute_on_main_thread(_impl)


@registry.register()
def list_strings(filter: str = "") -> list[dict]:
    def _impl():
        strings = []
        sc = ida_bytes.get_strlist_qty()
        for i in range(sc):
            si = ida_bytes.string_info_t()
            if not ida_bytes.get_strlist_item(si, i):
                continue
            s = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
            if s is None:
                continue
            try:
                decoded = s.decode("utf-8", errors="replace")
            except Exception:
                decoded = repr(s)
            if filter and filter.lower() not in decoded.lower():
                continue
            strings.append({
                "address": hex(si.ea),
                "value": decoded,
                "length": si.length,
            })
        return strings
    return execute_on_main_thread(_impl)


@registry.register()
def list_segments() -> list[dict]:
    def _impl():
        segments = []
        seg = ida_segment.get_first_seg()
        while seg:
            perm_str = ""
            if seg.perm & ida_segment.SFL_LOADER:
                perm_str = "loader"
            else:
                if seg.perm & 4:
                    perm_str += "r"
                if seg.perm & 2:
                    perm_str += "w"
                if seg.perm & 1:
                    perm_str += "x"
            segments.append({
                "name": ida_segment.get_segm_name(seg),
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": perm_str,
                "type": ida_segment.get_segm_class(seg),
            })
            seg = ida_segment.get_next_seg(seg.start_ea)
        return segments
    return execute_on_main_thread(_impl)


@registry.register()
def get_imports() -> list[dict]:
    def _impl():
        imports = []

        def imp_callback(ea, name, ordinal):
            imports.append({
                "address": hex(ea) if ea else None,
                "name": name or f"ordinal_{ordinal}",
                "ordinal": ordinal,
            })
            return True

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            current_module = module_name
            module_imports = []

            def module_imp_callback(ea, name, ordinal):
                module_imports.append({
                    "address": hex(ea) if ea else None,
                    "name": name or f"ordinal_{ordinal}",
                    "ordinal": ordinal,
                    "module": current_module,
                })
                return True

            ida_nalt.enum_import_names(i, module_imp_callback)
            imports.extend(module_imports)

        return imports
    return execute_on_main_thread(_impl)


@registry.register()
def get_exports() -> list[dict]:
    def _impl():
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            exports.append({
                "address": hex(ea),
                "name": name or f"ordinal_{ordinal}",
                "ordinal": ordinal,
            })
        return exports
    return execute_on_main_thread(_impl)


@registry.register()
def list_structs() -> list[dict]:
    def _impl():
        structs = []
        til = ida_typeinf.get_idati()
        qty = ida_typeinf.get_ordinal_count(til)
        for ordinal in range(1, qty + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            if not tif.is_struct() and not tif.is_union():
                continue
            name = tif.get_type_name()
            members = []
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                for member in udt:
                    members.append({
                        "name": member.name,
                        "offset": member.offset // 8,
                        "size": member.size // 8,
                        "type": str(member.type),
                    })
            structs.append({
                "name": name,
                "size": tif.get_size(),
                "is_union": tif.is_union(),
                "members": members,
            })
        return structs
    return execute_on_main_thread(_impl)


@registry.register()
def list_enums() -> list[dict]:
    def _impl():
        enums = []
        til = ida_typeinf.get_idati()
        qty = ida_typeinf.get_ordinal_count(til)
        for ordinal in range(1, qty + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            if not tif.is_enum():
                continue
            name = tif.get_type_name()
            members = []
            ed = ida_typeinf.enum_type_data_t()
            if tif.get_enum_details(ed):
                for member in ed:
                    members.append({
                        "name": member.name,
                        "value": member.value,
                    })
            enums.append({
                "name": name,
                "members": members,
            })
        return enums
    return execute_on_main_thread(_impl)


@registry.register()
def get_bytes_at(address: str, size: int = 16) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        raw = ida_bytes.get_bytes(ea, size)
        if raw is None:
            raise ValueError(f"Cannot read {size} bytes at {address}")
        return {
            "address": hex(ea),
            "size": size,
            "hex": raw.hex(),
            "bytes": list(raw),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def rename_function(identifier: str, new_name: str) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        success = ida_name.set_name(func.start_ea, new_name, ida_name.SN_NOWARN)
        return {"success": bool(success), "address": hex(func.start_ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def rename_address(address: str, new_name: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def set_comment(address: str, comment: str, is_repeatable: bool = False) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = idc.set_cmt(ea, comment, is_repeatable)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def set_function_prototype(identifier: str, prototype: str) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not ida_typeinf.parse_decl(tif, til, prototype, ida_typeinf.PT_SIL):
            raise ValueError(f"Failed to parse prototype: {prototype}")
        success = ida_typeinf.apply_tinfo(func.start_ea, tif, ida_typeinf.TINFO_DEFINITE)
        return {"success": bool(success), "address": hex(func.start_ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def set_type_at(address: str, type_str: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not ida_typeinf.parse_decl(tif, til, type_str, ida_typeinf.PT_SIL):
            raise ValueError(f"Failed to parse type: {type_str}")
        success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def create_struct(name: str, fields: list[dict]) -> dict:
    def _impl():
        til = ida_typeinf.get_idati()
        udt = ida_typeinf.udt_type_data_t()

        for f in fields:
            member = ida_typeinf.udt_member_t()
            member.name = f["name"]
            field_tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(field_tif, til, f.get("type", "int"), ida_typeinf.PT_SIL):
                raise ValueError(f"Cannot parse type for field '{f['name']}': {f.get('type', 'int')}")
            member.type = field_tif
            member.offset = ida_typeinf.BADSIZE
            udt.push_back(member)

        tif = ida_typeinf.tinfo_t()
        if not tif.create_udt(udt):
            raise RuntimeError("Failed to create struct UDT")

        tif.set_named_type(til, name)
        return {"success": True, "name": name}
    return execute_write_on_main_thread(_impl)


@registry.register()
def search_text(query: str, max_results: int = 100) -> list[dict]:
    def _impl():
        results = []
        for i in range(ida_funcs.get_func_qty()):
            if len(results) >= max_results:
                break
            func = ida_funcs.getn_func(i)
            if func is None:
                continue
            current = func.start_ea
            while current < func.end_ea and len(results) < max_results:
                disasm = idc.generate_disasm_line(current, 0)
                if disasm and query.lower() in disasm.lower():
                    results.append({
                        "address": hex(current),
                        "function": ida_funcs.get_func_name(func.start_ea),
                        "line": disasm,
                    })
                current = idc.next_head(current, func.end_ea)
                if current == ida_idaapi.BADADDR:
                    break
        return results
    return execute_on_main_thread(_impl)


@registry.register()
def search_bytes_pattern(pattern: str, max_results: int = 100) -> list[dict]:
    def _impl():
        results = []
        ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        compiled = ida_bytes.compiled_binpat_vec_t()
        encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
        err = ida_bytes.parse_binpat_str(compiled, ea, pattern, 16, encoding)

        if err:
            pattern_clean = pattern.replace(" ", "")
            try:
                raw = bytes.fromhex(pattern_clean)
            except ValueError:
                raise ValueError(f"Invalid byte pattern: {pattern}")

            hex_str = " ".join(f"{b:02X}" for b in raw)
            compiled = ida_bytes.compiled_binpat_vec_t()
            err2 = ida_bytes.parse_binpat_str(compiled, ea, hex_str, 16, encoding)
            if err2:
                raise ValueError(f"Cannot compile byte pattern: {pattern}")

        while ea < max_ea and len(results) < max_results:
            ea = ida_bytes.bin_search(ea, max_ea, compiled, ida_bytes.BIN_SEARCH_FORWARD)
            if ea == ida_idaapi.BADADDR:
                break
            func = ida_funcs.get_func(ea)
            results.append({
                "address": hex(ea),
                "function": ida_funcs.get_func_name(func.start_ea) if func else None,
            })
            ea += 1

        return results
    return execute_on_main_thread(_impl)


@registry.register()
def patch_bytes_at(address: str, hex_bytes: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        clean = hex_bytes.replace(" ", "")
        try:
            raw = bytes.fromhex(clean)
        except ValueError:
            raise ValueError(f"Invalid hex string: {hex_bytes}")
        for i, b in enumerate(raw):
            ida_bytes.patch_byte(ea + i, b)
        return {
            "success": True,
            "address": hex(ea),
            "size": len(raw),
            "patched": clean,
        }
    return execute_write_on_main_thread(_impl)


@registry.register()
def execute_script(code: str) -> dict:
    def _impl():
        local_vars = {}
        exec(code, {"__builtins__": __builtins__}, local_vars)
        result = local_vars.get("result", None)
        output = local_vars.get("output", None)
        if result is not None:
            return {"success": True, "result": result}
        if output is not None:
            return {"success": True, "output": output}
        return {"success": True}
    return execute_on_main_thread(_impl)


@registry.register()
def load_til_file(path: str) -> dict:
    def _impl():
        til = ida_typeinf.get_idati()
        result = ida_typeinf.add_til(path, ida_typeinf.ADDTIL_DEFAULT)
        if result == 0:
            raise RuntimeError(f"Failed to load TIL: {path}")
        return {"success": True, "path": path}
    return execute_on_main_thread(_impl)


@registry.register()
def list_til() -> list[dict]:
    def _impl():
        til = ida_typeinf.get_idati()
        tils = []
        for i in range(til.nbases):
            base = til.base(i)
            tils.append({
                "name": base.name,
                "desc": base.desc if hasattr(base, 'desc') else "",
            })
        return tils
    return execute_on_main_thread(_impl)


@registry.register()
def apply_callee_type(address: str, prototype: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not ida_typeinf.parse_decl(tif, til, prototype, ida_typeinf.PT_SIL):
            raise ValueError(f"Failed to parse: {prototype}")
        success = ida_typeinf.apply_callee_tinfo(ea, tif)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_function_callers(identifier: str) -> list[dict]:
    def _impl():
        import ida_xref
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        callers = {}
        xref = ida_xref.get_first_cref_to(func.start_ea)
        while xref != ida_idaapi.BADADDR:
            caller_func = ida_funcs.get_func(xref)
            if caller_func and caller_func.start_ea != func.start_ea:
                key = caller_func.start_ea
                if key not in callers:
                    callers[key] = {
                        "name": ida_funcs.get_func_name(caller_func.start_ea),
                        "address": hex(caller_func.start_ea),
                        "call_sites": [],
                    }
                callers[key]["call_sites"].append(hex(xref))
            xref = ida_xref.get_next_cref_to(func.start_ea, xref)
        return list(callers.values())
    return execute_on_main_thread(_impl)


@registry.register()
def get_function_callees(identifier: str) -> list[dict]:
    def _impl():
        import ida_xref
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        callees = {}
        current = func.start_ea
        while current < func.end_ea:
            xref = ida_xref.get_first_cref_from(current)
            while xref != ida_idaapi.BADADDR:
                callee_func = ida_funcs.get_func(xref)
                if callee_func and callee_func.start_ea != func.start_ea:
                    if callee_func.start_ea == xref:
                        key = callee_func.start_ea
                        if key not in callees:
                            callees[key] = {
                                "name": ida_funcs.get_func_name(callee_func.start_ea),
                                "address": hex(callee_func.start_ea),
                                "call_sites": [],
                            }
                        callees[key]["call_sites"].append(hex(current))
                xref = ida_xref.get_next_cref_from(current, xref)
            current = idc.next_head(current, func.end_ea)
            if current == ida_idaapi.BADADDR:
                break
        return list(callees.values())
    return execute_on_main_thread(_impl)


@registry.register()
def make_code(address: str, size: int = 0) -> dict:
    def _impl():
        import ida_ua
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        if size > 0:
            ida_bytes.del_items(ea, 0, size)
        length = ida_ua.create_insn(ea)
        return {"success": length > 0, "address": hex(ea), "instruction_size": length}
    return execute_write_on_main_thread(_impl)


@registry.register()
def make_data(address: str, size: int = 1, data_type: str = "byte") -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        type_map = {
            "byte": ida_bytes.byte_flag(),
            "word": ida_bytes.word_flag(),
            "dword": ida_bytes.dword_flag(),
            "qword": ida_bytes.qword_flag(),
            "float": ida_bytes.float_flag(),
            "double": ida_bytes.double_flag(),
        }
        flags = type_map.get(data_type.lower())
        if flags is None:
            raise ValueError(f"Unknown data type: {data_type}. Use: byte, word, dword, qword, float, double")
        success = ida_bytes.create_data(ea, flags, size, ida_idaapi.BADADDR)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def make_string(address: str, length: int = 0) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        if length > 0:
            success = ida_bytes.create_strlit(ea, length, ida_nalt.STRTYPE_C)
        else:
            success = ida_bytes.create_strlit(ea, 0, ida_nalt.STRTYPE_C)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def undefine(address: str, size: int = 1) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_bytes.del_items(ea, 0, size)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def define_function(start: str, end: str = "") -> dict:
    def _impl():
        start_ea = parse_address(start)
        if start_ea is None:
            raise ValueError(f"Invalid start address: {start}")
        end_ea = ida_idaapi.BADADDR
        if end:
            end_ea = parse_address(end)
            if end_ea is None:
                raise ValueError(f"Invalid end address: {end}")
        success = ida_funcs.add_func(start_ea, end_ea)
        return {"success": bool(success), "address": hex(start_ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def undefine_function(address: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {address}")
        success = ida_funcs.del_func(func.start_ea)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def add_bookmark(address: str, description: str = "", index: int = -1) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        slot = index if index >= 0 else idc.get_next_bmask(ea)
        if slot is None or slot < 0:
            for i in range(1024):
                if idc.get_bookmark(i) is None or idc.get_bookmark(i) == ida_idaapi.BADADDR:
                    slot = i
                    break
            else:
                raise RuntimeError("No free bookmark slots")
        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return {"success": True, "address": hex(ea), "slot": slot}
    return execute_write_on_main_thread(_impl)


@registry.register()
def list_bookmarks() -> list[dict]:
    def _impl():
        bookmarks = []
        for i in range(1024):
            ea = idc.get_bookmark(i)
            if ea is None or ea == ida_idaapi.BADADDR:
                continue
            desc = idc.get_bookmark_desc(i)
            bookmarks.append({
                "slot": i,
                "address": hex(ea),
                "description": desc or "",
            })
        return bookmarks
    return execute_on_main_thread(_impl)


@registry.register()
def delete_bookmark(slot: int) -> dict:
    def _impl():
        idc.put_bookmark(ida_idaapi.BADADDR, 0, 0, 0, slot, "")
        return {"success": True, "slot": slot}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_local_variables(identifier: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")
        if cfunc is None:
            raise RuntimeError("Decompilation returned None")
        variables = []
        for lvar in cfunc.get_lvars():
            variables.append({
                "name": lvar.name,
                "type": str(lvar.type()),
                "is_arg": lvar.is_arg_var,
                "is_stk": lvar.is_stk_var(),
            })
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "variables": variables,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def rename_local_variable(func_identifier: str, old_name: str, new_name: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(func_identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {func_identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {func_identifier}")
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")
        if cfunc is None:
            raise RuntimeError("Decompilation returned None")
        for lvar in cfunc.get_lvars():
            if lvar.name == old_name:
                lvar.name = new_name
                cfunc.save_user_lvars()
                return {"success": True, "old_name": old_name, "new_name": new_name}
        raise ValueError(f"Variable '{old_name}' not found")
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_global_variables(filter: str = "") -> list[dict]:
    def _impl():
        variables = []
        ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        while ea < max_ea and len(variables) < 500:
            name = ida_name.get_name(ea)
            if name and not ida_funcs.get_func(ea):
                flags = ida_bytes.get_flags(ea)
                if ida_bytes.is_data(flags):
                    if filter and filter.lower() not in name.lower():
                        ea = idc.next_head(ea, max_ea)
                        if ea == ida_idaapi.BADADDR:
                            break
                        continue
                    size = ida_bytes.get_item_size(ea)
                    variables.append({
                        "name": name,
                        "address": hex(ea),
                        "size": size,
                    })
            ea = idc.next_head(ea, max_ea)
            if ea == ida_idaapi.BADADDR:
                break
        return variables
    return execute_on_main_thread(_impl)


@registry.register()
def set_breakpoint(address: str) -> dict:
    def _impl():
        import ida_dbg
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_dbg.add_bpt(ea)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def delete_breakpoint(address: str) -> dict:
    def _impl():
        import ida_dbg
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_dbg.del_bpt(ea)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def list_breakpoints() -> list[dict]:
    def _impl():
        import ida_dbg
        bpts = []
        qty = ida_dbg.get_bpt_qty()
        for i in range(qty):
            bpt = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(i, bpt):
                bpts.append({
                    "address": hex(bpt.ea),
                    "size": bpt.size,
                    "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED),
                    "type": "hardware" if bpt.type == ida_dbg.BPT_WRITE else "software",
                })
        return bpts
    return execute_on_main_thread(_impl)


@registry.register()
def enable_breakpoint(address: str, enable: bool = True) -> dict:
    def _impl():
        import ida_dbg
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_dbg.enable_bpt(ea, enable)
        return {"success": bool(success), "address": hex(ea), "enabled": enable}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_registers() -> dict:
    def _impl():
        import ida_dbg
        import ida_idd
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        regs = {}
        rv = ida_idd.regval_t()
        reg_names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                      "rip", "rflags",
                      "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
        for name in reg_names:
            if ida_dbg.get_reg_val(name, rv):
                regs[name] = hex(rv.ival)
        return regs
    return execute_on_main_thread(_impl)


@registry.register()
def read_debug_memory(address: str, size: int = 16) -> dict:
    def _impl():
        import ida_dbg
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        data = ida_dbg.dbg_read_memory(ea, size)
        if data is None:
            raise RuntimeError(f"Cannot read {size} bytes at {address}")
        return {
            "address": hex(ea),
            "size": len(data),
            "hex": data.hex(),
            "bytes": list(data),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def start_debugger(args: str = "", path: str = "") -> dict:
    def _impl():
        import ida_dbg
        success = ida_dbg.start_process(path or None, args or None)
        return {"success": success >= 0}
    return execute_write_on_main_thread(_impl)


@registry.register()
def step_into() -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.step_into()
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def step_over() -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.step_over()
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def continue_execution() -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.continue_process()
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def suspend_debugger() -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.suspend_process()
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def exit_debugger() -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.exit_process()
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_debugger_status() -> dict:
    def _impl():
        import ida_dbg
        return {
            "active": ida_dbg.is_debugger_on(),
            "suspended": ida_dbg.is_debugger_on() and not ida_dbg.is_debugger_busy(),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def get_stack_trace() -> list[dict]:
    def _impl():
        import ida_dbg
        import ida_idd
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        trace = ida_idd.call_stack_t()
        if not ida_dbg.get_call_stack(trace):
            raise RuntimeError("Cannot retrieve call stack")
        frames = []
        for i in range(trace.size()):
            entry = trace[i]
            func = ida_funcs.get_func(entry.callea)
            frames.append({
                "index": i,
                "caller": hex(entry.callea),
                "function": ida_funcs.get_func_name(func.start_ea) if func else None,
            })
        return frames
    return execute_on_main_thread(_impl)


@registry.register()
def get_flowchart(identifier: str) -> dict:
    def _impl():
        import ida_gdl
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        fc = ida_gdl.FlowChart(func)
        blocks = []
        for block in fc:
            succs = []
            for succ in block.succs():
                succs.append(hex(succ.start_ea))
            preds = []
            for pred in block.preds():
                preds.append(hex(pred.start_ea))
            blocks.append({
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": succs,
                "predecessors": preds,
            })
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "block_count": len(blocks),
            "blocks": blocks,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def get_comment(address: str, is_repeatable: bool = False) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        cmt = idc.get_cmt(ea, is_repeatable)
        return {
            "address": hex(ea),
            "comment": cmt or "",
            "is_repeatable": is_repeatable,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def get_all_comments_in_function(identifier: str) -> list[dict]:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        comments = []
        current = func.start_ea
        while current < func.end_ea:
            regular = idc.get_cmt(current, False)
            repeatable = idc.get_cmt(current, True)
            if regular:
                comments.append({
                    "address": hex(current),
                    "comment": regular,
                    "is_repeatable": False,
                })
            if repeatable:
                comments.append({
                    "address": hex(current),
                    "comment": repeatable,
                    "is_repeatable": True,
                })
            current = idc.next_head(current, func.end_ea)
            if current == ida_idaapi.BADADDR:
                break
        return comments
    return execute_on_main_thread(_impl)


@registry.register()
def get_function_comment(identifier: str, is_repeatable: bool = False) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        cmt = ida_funcs.get_func_cmt(func, is_repeatable)
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "comment": cmt or "",
            "is_repeatable": is_repeatable,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def set_function_comment(identifier: str, comment: str, is_repeatable: bool = False) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        success = ida_funcs.set_func_cmt(func, comment, is_repeatable)
        return {"success": bool(success), "address": hex(func.start_ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_stack_frame(identifier: str) -> dict:
    def _impl():
        import ida_frame
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        frame = ida_frame.get_frame(func)
        if frame is None:
            return {
                "function": ida_funcs.get_func_name(func.start_ea),
                "address": hex(func.start_ea),
                "frame_size": 0,
                "members": [],
            }
        members = []
        for i in range(frame.memqty):
            member = frame.get_member(i)
            if member is None:
                continue
            name = ida_typeinf.get_member_name(member.id) if hasattr(ida_typeinf, 'get_member_name') else str(member.id)
            try:
                name = ida_struct.get_member_name(member.id) if 'ida_struct' in dir() else name
            except Exception:
                pass
            members.append({
                "name": name,
                "offset": member.soff,
                "size": member.eoff - member.soff,
            })
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "frame_size": ida_frame.get_frame_size(func),
            "local_size": func.frsize,
            "saved_regs": func.frregs,
            "args_size": func.argsize,
            "members": members,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def set_operand_type(address: str, operand_num: int, display_type: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        n = operand_num
        type_map = {
            "hex": lambda: idc.op_hex(ea, n),
            "decimal": lambda: idc.op_dec(ea, n),
            "octal": lambda: idc.op_oct(ea, n),
            "binary": lambda: idc.op_bin(ea, n),
            "char": lambda: idc.op_chr(ea, n),
            "default": lambda: idc.op_plain_offset(ea, n, 0),
        }
        handler = type_map.get(display_type.lower())
        if handler is None:
            raise ValueError(f"Unknown display type: {display_type}. Use: hex, decimal, octal, binary, char, default")
        success = handler()
        return {"success": bool(success), "address": hex(ea), "operand": n, "type": display_type}
    return execute_write_on_main_thread(_impl)


@registry.register()
def set_local_variable_type(func_identifier: str, var_name: str, type_str: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(func_identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {func_identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {func_identifier}")
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")
        if cfunc is None:
            raise RuntimeError("Decompilation returned None")
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not ida_typeinf.parse_decl(tif, til, type_str, ida_typeinf.PT_SIL):
            raise ValueError(f"Failed to parse type: {type_str}")
        for lvar in cfunc.get_lvars():
            if lvar.name == var_name:
                lvar.set_lvar_type(tif)
                cfunc.save_user_lvars()
                return {"success": True, "variable": var_name, "new_type": type_str}
        raise ValueError(f"Variable '{var_name}' not found")
    return execute_write_on_main_thread(_impl)


@registry.register()
def apply_sig(sig_name: str) -> dict:
    def _impl():
        result = ida_funcs.plan_to_apply_idasgn(sig_name)
        return {"success": result >= 0, "signature": sig_name}
    return execute_on_main_thread(_impl)


@registry.register()
def list_applied_sigs() -> list[str]:
    def _impl():
        sigs = []
        for i in range(ida_funcs.get_idasgn_qty()):
            name = ida_funcs.get_idasgn_desc(i)
            if name:
                sigs.append(name)
        return sigs
    return execute_on_main_thread(_impl)


@registry.register()
def set_color(address: str, color: int, item_type: str = "instruction") -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        type_map = {
            "instruction": idc.CIC_ITEM,
            "function": idc.CIC_FUNC,
            "segment": idc.CIC_SEGM,
        }
        cic = type_map.get(item_type.lower())
        if cic is None:
            raise ValueError(f"Unknown item type: {item_type}. Use: instruction, function, segment")
        success = idc.set_color(ea, cic, color)
        return {"success": bool(success), "address": hex(ea), "color": hex(color)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_color(address: str, item_type: str = "instruction") -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        type_map = {
            "instruction": idc.CIC_ITEM,
            "function": idc.CIC_FUNC,
            "segment": idc.CIC_SEGM,
        }
        cic = type_map.get(item_type.lower())
        if cic is None:
            raise ValueError(f"Unknown item type: {item_type}. Use: instruction, function, segment")
        color = idc.get_color(ea, cic)
        return {"address": hex(ea), "color": hex(color) if color != 0xFFFFFFFF else None}
    return execute_on_main_thread(_impl)


@registry.register()
def save_database(path: str = "") -> dict:
    def _impl():
        if path:
            success = ida_loader.save_database(path, 0)
        else:
            success = ida_loader.save_database(ida_nalt.get_input_file_path() + ".idb", 0)
        return {"success": bool(success)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def create_segment(name: str, start: str, end: str, seg_class: str = "DATA", permissions: int = 7) -> dict:
    def _impl():
        start_ea = parse_address(start)
        end_ea = parse_address(end)
        if start_ea is None:
            raise ValueError(f"Invalid start: {start}")
        if end_ea is None:
            raise ValueError(f"Invalid end: {end}")
        seg = ida_segment.segment_t()
        seg.start_ea = start_ea
        seg.end_ea = end_ea
        seg.perm = permissions
        seg.bitness = 2 if ida_idaapi.get_inf_structure().is_64bit() else 1
        success = ida_segment.add_segm_ex(seg, name, seg_class, 0)
        return {"success": bool(success), "name": name, "start": hex(start_ea), "end": hex(end_ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def delete_segment(address: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_segment.del_segm(ea, ida_segment.SEGMOD_KEEP)
        return {"success": bool(success), "address": hex(ea)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def set_segment_permissions(address: str, read: bool = True, write: bool = True, execute: bool = True) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        seg = ida_segment.getseg(ea)
        if seg is None:
            raise ValueError(f"No segment at {address}")
        perm = 0
        if read:
            perm |= 4
        if write:
            perm |= 2
        if execute:
            perm |= 1
        seg.perm = perm
        success = seg.update()
        return {"success": bool(success), "segment": ida_segment.get_segm_name(seg)}
    return execute_write_on_main_thread(_impl)


@registry.register()
def create_array(address: str, count: int, element_type: str = "byte") -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        type_sizes = {
            "byte": 1,
            "word": 2,
            "dword": 4,
            "qword": 8,
        }
        elem_size = type_sizes.get(element_type.lower())
        if elem_size is None:
            raise ValueError(f"Unknown element type: {element_type}. Use: byte, word, dword, qword")
        type_flags = {
            "byte": ida_bytes.byte_flag(),
            "word": ida_bytes.word_flag(),
            "dword": ida_bytes.dword_flag(),
            "qword": ida_bytes.qword_flag(),
        }
        flags = type_flags[element_type.lower()]
        ida_bytes.del_items(ea, 0, count * elem_size)
        success = ida_bytes.create_data(ea, flags, elem_size, ida_idaapi.BADADDR)
        if success:
            success = ida_bytes.create_data(ea, flags, count * elem_size, ida_idaapi.BADADDR)
        return {"success": bool(success), "address": hex(ea), "count": count, "element_type": element_type}
    return execute_write_on_main_thread(_impl)


@registry.register()
def list_debugger_threads() -> list[dict]:
    def _impl():
        import ida_dbg
        import ida_idd
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        threads = []
        qty = ida_dbg.get_thread_qty()
        for i in range(qty):
            tid = ida_dbg.getn_thread(i)
            tinfo = ida_idd.thrinf_t()
            if ida_dbg.get_thread_info(tid, tinfo):
                threads.append({
                    "tid": tid,
                    "name": tinfo.name if hasattr(tinfo, 'name') else "",
                    "state": "suspended" if tinfo.state == 0 else "running",
                })
            else:
                threads.append({"tid": tid, "name": "", "state": "unknown"})
        return threads
    return execute_on_main_thread(_impl)


@registry.register()
def switch_debugger_thread(tid: int) -> dict:
    def _impl():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            raise RuntimeError("Debugger is not active")
        success = ida_dbg.select_thread(tid)
        return {"success": bool(success), "tid": tid}
    return execute_write_on_main_thread(_impl)


@registry.register()
def add_watchpoint(address: str, size: int = 4, watch_type: str = "write") -> dict:
    def _impl():
        import ida_dbg
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        type_map = {
            "write": ida_dbg.BPT_WRITE,
            "read": ida_dbg.BPT_RDWR,
            "execute": ida_dbg.BPT_EXEC,
        }
        bpt_type = type_map.get(watch_type.lower())
        if bpt_type is None:
            raise ValueError(f"Unknown watch type: {watch_type}. Use: write, read, execute")
        success = ida_dbg.add_bpt(ea, size, bpt_type)
        return {"success": bool(success), "address": hex(ea), "size": size, "type": watch_type}
    return execute_write_on_main_thread(_impl)


@registry.register()
def get_function_hash(identifier: str, algorithm: str = "md5") -> dict:
    def _impl():
        import hashlib
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        func_bytes = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
        if func_bytes is None:
            raise RuntimeError("Cannot read function bytes")
        algo_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }
        hasher = algo_map.get(algorithm.lower())
        if hasher is None:
            raise ValueError(f"Unknown algorithm: {algorithm}. Use: md5, sha1, sha256")
        digest = hasher(func_bytes).hexdigest()
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "address": hex(func.start_ea),
            "size": func.end_ea - func.start_ea,
            "algorithm": algorithm,
            "hash": digest,
        }
    return execute_on_main_thread(_impl)


@registry.register()
def navigate_to(address: str) -> dict:
    def _impl():
        ea = parse_address(address)
        if ea is None:
            raise ValueError(f"Invalid address: {address}")
        success = ida_kernwin.jumpto(ea)
        return {"success": bool(success), "address": hex(ea)}
    return execute_on_main_thread(_impl)


@registry.register()
def get_microcode(identifier: str, maturity: str = "preoptimized") -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        mat_map = {
            "generated": ida_hexrays.MMAT_GENERATED,
            "preoptimized": ida_hexrays.MMAT_PREOPTIMIZED,
            "locopt": ida_hexrays.MMAT_LOCOPT,
            "calls": ida_hexrays.MMAT_CALLS,
            "glbopt1": ida_hexrays.MMAT_GLBOPT1,
            "glbopt2": ida_hexrays.MMAT_GLBOPT2,
            "glbopt3": ida_hexrays.MMAT_GLBOPT3,
            "lvars": ida_hexrays.MMAT_LVARS,
        }
        mat = mat_map.get(maturity.lower(), ida_hexrays.MMAT_PREOPTIMIZED)
        mbr = ida_hexrays.mba_ranges_t()
        mbr.ranges.push_back(ida_range.range_t(func.start_ea, func.end_ea))
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, mat)
        if mba is None:
            raise RuntimeError(f"Microcode generation failed: {hf.str}")
        lines = []
        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            lines.append(f"Block {i} ({hex(blk.start)}-{hex(blk.end)}):")
            insn = blk.head
            while insn:
                lines.append(f"  {insn._print()}")
                insn = insn.next
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "maturity": maturity,
            "block_count": mba.qty,
            "microcode": "\n".join(lines),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def produce_asm_file(identifier: str) -> dict:
    def _impl():
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        lines = []
        current = func.start_ea
        while current < func.end_ea:
            line = idc.generate_disasm_line(current, 0)
            if line:
                lines.append(f"{ida_funcs.get_func_name(func.start_ea) if current == func.start_ea else '':<30} {line}")
            current = idc.next_head(current, func.end_ea)
            if current == ida_idaapi.BADADDR:
                break
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "asm": "\n".join(lines),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def produce_c_file(identifier: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")
        if cfunc is None:
            raise RuntimeError("Decompilation returned None")
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "c_code": str(cfunc),
        }
    return execute_on_main_thread(_impl)


@registry.register()
def run_idc(code: str) -> dict:
    def _impl():
        result = idc.eval_idc(code)
        return {"success": True, "result": str(result) if result is not None else None}
    return execute_on_main_thread(_impl)


@registry.register()
def run_ida_action(action_name: str) -> dict:
    def _impl():
        success = ida_kernwin.process_ui_action(action_name, 0)
        return {"success": bool(success), "action": action_name}
    return execute_on_main_thread(_impl)


@registry.register()
def list_ida_actions() -> list[str]:
    def _impl():
        actions = []
        for name in ida_kernwin.get_registered_actions():
            actions.append(name)
        return sorted(actions)
    return execute_on_main_thread(_impl)


@registry.register()
def get_exception_info(identifier: str) -> dict:
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")

    def _impl():
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays decompiler failed to initialize")
        ea = parse_address(identifier)
        if ea is None:
            raise ValueError(f"Cannot resolve: {identifier}")
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {identifier}")
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except ida_hexrays.DecompilationFailure as e:
            raise RuntimeError(f"Decompilation failed: {e}")
        if cfunc is None:
            raise RuntimeError("Decompilation returned None")
        pseudocode = str(cfunc)
        has_try = "try" in pseudocode
        has_catch = "catch" in pseudocode
        has_throw = "throw" in pseudocode
        return {
            "function": ida_funcs.get_func_name(func.start_ea),
            "has_exception_handling": has_try or has_catch,
            "has_try": has_try,
            "has_catch": has_catch,
            "has_throw": has_throw,
            "pseudocode": pseudocode if (has_try or has_catch) else None,
        }
    return execute_on_main_thread(_impl)


class JsonRpcServer:
    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT):
        self._host = host
        self._port = port
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        ida_kernwin.msg(f"[IDA-MCP] JSON-RPC server started on {self._host}:{self._port}\n")

    def stop(self):
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
        ida_kernwin.msg("[IDA-MCP] JSON-RPC server stopped\n")

    def _serve(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(5)

        while self._running:
            try:
                client, addr = self._server_socket.accept()
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr),
                    daemon=True,
                )
                handler.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, client: socket.socket, addr):
        client.settimeout(None)
        buffer = b""

        try:
            while self._running:
                data = client.recv(BUFFER_SIZE)
                if not data:
                    break
                buffer += data

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    response = self._process_request(line)
                    client.sendall(response + b"\n")
        except (ConnectionError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _process_request(self, data: bytes) -> bytes:
        try:
            obj = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error_response(None, -32700, "Parse error")

        req_id = obj.get("id")
        method_name = obj.get("method")
        params = obj.get("params", {})

        if not method_name:
            return self._error_response(req_id, -32600, "Invalid request: missing method")

        method = registry.get(method_name)
        if method is None:
            return self._error_response(req_id, -32601, f"Method not found: {method_name}")

        try:
            if isinstance(params, dict):
                result = method(**params)
            elif isinstance(params, list):
                result = method(*params)
            else:
                result = method()

            response = {"jsonrpc": "2.0", "result": result, "id": req_id}
            return json.dumps(response).encode("utf-8")

        except TypeError as e:
            return self._error_response(req_id, -32602, f"Invalid params: {e}")
        except ValueError as e:
            return self._error_response(req_id, -32602, str(e))
        except RuntimeError as e:
            return self._error_response(req_id, -32603, str(e))
        except Exception as e:
            tb = traceback.format_exc()
            ida_kernwin.msg(f"[IDA-MCP] Error in {method_name}: {tb}\n")
            return self._error_response(req_id, -32603, f"Internal error: {e}")

    def _error_response(self, req_id, code: int, message: str) -> bytes:
        response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
            "id": req_id,
        }
        return json.dumps(response).encode("utf-8")


class IdaMcpPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "MCP bridge for AI-assisted reverse engineering"
    help = "Exposes IDA Pro APIs via JSON-RPC for Claude Code integration"
    wanted_name = "IDA MCP"
    wanted_hotkey = ""

    def init(self):
        self._server = JsonRpcServer()
        self._server.start()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.msg(f"[IDA-MCP] Server running on 127.0.0.1:{DEFAULT_PORT}\n")
        ida_kernwin.msg(f"[IDA-MCP] Available methods: {', '.join(registry.list_methods())}\n")

    def term(self):
        if hasattr(self, "_server"):
            self._server.stop()


def PLUGIN_ENTRY():
    return IdaMcpPlugin()
