"""Smoke tests for the parity track, consumed by run_comprehensive_tests.py.

Each phase maps to (title, [(test_id, tool, args), ...]). Tests run in order
against putty.exe (MIT, PE x64) in the disposable ``parity_smoke`` project, so
create -> use -> clean up sequences are allowed. binary_name/project_name are
filled in by the runner.

Usage:
    python run_comprehensive_tests.py --parity          # all parity phases
    python run_comprehensive_tests.py --parity 10 11    # selected phases
"""

import os
import shutil
from pathlib import Path

ROOT = Path(__file__).parent
FIXTURES = ROOT / "tests" / "fixtures"
EXPORTS = ROOT / "exports"
F = "0x140001000"  # putty.exe FUN_140001000: 4 params (RCX,RDX,R8,R9), 6 locals
ENTRY = "0x1400be504"

# Second binary for cross-program tools (identical code, different program)
_B = ROOT / "binaries"
if (_B / "putty.exe").exists() and not (_B / "putty_b.exe").exists():
    shutil.copy(_B / "putty.exe", _B / "putty_b.exe")

# Hand-assembled x64 djb2(RCX=str) -> EAX, used by the emulation tests:
#   mov eax,5381 / loop: movzx edx,[rcx] / test dl,dl / je done / mov r8d,eax /
#   shl eax,5 / add eax,r8d / add eax,edx / inc rcx / jmp loop / done: ret
DJB2_X64 = "b805150000 0fb611 84d2 7410 4189c0 c1e005 4401c0 01d0 48ffc1 ebe9 c3".replace(" ", "")

PARITY_TESTS = {
    9: ("Program, Memory, Options & Utilities", [
        ("P9-001", "get_address_spaces", {}),
        ("P9-002", "get_language_metadata", {"include_registers": True}),
        ("P9-003", "get_program_options", {}),
        ("P9-004", "get_program_options", {"group": "Program Information"}),
        ("P9-005", "set_program_option", {"group": "MCP Smoke", "name": "note", "value": "hi", "type": "string"}),
        ("P9-006", "remove_program_option", {"group": "MCP Smoke", "name": "note"}),
        ("P9-007", "create_property_map", {"name": "mcp_smoke_tags", "type": "string"}),
        ("P9-008", "set_property", {"map": "mcp_smoke_tags", "address": "entry", "value": "entry-point"}),
        ("P9-009", "get_property", {"map": "mcp_smoke_tags", "address": "entry"}),
        ("P9-010", "list_properties", {}),
        ("P9-011", "list_properties", {"map": "mcp_smoke_tags"}),
        ("P9-012", "remove_property", {"map": "mcp_smoke_tags", "address": "entry"}),
        ("P9-013", "delete_property_map", {"name": "mcp_smoke_tags"}),
        ("P9-014", "create_memory_block", {"name": "mcp_smoke", "address": "0x200000000",
                                           "bytes_hex": "deadbeef", "execute": True}),
        ("P9-015", "set_memory_block", {"block": "mcp_smoke", "write": True, "execute": False}),
        ("P9-016", "analysis_status", {}),
        ("P9-017", "configure_analyzer", {"name": "Decompiler Parameter ID", "enabled": True}),
        ("P9-018", "set_bookmark", {"address": "0x1400be504", "category": "mcp_smoke", "comment": "x"}),
        ("P9-019", "delete_bookmark", {"address": "entry", "category": "mcp_smoke"}),
        ("P9-020", "list_calling_conventions", {}),
        ("P9-021", "get_external_location", {}),
        ("P9-022", "get_external_location", {"dll_name": "KERNEL32.DLL"}),
        ("P9-023", "set_image_base", {"address": "0x150000000"}),
        ("P9-024", "set_image_base", {"address": "0x140000000"}),
        ("P9-025", "convert_number", {"text": "0xFFFFFFFE", "size": 4}),
        ("P9-026", "check_connection", {}),
        ("P9-027", "mcp_health", {}),
        ("P9-028", "mcp_schema", {"tool": "get_address_spaces"}),
    ]),
    10: ("Advanced Data Types", [
        ("P10-001", "create_union", {"name": "McpU1", "fields": [{"name": "i", "type": "int"},
                                                                 {"name": "q", "type": "longlong"}]}),
        ("P10-002", "create_function_signature", {"name": "mcp_cb_t", "prototype": "int mcp_cb_t(void *ctx, int n)"}),
        ("P10-003", "create_function_signature", {"name": "mcp_cb2_t", "return_type": "void",
                                                  "parameters": [{"name": "p", "type": "char *"}]}),
        ("P10-004", "create_derived_type", {"kind": "array", "base_type": "int", "length": 4, "name": "mcp_int4_t"}),
        ("P10-005", "create_derived_type", {"kind": "pointer", "base_type": "McpU1"}),
        ("P10-006", "create_derived_type", {"kind": "typedef", "base_type": "McpU1", "name": "McpU1_t"}),
        ("P10-007", "create_data_type_category", {"category_path": "/mcp_smoke/pk"}),
        ("P10-008", "clone_data_type", {"source_type": "McpU1", "new_name": "McpU2"}),
        ("P10-009", "move_data_type_to_category", {"type_name": "McpU2", "category_path": "/mcp_smoke/pk"}),
        ("P10-010", "rename_data_type", {"old_name": "McpU2", "new_name": "McpU3"}),
        ("P10-011", "recreate_struct", {"name": "McpS1", "fields": [{"name": "a", "type": "int"},
                                                                    {"name": "b", "type": "char *", "offset": 8}]}),
        ("P10-012", "resize_struct", {"name": "McpS1", "new_size": 32}),
        ("P10-013", "resize_struct", {"name": "McpS1", "new_size": 12, "force": True}),
        ("P10-014", "resolve_duplicate_type", {"type_name": "McpS1"}),
        ("P10-015", "validate_data_type", {"type_name": "McpS1 *"}),
        ("P10-016", "validate_data_type", {"type_name": "char[16]", "address": "entry"}),
        ("P10-017", "validate_function_prototype", {"prototype": "int foo(char *s, int n)"}),
        ("P10-018", "validate_function_prototype", {"prototype": "int foo(char *s, int n)",
                                                    "calling_convention": "__fastcall"}),
        ("P10-019", "get_valid_data_types", {"filter": "dword", "limit": 20}),
        ("P10-020", "suggest_field_names", {"struct_address": "0x140132000", "struct_size": 32}),
        ("P10-021", "analyze_data_region", {"address": "0x140132000", "max_scan_bytes": 128}),
        ("P10-022", "detect_array_bounds", {"address": "0x140132000"}),
        ("P10-023", "get_field_access_context", {"struct_address": "0x140132000", "field_offset": 0}),
        ("P10-024", "apply_data_classification", {"address": "0x200000000", "classification": "STRUCTURE",
                                                  "type_definition": {"name": "McpBlk", "fields": [
                                                      {"name": "magic", "type": "uint"}]},
                                                  "name": "g_mcpBlk", "comment": "smoke"}),
        ("P10-025", "analyze_struct_field_usage", {"address": "0x200000000", "max_functions": 5}),
        ("P10-026", "import_data_types", {"source": str(FIXTURES / "mcp_smoke_types.h")}),
    ]),
    11: ("Globals, Listings, Symbols, Comments & Xrefs", [
        ("P11-001", "list_globals", {"limit": 10}),
        ("P11-002", "list_globals", {"min_xrefs": 3, "limit": 5, "undocumented_only": True}),
        ("P11-003", "list_shadowed_globals", {"limit": 10}),
        ("P11-004", "list_data_items_by_xrefs", {"limit": 10}),
        ("P11-005", "list_program_items", {"kind": "segments"}),
        ("P11-006", "list_program_items", {"kind": "imports", "limit": 10}),
        ("P11-007", "list_program_items", {"kind": "exports"}),
        ("P11-008", "list_program_items", {"kind": "external_locations", "limit": 5}),
        ("P11-009", "list_program_items", {"kind": "namespaces", "limit": 5}),
        ("P11-010", "audit_global", {"address": "0x140132000"}),
        ("P11-011", "set_global", {"address": "0x140132010", "name": "g_mcpSmoke", "type_name": "dword",
                                   "array_length": 2, "plate_comment": "smoke global"}),
        ("P11-012", "analyze_global_completeness", {"address": "g_mcpSmoke"}),
        ("P11-013", "audit_globals_in_function", {"function": "entry"}),
        ("P11-014", "can_rename_at_address", {"address": "0x140132010"}),
        ("P11-015", "rename_symbol", {"target": "0x140132010", "new_name": "g_mcpSmoke2"}),
        ("P11-016", "rename_symbol", {"target": "g_mcpSmoke2", "new_name": "g_mcpSmoke"}),
        ("P11-017", "set_repeatable_comment", {"address": "0x140132010", "comment": "repeat me"}),
        ("P11-018", "get_comment", {"address": "0x140132010"}),
        ("P11-019", "get_comment", {"addresses": "0x140132010,entry", "only_with_comments": True}),
        ("P11-020", "add_memory_reference", {"from_address": "0x140132010", "to_address": "entry"}),
        ("P11-021", "get_xrefs_to", {"address": "0x1400be504"}),
        ("P11-022", "remove_reference", {"from_address": "0x140132010", "to_address": "entry"}),
        ("P11-023", "get_assembly_context", {"xref_sources": "entry", "context_instructions": 3}),
        ("P11-024", "get_full_call_graph", {"limit": 50, "format": "mermaid"}),
        ("P11-025", "analyze_call_graph", {"analysis_type": "stats", "limit": 5}),
        ("P11-026", "analyze_call_graph", {"analysis_type": "cycles", "limit": 5}),
        ("P11-027", "analyze_call_graph", {"analysis_type": "path", "start_function": "entry",
                                           "end_function": "entry"}),
        ("P11-028", "search_instructions", {"mnemonic": "call", "limit": 5}),
        ("P11-029", "search_instructions", {"operand_pattern": "[rsp+0x", "function": "entry", "limit": 5}),
        ("P11-030", "find_code_gaps", {"min_size": 32, "limit": 5}),
        ("P11-031", "find_next_undefined_function", {}),
        ("P11-032", "list_class_members", {"class_name": "std"}),
    ]),
    12: ("Function Editing, P-code & Dataflow", [
        ("P12-001", "add_function_tag", {"function": F, "tags": "mcp_smoke,parser",
                                         "tag_comments": {"mcp_smoke": "smoke test tag"}}, "mcp_smoke"),
        ("P12-002", "add_function_tag", {"assignments": [{"function": "entry", "tags": "mcp_smoke"}]}),
        ("P12-003", "list_function_tags", {}, "mcp_smoke"),
        ("P12-004", "list_function_tags", {"tag": "mcp_smoke"}, "entry"),
        ("P12-005", "set_function_tag_comment", {"name": "parser", "comment": "parses things"}),
        ("P12-006", "remove_function_tag", {"function": F, "tags": "parser"}),
        ("P12-007", "delete_function_tag", {"name": "parser"}),
        ("P12-008", "rename_variables", {"function": F, "variable_renames": {"param_1": "pBuf"}}, "pBuf"),
        ("P12-009", "set_variable_type", {"function": F, "variable_name": "param_2", "new_type": "ulonglong"}),
        ("P12-010", "set_variables", {"function": F, "variables": [
            {"name": "param_3", "new_name": "pCtx", "type": "void *"},
            {"name": "param_4", "new_name": "dwFlags", "type": "uint"}]}, "dwFlags"),
        ("P12-011", "batch_rename_function_components", {"function": F, "parameter_renames": {"pBuf": "pBuffer"},
                                                         "return_type": "int"}, "pBuffer"),
        ("P12-012", "get_functions", {"functions": F + ",entry", "fields": "signature,variables,tags,metrics"},
         "pBuffer"),
        ("P12-013", "force_decompile", {"function": F}, "pBuffer"),
        ("P12-014", "get_function_pcode", {"function": "entry", "granularity": "basic"}, "pcode"),
        ("P12-015", "get_function_pcode", {"function": F, "max_ops": 50}, "blocks"),
        ("P12-016", "analyze_dataflow", {"address": F, "variable": "pBuffer", "direction": "forward"}),
        ("P12-017", "analyze_dataflow", {"address": F, "variable": "pBuffer", "direction": "backward"}),
        ("P12-018", "set_variable_storage", {"function": F, "variable_name": "dwFlags", "storage": "R9"}, "R9"),
        ("P12-019", "set_function_this_type", {"function": F, "this_type": "McpSmokeClass"}, "McpSmokeClass"),
        ("P12-020", "list_class_members", {"class_name": "McpSmokeClass"}, "140001000"),
        ("P12-021", "list_program_items", {"kind": "classes"}, "McpSmokeClass"),
        ("P12-022", "clear_instruction_flow_override", {"address": ENTRY, "flow_override": "CALL_RETURN"}),
        ("P12-023", "clear_instruction_flow_override", {"address": ENTRY}, "NONE"),
        ("P12-024", "clear_flow_and_repair", {"start_address": "0x140132020"}),
    ]),
    13: ("Documentation Workflow & Cross-Binary", [
        ("P13-000", "analyze_binary", {"file_path": "putty_b.exe"}),
        ("P13-001", "analyze_function_completeness", {"function": F}, "score"),
        ("P13-002", "analyze_function_completeness", {"addresses": "entry," + F, "compact": True}, "results"),
        ("P13-003", "analyze_for_documentation", {"function": F}, "classification"),
        ("P13-004", "analyze_function_complete", {"function": "entry", "include_disasm": False}, "completeness"),
        ("P13-005", "apply_documentation", {"address": F, "name": "McpParseBuffer",
                                            "plate_comment": "Parses a buffer (smoke)",
                                            "comments": [{"offset": 0, "type": "eol", "text": "prologue"}],
                                            "tags": "mcp_smoke"}, "McpParseBuffer"),
        ("P13-006", "get_function_documentation", {"function": "McpParseBuffer"}, ["prologue", "hash"]),
        ("P13-007", "apply_documentation", {"entries": [
            {"address": "entry", "plate_comment": "CRT entry point"},
            {"address": "0x140001010", "plate_comment": "inner"}]}, "applied"),
        ("P13-008", "get_function_hashes", {"limit": 5}, "hash"),
        ("P13-009", "get_function_hashes", {"filter": "documented", "limit": 5}, "McpParseBuffer"),
        ("P13-010", "batch_string_anchor_report", {"limit": 10}, "anchors"),
        ("P13-011", "find_undocumented_by_string", {"address": "0x1400ed000"}),
        ("P13-012", "find_similar_functions_fuzzy", {"function": "McpParseBuffer", "source_program": "putty.exe",
                                                     "target_program": "putty_b.exe"}, "exact_hash_match"),
        ("P13-013", "bulk_fuzzy_match", {"source_program": "putty.exe", "target_program": "putty_b.exe",
                                         "exact_only": True, "limit": 5}, "exact_hash"),
        ("P13-014", "merge_program_documentation", {"source": "putty.exe", "target": "putty_b.exe",
                                                    "dry_run": True}, "McpParseBuffer"),
        ("P13-015", "merge_program_documentation", {"source": "putty.exe", "target": "putty_b.exe",
                                                    "match_by": "hash"}, "applied"),
        ("P13-016", "compare_programs_documentation", {}, "putty_b.exe"),
        ("P13-017", "archive_ingest_function", {"function": "McpParseBuffer", "version_override": "smoke",
                                                "dry_run": True}, "created"),
        ("P13-018", "archive_ingest_program", {"limit": 5, "dry_run": True}, "functions"),
    ]),
    14: ("P-code Emulation", [
        ("P14-001", "create_memory_block", {"name": "mcp_emu", "address": "0x210000000",
                                            "bytes_hex": DJB2_X64, "execute": True}),
        ("P14-002", "create_function", {"address": "0x210000000", "name": "mcp_djb2"}),
        ("P14-003", "emulate_function", {"function": "mcp_djb2", "registers": {"RCX": "0xe0000000"},
                                         "memory": [{"address": "0xe0000000", "string": "abc"}]},
         ["returned", "0xb885c8b"]),
        ("P14-004", "emulate_hash_batch", {"hash_function_address": "mcp_djb2", "target_hash": "0x5fbff0fb",
                                           "candidates": "GetProcAddress,LoadLibraryA,VirtualAlloc"},
         '"LoadLibraryA"'),
        ("P14-005", "emulate_function", {"function": "entry", "max_steps": 200}, "status"),
    ]),
    15: ("Project & Program Lifecycle", [
        ("P15-001", "create_project", {"_raw": True, "name": "mcp_smoke_proj"}, "mcp_smoke_proj"),
        ("P15-002", "export_program", {"program_name": "putty_b.exe"}, ".gzf"),
        ("P15-003", "import_program", {"project_name": "mcp_smoke_proj", "gzf_path": str(EXPORTS / "putty_b.exe.gzf"),
                                       "target_folder": "/fw/v1", "target_name": "putty_imported"}, "/fw/v1/putty_imported"),
        ("P15-004", "create_folder", {"project_name": "mcp_smoke_proj", "path": "/archive/old"}, "/archive/old"),
        ("P15-005", "move_file", {"project_name": "mcp_smoke_proj", "filePath": "putty_imported",
                                  "destFolder": "/archive"}, "/archive/putty_imported"),
        ("P15-006", "move_folder", {"project_name": "mcp_smoke_proj", "sourcePath": "/fw",
                                    "destPath": "/archive"}, "/archive/fw"),
        ("P15-007", "list_project_files", {"project_name": "mcp_smoke_proj", "folder": "/archive"}, "putty_imported"),
        ("P15-008", "get_project_info", {"project_name": "mcp_smoke_proj"}, "putty_imported"),
        ("P15-009", "archive_project", {"project_name": "mcp_smoke_proj"}, ".gar"),
        ("P15-010", "restore_project", {"_raw": True, "project_name": "mcp_smoke_restored",
                                        "gar_path": str(EXPORTS / "mcp_smoke_proj.gar")}, "putty_imported"),
        ("P15-011", "delete_file", {"project_name": "mcp_smoke_proj", "filePath": "/archive/putty_imported"}, "deleted"),
        ("P15-012", "open_project", {"_raw": True, "path": "parity_smoke"}, "putty.exe"),
        ("P15-013", "open_program", {"_raw": True, "path": "putty.exe"}, "putty.exe"),
        ("P15-014", "analysis_status", {"_raw": True}, "function_count"),
        ("P15-015", "switch_program", {"_raw": True, "program": "putty_b.exe"}, "putty_b.exe"),
        ("P15-016", "list_open_programs", {"_raw": True}, "putty_b.exe"),
        ("P15-017", "close_program", {"_raw": True}, "putty.exe"),
        ("P15-018", "save_program", {"_raw": True}, "saved"),
        ("P15-019", "save_all_programs", {"_raw": True}, "saved"),
        ("P15-020", "close_project", {"_raw": True}, "parity_smoke"),
        ("P15-021", "run_ghidra_script", {"script_name": "HelloWorldScript.java"}, "Hello"),
        ("P15-022", "delete_project", {"_raw": True, "project_name": "mcp_smoke_restored", "confirm": True}),
        ("P15-023", "delete_project", {"_raw": True, "project_name": "mcp_smoke_proj", "confirm": True}),
        ("P15-024", "exit_ghidra", {"_raw": True}, "success"),
    ]),
}

# ---------------------------------------------------------------------------
# Environment-gated phases
# ---------------------------------------------------------------------------

# Phase 16 needs the GUI bridge: KAWAIIDRA_GUI_MODE=true and a ghidra_bridge
# server running inside Ghidra (GUI, or headless for the non-debugger tools).
if os.environ.get("KAWAIIDRA_GUI_MODE", "").lower() in ("1", "true", "yes"):
    _live_debugger = bool(os.environ.get("KAWAIIDRA_SMOKE_DEBUGGER"))
    PARITY_TESTS[16] = ("GUI Bridge & Debugger", [
        ("P16-001", "get_ui_cursor", {"_raw": True}, "program"),
        ("P16-002", "get_ui_cursor", {"_raw": True, "type": "address"}, "address"),
        ("P16-003", "goto_address", {"_raw": True, "address": "entry"}, "1400be504"),
        ("P16-004", "prompt_policy", {"_raw": True, "action": "enable", "reason": "smoke"}, "true"),
        ("P16-005", "prompt_policy", {"_raw": True, "action": "disable"}, "false"),
        ("P16-006", "debugger_status", {"_raw": True}, "available"),
    ] + ([
        ("P16-010", "debugger_launch_offers", {"_raw": True}, "offers"),
        ("P16-011", "debugger_launch", {"_raw": True}, "trace"),
        ("P16-012", "debugger_traces", {"_raw": True}, "current"),
        ("P16-013", "debugger_modules", {"_raw": True}, "putty"),
        ("P16-014", "debugger_registers", {"_raw": True}, "registers"),
        ("P16-015", "debugger_static_to_dynamic", {"_raw": True, "address": ENTRY}, "dynamic"),
        ("P16-016", "debugger_set_breakpoint", {"_raw": True, "address": ENTRY, "static": True}, "success"),
        ("P16-017", "debugger_list_breakpoints", {"_raw": True}, "breakpoints"),
        ("P16-018", "debugger_resume", {"_raw": True}, "success"),
        ("P16-019", "debugger_interrupt", {"_raw": True}, "success"),
        ("P16-020", "debugger_stack_trace", {"_raw": True}, "frames"),
        ("P16-021", "debugger_step", {"_raw": True, "kind": "into"}, "pc"),
        ("P16-022", "debugger_read_memory", {"_raw": True, "address": ENTRY, "size": 16}, "hex"),
        ("P16-023", "debugger_dynamic_to_static", {"_raw": True, "address": ENTRY}, "static"),
        ("P16-024", "debugger_remove_breakpoint", {"_raw": True, "address": ENTRY, "static": True}, "removed"),
        ("P16-025", "running_tools", {"_raw": True}, "tools"),
    ] if _live_debugger else []))

# Phase 17 needs a Ghidra Server, e.g. a throwaway local one:
#   KAWAIIDRA_SMOKE_GHIDRA_SERVER=127.0.0.1:13100
#   KAWAIIDRA_SMOKE_GHIDRA_USER=<user>  KAWAIIDRA_SMOKE_GHIDRA_PASSWORD=<password>
# (server started with -a0 -u so the client may supply the user name)
if os.environ.get("KAWAIIDRA_SMOKE_GHIDRA_SERVER"):
    _host, _, _port = os.environ["KAWAIIDRA_SMOKE_GHIDRA_SERVER"].partition(":")
    _repo, _proj = "mcp_smoke_repo", "mcp_smoke_vcs"
    PARITY_TESTS[17] = ("Ghidra Server & Version Control", [
        ("P17-001", "server_authenticate", {"_raw": True, "username": os.environ.get("KAWAIIDRA_SMOKE_GHIDRA_USER", ""),
                                            "password": os.environ.get("KAWAIIDRA_SMOKE_GHIDRA_PASSWORD", "")}, "success"),
        ("P17-002", "server_connect", {"_raw": True, "host": _host, "port": int(_port or 13100)}, '"connected": true'),
        ("P17-003", "server_status", {"_raw": True}, "repository_count"),
        ("P17-004", "server_repository_create", {"_raw": True, "name": _repo}, _repo),
        ("P17-005", "server_repositories", {"_raw": True}, _repo),
        ("P17-006", "server_admin_users", {"_raw": True}, "users"),
        ("P17-007", "create_project", {"_raw": True, "name": _proj}, _proj),
        ("P17-008", "export_program", {"program_name": "putty_b.exe", "output_name": "vcs_smoke.gzf"}, ".gzf"),
        ("P17-009", "import_program", {"_raw": True, "project_name": _proj, "gzf_path": str(EXPORTS / "vcs_smoke.gzf"),
                                       "target_name": "putty.exe"}, "/putty.exe"),
        ("P17-010", "server_share_project", {"_raw": True, "project_name": _proj, "repo": _repo}, _repo),
        ("P17-011", "server_version_control_add", {"_raw": True, "project_name": _proj, "path": "putty.exe",
                                                   "comment": "initial import"}, '"version": 1'),
        ("P17-012", "server_repository_files", {"_raw": True, "repo": _repo}, "/putty.exe"),
        ("P17-013", "server_version_control_checkout", {"_raw": True, "project_name": _proj, "path": "putty.exe"},
         '"checked_out": true'),
        ("P17-014", "set_program_option", {"project_name": _proj, "binary_name": "putty.exe", "group": "MCP VCS",
                                           "name": "note", "value": "edited", "type": "string"}, "edited"),
        ("P17-015", "checkin_program", {"_raw": True, "project_name": _proj, "path": "putty.exe", "dry_run": True},
         '"modified_since_checkout": true'),
        ("P17-016", "checkin_program", {"_raw": True, "project_name": _proj, "path": "putty.exe",
                                        "comment": "edit", "keep_checked_out": True}, '"new_version": 2'),
        ("P17-017", "server_version_history", {"_raw": True, "project_name": _proj, "path": "putty.exe"}, "initial import"),
        ("P17-018", "server_repository_file", {"_raw": True, "repo": _repo, "path": "/putty.exe"}, "checkouts"),
        ("P17-019", "server_checkouts", {"_raw": True, "repo": _repo}, "checkout_id"),
        ("P17-020", "server_version_control_undo_checkout", {"_raw": True, "project_name": _proj, "path": "putty.exe"},
         '"checked_out": false'),
        ("P17-021", "server_version_control_checkout", {"_raw": True, "project_name": _proj, "path": "putty.exe"},
         '"checked_out": true'),
        ("P17-022", "server_admin_terminate_all_checkouts", {"_raw": True, "repo": _repo}, '"count": 1'),
        ("P17-023", "server_admin_set_permissions", {"_raw": True, "repo": _repo,
                                                     "user": os.environ.get("KAWAIIDRA_SMOKE_GHIDRA_USER", ""),
                                                     "access_level": "admin"}, "success"),
        ("P17-024", "server_disconnect", {"_raw": True}, '"connected": false'),
        ("P17-025", "delete_project", {"_raw": True, "project_name": _proj, "confirm": True}),
    ])
