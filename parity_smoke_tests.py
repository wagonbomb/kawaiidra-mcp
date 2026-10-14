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

# Phase 18: one asserted test for every competitor endpoint whose kawaiidra
# equivalent is a core (pre-parity) tool, so each endpoint has direct evidence.
# Comments name the bethington endpoint covered.
PARITY_TESTS[18] = ("Endpoint Coverage (core-tool equivalents)", [
    # program / listing
    ("P18-001", "get_binary_info", {}, "x86"),                                          # get_metadata
    ("P18-002", "get_entry_points", {}, "1400be504"),                                   # get_entry_points
    ("P18-003", "get_function_count", {}, "unction"),                                   # get_function_count
    ("P18-004", "find_functions", {"pattern": "McpParse"}, "McpParseBuffer"),          # find_functions
    ("P18-005", "list_strings", {"min_length": 6, "limit": 10}, "SSH-2 private key"),   # list_strings
    ("P18-006", "search_strings", {"pattern": "PuTTY"}, "PuTTY"),                       # search_strings
    ("P18-007", "read_memory", {"address": ENTRY, "length": 16}, "48 83 EC 28"),        # read_memory
    ("P18-008", "search_bytes", {"pattern": "48 83 EC 28 E8", "limit": 200}, "1400be504"),  # search_byte_patterns
    ("P18-009", "list_projects", {"_raw": True}, "parity_smoke"),                       # list_projects
    ("P18-010", "list_scripts", {"_raw": True}),                                        # list_scripts
    # analysis
    ("P18-011", "list_analyzers", {}, "Decompiler Parameter ID"),                       # list_analyzers
    ("P18-012", "run_analysis", {}),                                                    # run_analysis / reanalyze
    ("P18-013", "get_control_flow_graph", {"function_name": "entry"}, "1400be504"),     # analyze_control_flow
    ("P18-014", "get_call_graph", {"function_name": "entry", "depth": 2},
     "__scrt_common_main_seh"),                                                         # get_function_call_graph
    ("P18-015", "get_xrefs_from", {"address": ENTRY}, "1400"),                          # get_xrefs_from
    ("P18-016", "find_similar_functions", {"function_name": "FUN_140006220", "threshold": 0.5}),  # find_similar_functions
    ("P18-017", "find_dead_code", {"limit": 5}),                                        # find_dead_code
    ("P18-018", "diff_functions", {"function_a": "FUN_140006220", "function_b": "FUN_140006260"},
     "FUN_140006260"),                                                                  # diff_functions
    ("P18-019", "get_function_disassembly", {"function_name": "entry"}, "SUB RSP"),     # disassemble_function
    ("P18-020", "disassemble_bytes", {"address": ENTRY, "count": 3}, "SUB"),            # disassemble_bytes
    # functions
    ("P18-021", "rename_function", {"old_name": "FUN_1400062f0", "new_name": "McpRenamed"}, "McpRenamed"),  # rename_function
    ("P18-022", "set_function_prototype", {"function_name": "McpRenamed",
                                           "prototype": "int McpRenamed(void *ctx, int n)"}, "McpRenamed"),  # set_function_prototype
    ("P18-023", "get_functions", {"function": "McpRenamed", "fields": "signature,variables"}, "ctx"),
    ("P18-024", "set_function_no_return", {"function_name": "FUN_140007550", "no_return": True}),  # set_function_no_return
    ("P18-025", "get_functions", {"function": "0x140007550", "fields": "signature"}, '"no_return": true'),
    ("P18-026", "delete_function", {"address_or_name": "0x140007550"}),                 # delete_function
    ("P18-027", "get_functions", {"functions": "0x140007550"}, "Function not found"),
    ("P18-028", "create_function", {"address": "0x140007550", "name": "McpTmpFn"}),
    ("P18-029", "run_script", {"code": "print('MCP_INLINE_OK %d' % currentProgram.getFunctionManager().getFunctionCount())"},
     "MCP_INLINE_OK"),                                                                  # run_script_inline
    # labels, comments, bookmarks
    ("P18-030", "create_label", {"address": "0x140132030", "name": "g_mcpCoverLabel"}),  # create_label
    ("P18-031", "rename_symbol", {"target": "g_mcpCoverLabel", "new_name": "g_mcpCoverLabel2"}, "g_mcpCoverLabel2"),
    ("P18-032", "can_rename_at_address", {"address": "0x140132030"}, "g_mcpCoverLabel2"),
    ("P18-033", "delete_label", {"address": "0x140132030", "name": "g_mcpCoverLabel2"}),  # delete_label
    ("P18-034", "batch_set_comments", {"comments": [
        {"address": "0x1400be504", "comment": "mcp batch eol", "comment_type": "EOL"},
        {"address": "0x1400be508", "comment": "mcp batch pre", "comment_type": "PRE"}]}),  # batch_set_comments
    ("P18-035", "get_comment", {"addresses": "0x1400be504,0x1400be508", "only_with_comments": True},
     ["mcp batch eol", "mcp batch pre"]),
    ("P18-036", "clear_comments", {"function_name": "entry"}),                           # clear_function_comments
    ("P18-037", "get_comment", {"addresses": "0x1400be504,0x1400be508", "only_with_comments": True}, '"count": 0'),
    ("P18-038", "set_bookmark", {"address": "0x1400be504", "category": "mcp_cover", "comment": "c"}),
    ("P18-039", "list_bookmarks", {"category": "mcp_cover"}, "mcp_cover"),               # list_bookmarks
    ("P18-040", "delete_bookmark", {"address": "entry", "category": "mcp_cover"}),
    # data types
    ("P18-041", "create_struct", {"name": "McpCoverS", "fields": [{"name": "a", "type": "int"},
                                                                   {"name": "b", "type": "short"}]}),  # create_struct
    ("P18-042", "add_struct_field", {"struct_name": "McpCoverS", "field_name": "c", "field_type": "char *"}),  # add_struct_field
    ("P18-043", "modify_struct_field", {"struct_name": "McpCoverS", "field_index": 1, "new_name": "b2"}),  # modify_struct_field
    ("P18-044", "remove_struct_field", {"struct_name": "McpCoverS", "field_index": 0}),  # remove_struct_field
    ("P18-045", "get_data_type_details", {"type_name": "McpCoverS"}, ["b2", "char *"]),  # get_struct_layout / get_type_size
    ("P18-046", "create_enum", {"name": "McpCoverE", "values": {"MC_A": 1, "MC_B": 7}}),  # create_enum
    ("P18-047", "get_data_type_details", {"type_name": "McpCoverE"}, ["MC_A", "MC_B"]),  # get_enum_values
    ("P18-048", "apply_data_type", {"address": "0x140132040", "type_name": "McpCoverS"}),  # apply_data_type
    ("P18-049", "audit_global", {"address": "0x140132040"}, "McpCoverS"),
    ("P18-050", "list_data_types", {"filter": "McpCover"}, "McpCoverE"),                 # find_data_types
    ("P18-051", "delete_data_type", {"type_name": "McpCoverE"}),                         # delete_data_type
    ("P18-052", "get_valid_data_types", {"filter": "McpCoverE"}, '"total": 0'),
    # malware / security (bethington "malware" category)
    ("P18-053", "detect_malware_behaviors", {}),                                         # detect_malware_behaviors
    ("P18-054", "find_anti_analysis", {}),                                               # find_anti_analysis_techniques
    ("P18-055", "extract_iocs", {}),                                                     # extract_iocs_with_context
    ("P18-056", "analyze_api_chains", {}),                                               # analyze_api_call_chains
    ("P18-057", "find_crypto_constants", {}),                                            # detect_crypto_constants
])

# ---------------------------------------------------------------------------
# Environment-gated phases
# ---------------------------------------------------------------------------

# Phase 16 needs the GUI bridge: KAWAIIDRA_GUI_MODE=true and a ghidra_bridge
# server running inside Ghidra (GUI, or headless for the non-debugger tools).
# The live-debugger subset (KAWAIIDRA_SMOKE_DEBUGGER=1) expects the GUI's
# Debugger tool to have the target program open and a working dbgeng agent:
#   KAWAIIDRA_SMOKE_DEBUGGER_PYTHON  python with ghidradbg/ghidratrace/pybag
#   KAWAIIDRA_SMOKE_DEBUGGER_ENTRY   static entry of that program (default
#                                    0x140001300 = Windows PING.EXE)
#   KAWAIIDRA_SMOKE_DEBUGGER_ARGS    target arguments (default ping -n 120)
if os.environ.get("KAWAIIDRA_GUI_MODE", "").lower() in ("1", "true", "yes"):
    _live_debugger = bool(os.environ.get("KAWAIIDRA_SMOKE_DEBUGGER"))
    _dbg_entry = os.environ.get("KAWAIIDRA_SMOKE_DEBUGGER_ENTRY", "0x140001300")
    _launch = {"_raw": True, "args": os.environ.get("KAWAIIDRA_SMOKE_DEBUGGER_ARGS", "-n 120 127.0.0.1"),
               "windbg_dir": os.environ.get("WINDBG_DIR", "C:/Windows/System32")}
    if os.environ.get("KAWAIIDRA_SMOKE_DEBUGGER_PYTHON"):
        _launch["python_executable"] = os.environ["KAWAIIDRA_SMOKE_DEBUGGER_PYTHON"]
    PARITY_TESTS[16] = ("GUI Bridge & Debugger", [
        ("P16-001", "get_ui_cursor", {"_raw": True}, "program"),
        ("P16-002", "get_ui_cursor", {"_raw": True, "type": "address"}, "address"),
        ("P16-003", "goto_address", {"_raw": True, "address": "entry"}, '"address"'),
        ("P16-004", "prompt_policy", {"_raw": True, "action": "enable", "reason": "smoke"}, "true"),
        ("P16-005", "prompt_policy", {"_raw": True, "action": "disable"}, "false"),
        ("P16-006", "debugger_status", {"_raw": True}, "available"),
    ] + ([
        ("P16-010", "running_tools", {"_raw": True}, "Debugger"),
        ("P16-011", "debugger_launch_offers", {"_raw": True}, "local-dbgeng.bat"),
        ("P16-012", "debugger_launch", _launch, '"ready": true'),
        ("P16-013", "debugger_traces", {"_raw": True}, '"current": true'),
        ("P16-014", "debugger_status", {"_raw": True}, '"target_alive": true'),
        ("P16-015", "debugger_modules", {"_raw": True}, "ntdll"),
        ("P16-016", "debugger_registers", {"_raw": True, "registers": "RIP,RSP"}, "RIP"),
        ("P16-017", "debugger_static_to_dynamic", {"_raw": True, "address": _dbg_entry}, "dynamic"),
        ("P16-018", "debugger_set_breakpoint", {"_raw": True, "address": _dbg_entry, "static": True}, "success"),
        ("P16-019", "debugger_list_breakpoints", {"_raw": True}, "SW_EXECUTE"),
        ("P16-020", "debugger_resume", {"_raw": True, "wait_seconds": 15}, '"stopped": true'),
        ("P16-021", "debugger_stack_trace", {"_raw": True, "depth": 5}, '"function": "entry"'),
        ("P16-022", "debugger_registers", {"_raw": True, "registers": "RIP"}, "RIP"),
        ("P16-023", "debugger_read_memory", {"_raw": True, "address": "RIP", "size": 16}, "hex"),
        ("P16-023b", "debugger_dynamic_to_static", {"_raw": True, "address": "RIP"}, _dbg_entry[2:].lower()),
        ("P16-024", "debugger_step", {"_raw": True, "kind": "into"}, "Step Into"),
        ("P16-025", "debugger_step", {"_raw": True, "kind": "over"}, "Step Over"),
        ("P16-026", "debugger_remove_breakpoint", {"_raw": True, "address": _dbg_entry, "static": True}, '"removed": 1'),
        ("P16-027", "debugger_resume", {"_raw": True}, "Go"),
        ("P16-028", "debugger_interrupt", {"_raw": True}, '"process_state": "STOPPED"'),
        ("P16-029", "debugger_status", {"_raw": True}, '"process_state": "STOPPED"'),
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
        ("P17-021b", "server_admin_terminate_checkout", {"_raw": True, "repo": _repo, "path": "/putty.exe"},
         '"terminated": ['),
        ("P17-021c", "import_program", {"_raw": True, "project_name": _proj, "gzf_path": str(EXPORTS / "vcs_smoke.gzf"),
                                        "target_name": "putty2.exe"}, "/putty2.exe"),
        ("P17-021d", "server_version_control_add", {"_raw": True, "project_name": _proj, "path": "putty2.exe",
                                                    "keep_checked_out": True}, '"checked_out": true'),
        ("P17-022", "server_admin_terminate_all_checkouts", {"_raw": True, "repo": _repo}, '"count": 1'),
        ("P17-023", "server_admin_set_permissions", {"_raw": True, "repo": _repo,
                                                     "user": os.environ.get("KAWAIIDRA_SMOKE_GHIDRA_USER", ""),
                                                     "access_level": "admin"}, "success"),
        ("P17-024", "server_disconnect", {"_raw": True}, '"connected": false'),
        ("P17-025", "delete_project", {"_raw": True, "project_name": _proj, "confirm": True}),
    ])
