"""Smoke tests for the parity track, consumed by run_comprehensive_tests.py.

Each phase maps to (title, [(test_id, tool, args), ...]). Tests run in order
against putty.exe (MIT, PE x64) in the disposable ``parity_smoke`` project, so
create -> use -> clean up sequences are allowed. binary_name/project_name are
filled in by the runner.

Usage:
    python run_comprehensive_tests.py --parity          # all parity phases
    python run_comprehensive_tests.py --parity 10 11    # selected phases
"""

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
}
