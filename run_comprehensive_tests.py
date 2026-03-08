#!/usr/bin/env python3
"""
Comprehensive Test Runner for Kawaiidra MCP

Runs all 87 tools with real binaries and reports results.
"""

import sys
import os
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
from dataclasses import dataclass, field

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set Ghidra path if not set
if not os.environ.get("GHIDRA_INSTALL_DIR"):
    # Try common Windows paths
    for path in ["C:/ghidra", "C:/ghidra_11.2_PUBLIC", "C:/ghidra_11.3_PUBLIC"]:
        if Path(path).exists():
            os.environ["GHIDRA_INSTALL_DIR"] = path
            break


@dataclass
class TestResult:
    """Result of a single test."""
    test_id: str
    tool_name: str
    success: bool
    duration: float
    output_preview: str = ""
    error: str = ""


@dataclass
class TestSuite:
    """Collection of test results."""
    name: str
    results: List[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.success)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.success)

    @property
    def total(self) -> int:
        return len(self.results)


class KawaiidraTestRunner:
    """Test runner for Kawaiidra MCP tools."""

    def __init__(self):
        self.suites: List[TestSuite] = []
        self.analyzed_binaries: set = set()

        # Import after setting GHIDRA_INSTALL_DIR
        from kawaiidra_mcp.server import TOOLS
        from kawaiidra_mcp.config import config

        self.config = config
        self.tools = {t.name: t for t in TOOLS}

        print(f"Kawaiidra Test Runner")
        print(f"=" * 50)
        print(f"Ghidra: {config.ghidra_home}")
        print(f"Tools available: {len(TOOLS)}")
        print(f"=" * 50)
        print()

    def run_tool(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str, str]:
        """Run a tool and return (success, output_preview, error)."""
        try:
            # Import handlers dynamically
            import kawaiidra_mcp.server as server
            import asyncio

            # Get the handler
            handler_name = f"handle_{tool_name}"

            # Map tool names to handler names
            handler_map = {
                "analyze_binary": "handle_analyze_binary",
                "list_analyzed_binaries": "handle_list_analyzed_binaries",
                "list_functions": "handle_list_functions",
                "find_functions": "handle_find_functions",
                "get_function_decompile": "handle_get_function_decompile",
                "get_function_disassembly": "handle_get_function_disassembly",
                "get_function_xrefs": "handle_get_function_xrefs",
                "search_strings": "handle_search_strings",
                "list_strings": "handle_list_strings",
                "get_binary_info": "handle_get_binary_info",
                "get_memory_map": "handle_get_memory_map",
                "export_analysis": "handle_export_analysis",
                "get_call_graph": "handle_get_call_graph",
                "detect_libraries": "handle_detect_libraries",
                "semantic_code_search": "handle_semantic_code_search",
                "get_function_with_context": "handle_get_function_with_context",
                "get_data_structures": "handle_get_data_structures",
                "get_control_flow_graph": "handle_get_control_flow_graph",
                "detect_vulnerabilities": "handle_detect_vulnerabilities",
                "find_similar_functions": "handle_find_similar_functions",
                "get_annotated_disassembly": "handle_get_annotated_disassembly",
                "suggest_symbol_names": "handle_suggest_symbol_names",
                "detect_kpp_ktrr": "handle_detect_kpp_ktrr",
                "analyze_mach_traps": "handle_analyze_mach_traps",
                "find_pac_gadgets": "handle_find_pac_gadgets",
                "analyze_sandbox_ops": "handle_analyze_sandbox_ops",
                "find_iokit_classes": "handle_find_iokit_classes",
                "detect_entitlement_checks": "handle_detect_entitlement_checks",
                "find_kernel_symbols": "handle_find_kernel_symbols",
                "analyze_mach_ports": "handle_analyze_mach_ports",
                "list_exports": "handle_list_exports",
                "list_imports": "handle_list_imports",
                "list_data_items": "handle_list_data_items",
                "list_namespaces": "handle_list_namespaces",
                "rename_function": "handle_rename_function",
                "rename_data": "handle_rename_data",
                "rename_variable": "handle_rename_variable",
                "set_comment": "handle_set_comment",
                "set_function_prototype": "handle_set_function_prototype",
                "set_local_variable_type": "handle_set_local_variable_type",
                "generate_report": "handle_generate_report",
                "cache_stats": "handle_cache_stats",
                "cache_clear": "handle_cache_clear",
                "bridge_status": "handle_bridge_status",
                "find_crypto_constants": "handle_find_crypto_constants",
                "analyze_jni_methods": "handle_analyze_jni_methods",
                "extract_api_endpoints": "handle_extract_api_endpoints",
                "find_hardcoded_secrets": "handle_find_hardcoded_secrets",
                "compare_binaries": "handle_compare_binaries",
                "get_current_address": "handle_get_current_address",
                "get_current_function": "handle_get_current_function",
                "set_current_address": "handle_set_current_address",
                "set_current_function": "handle_set_current_function",
                "get_current_selection": "handle_get_current_selection",
                "gui_status": "handle_gui_status",
                # Phase 1: Batch / Low-level / Script Tools
                "batch_decompile": "handle_batch_decompile",
                "read_memory": "handle_read_memory",
                "search_bytes": "handle_search_bytes",
                "create_function": "handle_create_function",
                "delete_function": "handle_delete_function",
                "run_script": "handle_run_script",
                # Phase 2: Data Types & Structures
                "list_data_types": "handle_list_data_types",
                "get_data_type_details": "handle_get_data_type_details",
                "create_struct": "handle_create_struct",
                "add_struct_field": "handle_add_struct_field",
                "modify_struct_field": "handle_modify_struct_field",
                "remove_struct_field": "handle_remove_struct_field",
                "create_enum": "handle_create_enum",
                "add_enum_value": "handle_add_enum_value",
                "create_typedef": "handle_create_typedef",
                "apply_data_type": "handle_apply_data_type",
                "delete_data_type": "handle_delete_data_type",
                "get_function_variables": "handle_get_function_variables",
                # Phase 3: Symbols, Labels & Bookmarks
                "create_label": "handle_create_label",
                "delete_label": "handle_delete_label",
                "rename_label": "handle_rename_label",
                "list_labels": "handle_list_labels",
                "get_xrefs_to": "handle_get_xrefs_to",
                "get_xrefs_from": "handle_get_xrefs_from",
                "set_bookmark": "handle_set_bookmark",
                "list_bookmarks": "handle_list_bookmarks",
                # Phase 4: Batch Operations & Comment Types
                "batch_rename": "handle_batch_rename",
                "batch_set_comments": "handle_batch_set_comments",
                "set_plate_comment": "handle_set_plate_comment",
                "set_pre_comment": "handle_set_pre_comment",
                "batch_set_types": "handle_batch_set_types",
                "clear_comments": "handle_clear_comments",
            }

            handler_name = handler_map.get(tool_name)
            if not handler_name:
                return False, "", f"No handler mapping for {tool_name}"

            handler = getattr(server, handler_name, None)
            if not handler:
                return False, "", f"Handler {handler_name} not found"

            # Run the handler
            if asyncio.iscoroutinefunction(handler):
                result = asyncio.run(handler(args))
            else:
                result = handler(args)

            # Extract text from result
            if result and len(result) > 0:
                text = result[0].text if hasattr(result[0], 'text') else str(result[0])
                preview = text[:200] + "..." if len(text) > 200 else text

                # Check for error indicators
                if "Error" in text and "error" in text.lower()[:50]:
                    return False, preview, "Tool returned error"

                return True, preview, ""

            return False, "", "No result returned"

        except Exception as e:
            return False, "", str(e)

    def run_test(self, test_id: str, tool_name: str, args: Dict[str, Any],
                 description: str = "") -> TestResult:
        """Run a single test and return result."""
        print(f"  [{test_id}] {tool_name}...", end=" ", flush=True)

        start = time.time()
        success, output, error = self.run_tool(tool_name, args)
        duration = time.time() - start

        result = TestResult(
            test_id=test_id,
            tool_name=tool_name,
            success=success,
            duration=duration,
            output_preview=output,
            error=error
        )

        status = "PASS" if success else "FAIL"
        print(f"{status} ({duration:.2f}s)")

        if not success and error:
            print(f"      Error: {error[:100]}")

        return result

    def ensure_binary_analyzed(self, binary_name: str, file_path: str = None):
        """Ensure a binary is analyzed before testing."""
        if binary_name in self.analyzed_binaries:
            return True

        print(f"\n  Analyzing {binary_name}...")
        path = file_path or binary_name
        success, _, error = self.run_tool("analyze_binary", {"file_path": path})

        if success:
            self.analyzed_binaries.add(binary_name)
            print(f"  Analysis complete for {binary_name}")
        else:
            print(f"  Failed to analyze {binary_name}: {error}")

        return success

    def run_phase1_core_tools(self) -> TestSuite:
        """Phase 1: Core Tools (Windows)."""
        suite = TestSuite("Phase 1: Core Tools")

        print("\n" + "=" * 50)
        print("PHASE 1: Core Tools")
        print("=" * 50)

        # Ensure test binary is analyzed
        if not self.ensure_binary_analyzed("putty.exe"):
            print("Cannot proceed without analyzed binary")
            return suite

        # Core tests
        tests = [
            ("CORE-002", "list_analyzed_binaries", {}),
            ("CORE-003", "list_functions", {"binary_name": "putty.exe", "limit": 20}),
            ("CORE-004", "find_functions", {"binary_name": "putty.exe", "pattern": "main"}),
            ("CORE-005", "get_function_decompile", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("CORE-006", "get_function_disassembly", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("CORE-007", "get_function_xrefs", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("CORE-008", "list_strings", {"binary_name": "putty.exe", "limit": 50}),
            ("CORE-009", "search_strings", {"binary_name": "putty.exe", "pattern": "error"}),
            ("CORE-010", "get_binary_info", {"binary_name": "putty.exe"}),
            ("CORE-011", "get_memory_map", {"binary_name": "putty.exe"}),
            ("CORE-012", "list_imports", {"binary_name": "putty.exe", "limit": 20}),
            ("CORE-013", "list_exports", {"binary_name": "putty.exe"}),
            ("CORE-014", "list_data_items", {"binary_name": "putty.exe", "limit": 20}),
            ("CORE-015", "list_namespaces", {"binary_name": "putty.exe"}),
            ("CORE-019", "export_analysis", {"binary_name": "putty.exe"}),
            ("CORE-021", "cache_stats", {}),
            ("CORE-022", "bridge_status", {}),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase2_advanced_tools(self) -> TestSuite:
        """Phase 2: Advanced LLM-Optimized Tools."""
        suite = TestSuite("Phase 2: Advanced Tools")

        print("\n" + "=" * 50)
        print("PHASE 2: Advanced LLM-Optimized Tools")
        print("=" * 50)

        tests = [
            ("ADV-001", "get_call_graph", {"binary_name": "putty.exe", "function_name": "entry", "depth": 2}),
            ("ADV-002", "detect_libraries", {"binary_name": "putty.exe"}),
            ("ADV-003", "semantic_code_search", {"binary_name": "putty.exe", "pattern": "file_io"}),
            ("ADV-004", "get_function_with_context", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("ADV-005", "get_data_structures", {"binary_name": "putty.exe"}),
            ("ADV-006", "get_control_flow_graph", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("ADV-007", "detect_vulnerabilities", {"binary_name": "putty.exe", "severity": "medium"}),
            ("ADV-008", "find_similar_functions", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("ADV-009", "get_annotated_disassembly", {"binary_name": "putty.exe", "function_name": "entry"}),
            ("ADV-010", "suggest_symbol_names", {"binary_name": "putty.exe", "function_name": "entry"}),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase3_android_tools(self) -> TestSuite:
        """Phase 3: Android/Mobile Tools."""
        suite = TestSuite("Phase 3: Android Tools")

        print("\n" + "=" * 50)
        print("PHASE 3: Android/Mobile Tools")
        print("=" * 50)

        # Analyze Android/mobile binaries
        # Uses open-source binaries:
        # - busybox: GPL-2.0 multi-call binary from busybox.net
        # - libcrypto: Apache-2.0 OpenSSL library
        self.ensure_binary_analyzed("busybox")
        self.ensure_binary_analyzed("libcrypto.so")

        tests = [
            ("ANDROID-001", "find_crypto_constants", {"binary_name": "libcrypto.so"}),
            ("ANDROID-002", "analyze_jni_methods", {"binary_name": "busybox"}),
            ("ANDROID-003", "extract_api_endpoints", {"binary_name": "busybox"}),
            ("ANDROID-004", "find_hardcoded_secrets", {"binary_name": "busybox"}),
            ("ANDROID-005", "compare_binaries", {"binary_name_a": "libcrypto.so", "binary_name_b": "busybox"}),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase4_gui_tools(self) -> TestSuite:
        """Phase 4: GUI/Context Tools."""
        suite = TestSuite("Phase 4: GUI/Context Tools")

        print("\n" + "=" * 50)
        print("PHASE 4: GUI/Context Tools")
        print("=" * 50)

        tests = [
            ("GUI-001", "gui_status", {}),
            ("GUI-002", "set_current_address", {"address": "0x401000"}),
            ("GUI-003", "get_current_address", {}),
            ("GUI-004", "set_current_function", {"function_name": "entry", "address": "0x401000"}),
            ("GUI-005", "get_current_function", {}),
            ("GUI-006", "get_current_selection", {}),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase5_new_batch_tools(self) -> TestSuite:
        """Phase 5: New Batch/Low-level/Script Tools (Tier 1 Phase 1)."""
        suite = TestSuite("Phase 5: Batch/Low-level/Script Tools")

        print("\n" + "=" * 50)
        print("PHASE 5: Batch/Low-level/Script Tools")
        print("=" * 50)

        tests = [
            # Batch decompile
            ("BATCH-001", "batch_decompile", {
                "binary_name": "putty.exe",
                "function_names": ["entry"]
            }),
            # Read memory at .text section start
            ("BATCH-002", "read_memory", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "length": 64
            }),
            # Search for MZ header bytes
            ("BATCH-003", "search_bytes", {
                "binary_name": "putty.exe",
                "pattern": "4D 5A",
                "limit": 5
            }),
            # Run a simple script
            ("BATCH-004", "run_script", {
                "binary_name": "putty.exe",
                "code": "print(currentProgram.getName())"
            }),
            # Decompile with pagination
            ("BATCH-005", "get_function_decompile", {
                "binary_name": "putty.exe",
                "function_name": "entry",
                "offset": 0,
                "limit": 10
            }),
            # Disassembly with pagination
            ("BATCH-006", "get_function_disassembly", {
                "binary_name": "putty.exe",
                "function_name": "entry",
                "offset": 0,
                "limit": 20
            }),
            # Create function, then delete it (use an address in .text)
            ("BATCH-007", "create_function", {
                "binary_name": "putty.exe",
                "address": "0x1400ec000",
                "name": "test_func_mcp"
            }),
            ("BATCH-008", "delete_function", {
                "binary_name": "putty.exe",
                "address_or_name": "test_func_mcp"
            }),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase6_data_type_tools(self) -> TestSuite:
        """Phase 6: Data Types & Structures Tools (Tier 1 Phase 2)."""
        suite = TestSuite("Phase 6: Data Types & Structures Tools")

        print("\n" + "=" * 50)
        print("PHASE 6: Data Types & Structures Tools")
        print("=" * 50)

        tests = [
            # List data types
            ("DTYPE-001", "list_data_types", {
                "binary_name": "putty.exe",
                "filter": "int",
                "limit": 20
            }),
            # Get function variables
            ("DTYPE-002", "get_function_variables", {
                "binary_name": "putty.exe",
                "function_name": "entry"
            }),
            # Create a struct
            ("DTYPE-003", "create_struct", {
                "binary_name": "putty.exe",
                "name": "TestMCPStruct",
                "fields": [
                    {"name": "id", "type": "int"},
                    {"name": "flags", "type": "byte"},
                ],
                "category": "/MCP_Test"
            }),
            # Get struct details
            ("DTYPE-004", "get_data_type_details", {
                "binary_name": "putty.exe",
                "type_name": "TestMCPStruct"
            }),
            # Add a field to the struct
            ("DTYPE-005", "add_struct_field", {
                "binary_name": "putty.exe",
                "struct_name": "TestMCPStruct",
                "field_name": "data",
                "field_type": "long",
                "comment": "Test field"
            }),
            # Modify a field in the struct
            ("DTYPE-006", "modify_struct_field", {
                "binary_name": "putty.exe",
                "struct_name": "TestMCPStruct",
                "field_index": 0,
                "new_name": "identifier",
                "new_comment": "Renamed from id"
            }),
            # Remove a field
            ("DTYPE-007", "remove_struct_field", {
                "binary_name": "putty.exe",
                "struct_name": "TestMCPStruct",
                "field_index": 2
            }),
            # Create an enum
            ("DTYPE-008", "create_enum", {
                "binary_name": "putty.exe",
                "name": "TestMCPEnum",
                "values": {"NONE": 0, "READ": 1, "WRITE": 2, "EXEC": 4},
                "size": 4,
                "category": "/MCP_Test"
            }),
            # Add enum value
            ("DTYPE-009", "add_enum_value", {
                "binary_name": "putty.exe",
                "enum_name": "TestMCPEnum",
                "value_name": "ALL",
                "value": 7
            }),
            # Create a typedef
            ("DTYPE-010", "create_typedef", {
                "binary_name": "putty.exe",
                "name": "MCPHandle",
                "base_type": "int",
                "category": "/MCP_Test"
            }),
            # Apply data type at an address (.rdata section)
            ("DTYPE-011", "apply_data_type", {
                "binary_name": "putty.exe",
                "address": "0x1400ed000",
                "type_name": "int"
            }),
            # Delete the test types (cleanup)
            ("DTYPE-012", "delete_data_type", {
                "binary_name": "putty.exe",
                "type_name": "TestMCPStruct"
            }),
            ("DTYPE-013", "delete_data_type", {
                "binary_name": "putty.exe",
                "type_name": "TestMCPEnum"
            }),
            ("DTYPE-014", "delete_data_type", {
                "binary_name": "putty.exe",
                "type_name": "MCPHandle"
            }),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase7_symbols_labels_bookmarks(self) -> TestSuite:
        """Phase 7: Symbols, Labels & Bookmarks (Roadmap Phase 3)."""
        suite = TestSuite("Phase 7: Symbols, Labels & Bookmarks")

        print("\n" + "=" * 50)
        print("PHASE 7: Symbols, Labels & Bookmarks")
        print("=" * 50)

        tests = [
            # Create a label at a known address (.text section)
            ("LABEL-001", "create_label", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "name": "mcp_test_label",
            }),
            # List labels to verify creation
            ("LABEL-002", "list_labels", {
                "binary_name": "putty.exe",
                "filter": "mcp_test",
                "limit": 20
            }),
            # Rename the label
            ("LABEL-003", "rename_label", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "new_name": "mcp_renamed_label",
            }),
            # Get xrefs TO the entry function address
            ("LABEL-004", "get_xrefs_to", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
            }),
            # Get xrefs FROM the entry point
            ("LABEL-005", "get_xrefs_from", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
            }),
            # Set a bookmark
            ("LABEL-006", "set_bookmark", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "category": "MCP_Test",
                "comment": "Test bookmark from MCP"
            }),
            # List bookmarks
            ("LABEL-007", "list_bookmarks", {
                "binary_name": "putty.exe",
                "category": "MCP_Test"
            }),
            # Delete the label (cleanup)
            ("LABEL-008", "delete_label", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "name": "mcp_renamed_label",
            }),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase8_batch_ops_comments(self) -> TestSuite:
        """Phase 8: Batch Operations & Comment Types (Roadmap Phase 4)."""
        suite = TestSuite("Phase 8: Batch Ops & Comment Types")

        print("\n" + "=" * 50)
        print("PHASE 8: Batch Operations & Comment Types")
        print("=" * 50)

        tests = [
            # Set a plate comment on entry function
            ("BATCHOP-001", "set_plate_comment", {
                "binary_name": "putty.exe",
                "function_name": "entry",
                "comment": "This is the entry point\nAnalyzed by MCP"
            }),
            # Set a pre-comment at .text start
            ("BATCHOP-002", "set_pre_comment", {
                "binary_name": "putty.exe",
                "address": "0x140001000",
                "comment": "Start of .text section"
            }),
            # Batch set comments at two addresses
            ("BATCHOP-003", "batch_set_comments", {
                "binary_name": "putty.exe",
                "comments": [
                    {"address": "0x140001000", "comment": "Batch comment 1", "comment_type": "EOL"},
                    {"address": "0x140001004", "comment": "Batch comment 2", "comment_type": "EOL"}
                ]
            }),
            # Clear all comments on entry
            ("BATCHOP-004", "clear_comments", {
                "binary_name": "putty.exe",
                "function_name": "entry"
            }),
            # Batch rename: create two labels first, then batch rename them
            ("BATCHOP-005", "create_label", {
                "binary_name": "putty.exe",
                "address": "0x140001010",
                "name": "mcp_batch_test_a"
            }),
            ("BATCHOP-006", "create_label", {
                "binary_name": "putty.exe",
                "address": "0x140001020",
                "name": "mcp_batch_test_b"
            }),
            ("BATCHOP-007", "batch_rename", {
                "binary_name": "putty.exe",
                "renames": [
                    {"old_name": "mcp_batch_test_a", "new_name": "mcp_renamed_a", "type": "label"},
                    {"old_name": "mcp_batch_test_b", "new_name": "mcp_renamed_b", "type": "label"}
                ]
            }),
            # Batch set types on entry function variables
            ("BATCHOP-008", "batch_set_types", {
                "binary_name": "putty.exe",
                "type_changes": [
                    {"function_name": "entry", "variable_name": "param_1", "new_type": "int"}
                ]
            }),
            # Cleanup: delete the test labels
            ("BATCHOP-009", "delete_label", {
                "binary_name": "putty.exe",
                "address": "0x140001010",
                "name": "mcp_renamed_a"
            }),
            ("BATCHOP-010", "delete_label", {
                "binary_name": "putty.exe",
                "address": "0x140001020",
                "name": "mcp_renamed_b"
            }),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def run_phase9_ios_tools(self) -> TestSuite:
        """Phase 9: iOS Security Tools (macOS only)."""
        suite = TestSuite("Phase 9: iOS Security Tools (macOS)")

        print("\n" + "=" * 50)
        print("PHASE 9: iOS Security Tools")
        print("=" * 50)

        # These will likely fail on Windows without iOS binaries
        # But we test that the handlers don't crash

        tests = [
            ("IOS-001", "detect_kpp_ktrr", {"binary_name": "putty.exe"}),
            ("IOS-002", "analyze_mach_traps", {"binary_name": "putty.exe"}),
            ("IOS-003", "find_pac_gadgets", {"binary_name": "putty.exe"}),
            ("IOS-004", "analyze_sandbox_ops", {"binary_name": "putty.exe"}),
            ("IOS-005", "find_iokit_classes", {"binary_name": "putty.exe"}),
            ("IOS-006", "detect_entitlement_checks", {"binary_name": "putty.exe"}),
            ("IOS-007", "find_kernel_symbols", {"binary_name": "putty.exe"}),
            ("IOS-008", "analyze_mach_ports", {"binary_name": "putty.exe"}),
        ]

        for test_id, tool, args in tests:
            result = self.run_test(test_id, tool, args)
            suite.results.append(result)

        return suite

    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)

        total_passed = 0
        total_failed = 0

        for suite in self.suites:
            print(f"\n{suite.name}:")
            print(f"  Passed: {suite.passed}/{suite.total}")
            if suite.failed > 0:
                print(f"  Failed: {suite.failed}")
                for r in suite.results:
                    if not r.success:
                        print(f"    - {r.test_id}: {r.tool_name} - {r.error[:50]}")
            total_passed += suite.passed
            total_failed += suite.failed

        print("\n" + "-" * 50)
        print(f"TOTAL: {total_passed}/{total_passed + total_failed} tests passed")

        if total_failed == 0:
            print("\n*** ALL TESTS PASSED ***")
        else:
            print(f"\n*** {total_failed} TESTS FAILED ***")

        return total_failed == 0

    def run_all(self, skip_ios: bool = True):
        """Run all test phases."""
        self.suites.append(self.run_phase1_core_tools())
        self.suites.append(self.run_phase2_advanced_tools())
        self.suites.append(self.run_phase3_android_tools())
        self.suites.append(self.run_phase4_gui_tools())
        self.suites.append(self.run_phase5_new_batch_tools())
        self.suites.append(self.run_phase6_data_type_tools())
        self.suites.append(self.run_phase7_symbols_labels_bookmarks())
        self.suites.append(self.run_phase8_batch_ops_comments())

        if not skip_ios:
            self.suites.append(self.run_phase9_ios_tools())
        else:
            print("\n" + "=" * 50)
            print("PHASE 9: iOS Security Tools - SKIPPED (use --ios flag)")
            print("=" * 50)

        return self.print_summary()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Kawaiidra MCP Comprehensive Test Runner")
    parser.add_argument("--ios", action="store_true", help="Include iOS security tools tests")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8, 9], help="Run specific phase only")
    args = parser.parse_args()

    runner = KawaiidraTestRunner()

    if args.phase:
        phase_methods = {
            1: runner.run_phase1_core_tools,
            2: runner.run_phase2_advanced_tools,
            3: runner.run_phase3_android_tools,
            4: runner.run_phase4_gui_tools,
            5: runner.run_phase5_new_batch_tools,
            6: runner.run_phase6_data_type_tools,
            7: runner.run_phase7_symbols_labels_bookmarks,
            8: runner.run_phase8_batch_ops_comments,
            9: runner.run_phase9_ios_tools,
        }

        # For phases 2+, ensure base binary is analyzed first
        if args.phase >= 2:
            runner.ensure_binary_analyzed("putty.exe")

        suite = phase_methods[args.phase]()
        runner.suites.append(suite)
        success = runner.print_summary()
    else:
        success = runner.run_all(skip_ios=not args.ios)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
