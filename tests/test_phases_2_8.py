"""
Smoke and functional tests for Phases 2–8 tools.

Covers:
- Phase 2: Data Types & Structures (12 tools)
- Phase 3: Symbols, Labels & Bookmarks (8 tools)
- Phase 4: Batch Operations & Comment Types (6 tools)
- Phase 5: Function Analysis Extras (7 tools)
- Phase 6: Script Management & Analysis Control (6 tools)
- Phase 7: Security & Malware Analysis (4 tools)
- Phase 8: Project & Multi-Binary Management (5 tools)
"""

import pytest
import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# ============================================================================
# Tool Definition Smoke Tests — verify all 109 tools are registered
# ============================================================================

class TestToolCount:
    """Verify expected tool count after all phases."""

    def test_total_tool_count_is_109(self):
        from kawaiidra_mcp.server import TOOLS
        assert len(TOOLS) == 109, f"Expected 109 tools, got {len(TOOLS)}"


class TestPhaseToolsExist:
    """Verify each phase's tools are present by name."""

    def _tool_names(self):
        from kawaiidra_mcp.server import TOOLS
        return [t.name for t in TOOLS]

    # Phase 2
    @pytest.mark.parametrize("name", [
        "list_data_types", "get_data_type_details", "create_struct",
        "add_struct_field", "modify_struct_field", "remove_struct_field",
        "create_enum", "add_enum_value", "create_typedef",
        "apply_data_type", "delete_data_type", "get_function_variables",
    ])
    def test_phase2_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 3
    @pytest.mark.parametrize("name", [
        "create_label", "delete_label", "rename_label", "list_labels",
        "get_xrefs_to", "get_xrefs_from", "set_bookmark", "list_bookmarks",
    ])
    def test_phase3_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 4
    @pytest.mark.parametrize("name", [
        "batch_rename", "batch_set_comments", "set_plate_comment",
        "set_pre_comment", "batch_set_types", "clear_comments",
    ])
    def test_phase4_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 5
    @pytest.mark.parametrize("name", [
        "get_function_signature", "get_function_hash", "get_function_metrics",
        "disassemble_bytes", "find_dead_code", "diff_functions",
        "set_function_no_return",
    ])
    def test_phase5_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 6
    @pytest.mark.parametrize("name", [
        "list_scripts", "save_script", "get_script", "delete_script",
        "list_analyzers", "run_analysis",
    ])
    def test_phase6_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 7
    @pytest.mark.parametrize("name", [
        "detect_malware_behaviors", "find_anti_analysis",
        "extract_iocs", "analyze_api_chains",
    ])
    def test_phase7_tool_exists(self, name):
        assert name in self._tool_names()

    # Phase 8
    @pytest.mark.parametrize("name", [
        "list_projects", "delete_project", "list_project_binaries",
        "get_entry_points", "get_function_count",
    ])
    def test_phase8_tool_exists(self, name):
        assert name in self._tool_names()


class TestToolSchemaIntegrity:
    """Verify schemas for all new tools are valid."""

    def _get_tools_by_names(self, names):
        from kawaiidra_mcp.server import TOOLS
        return [t for t in TOOLS if t.name in names]

    ALL_NEW_TOOLS = [
        # Phase 2
        "list_data_types", "get_data_type_details", "create_struct",
        "add_struct_field", "modify_struct_field", "remove_struct_field",
        "create_enum", "add_enum_value", "create_typedef",
        "apply_data_type", "delete_data_type", "get_function_variables",
        # Phase 3
        "create_label", "delete_label", "rename_label", "list_labels",
        "get_xrefs_to", "get_xrefs_from", "set_bookmark", "list_bookmarks",
        # Phase 4
        "batch_rename", "batch_set_comments", "set_plate_comment",
        "set_pre_comment", "batch_set_types", "clear_comments",
        # Phase 5
        "get_function_signature", "get_function_hash", "get_function_metrics",
        "disassemble_bytes", "find_dead_code", "diff_functions",
        "set_function_no_return",
        # Phase 6
        "list_scripts", "save_script", "get_script", "delete_script",
        "list_analyzers", "run_analysis",
        # Phase 7
        "detect_malware_behaviors", "find_anti_analysis",
        "extract_iocs", "analyze_api_chains",
        # Phase 8
        "list_projects", "delete_project", "list_project_binaries",
        "get_entry_points", "get_function_count",
    ]

    def test_all_schemas_are_objects(self):
        tools = self._get_tools_by_names(self.ALL_NEW_TOOLS)
        for tool in tools:
            schema = tool.inputSchema
            assert isinstance(schema, dict), f"{tool.name}: schema not a dict"
            assert schema.get("type") == "object", f"{tool.name}: schema type != object"
            assert "properties" in schema, f"{tool.name}: missing properties"

    def test_required_fields_exist_in_properties(self):
        tools = self._get_tools_by_names(self.ALL_NEW_TOOLS)
        for tool in tools:
            schema = tool.inputSchema
            required = schema.get("required", [])
            properties = schema.get("properties", {})
            for field in required:
                assert field in properties, (
                    f"{tool.name}: required field '{field}' not in properties"
                )


# ============================================================================
# Dispatch Tests — verify handle_call_tool routes correctly
# ============================================================================

class TestDispatchPhase6:
    """Verify Phase 6 tools dispatch correctly."""

    @pytest.mark.asyncio
    async def test_dispatch_list_scripts(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_list_scripts") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("list_scripts", {})
            mock.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_dispatch_save_script(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_save_script") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("save_script", {"name": "test", "code": "x"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_get_script(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_get_script") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("get_script", {"name": "test"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_delete_script(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_delete_script") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("delete_script", {"name": "test"})
            mock.assert_called_once()


class TestDispatchPhase7:
    """Verify Phase 7 tools dispatch correctly."""

    @pytest.mark.asyncio
    async def test_dispatch_detect_malware_behaviors(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_detect_malware_behaviors", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("detect_malware_behaviors", {"binary_name": "x"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_find_anti_analysis(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_find_anti_analysis", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("find_anti_analysis", {"binary_name": "x"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_extract_iocs(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_extract_iocs", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("extract_iocs", {"binary_name": "x"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_analyze_api_chains(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_analyze_api_chains", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("analyze_api_chains", {"binary_name": "x"})
            mock.assert_called_once()


class TestDispatchPhase8:
    """Verify Phase 8 tools dispatch correctly."""

    @pytest.mark.asyncio
    async def test_dispatch_list_projects(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_list_projects") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("list_projects", {})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_delete_project(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_delete_project") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("delete_project", {"project_name": "x", "confirm": True})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_list_project_binaries(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_list_project_binaries") as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("list_project_binaries", {})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_get_entry_points(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_get_entry_points", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("get_entry_points", {"binary_name": "x"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_get_function_count(self):
        from kawaiidra_mcp.server import handle_call_tool
        with patch("kawaiidra_mcp.server.handle_get_function_count", new_callable=AsyncMock) as mock:
            mock.return_value = [MagicMock(type="text", text="ok")]
            await handle_call_tool("get_function_count", {"binary_name": "x"})
            mock.assert_called_once()


# ============================================================================
# Phase 6 Handler Unit Tests — Script CRUD (filesystem, no Ghidra needed)
# ============================================================================

class TestHandleListScripts:
    """Tests for list_scripts handler."""

    def test_returns_message_when_dir_missing(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        original = server_module.config
        monkeypatch.setattr(server_module.config, "user_scripts_dir", tmp_path / "nonexistent")
        try:
            result = server_module.handle_list_scripts({})
            assert "save_script" in result[0].text.lower() or "no" in result[0].text.lower()
        finally:
            monkeypatch.setattr(server_module, "config", original)

    def test_returns_message_when_empty(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_list_scripts({})
        assert "no" in result[0].text.lower() or "save_script" in result[0].text.lower()

    def test_lists_scripts(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        (scripts_dir / "my_script.py").write_text("# My script\nprint('hello')\n", encoding="utf-8")
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_list_scripts({})
        text = result[0].text
        assert "my_script.py" in text
        assert "1" in text  # count


class TestHandleSaveScript:
    """Tests for save_script handler."""

    def test_saves_script(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_save_script({"name": "my_tool", "code": "print('hi')"})
        assert "saved" in result[0].text.lower() or "my_tool" in result[0].text.lower()
        assert (scripts_dir / "my_tool.py").exists()
        assert (scripts_dir / "my_tool.py").read_text(encoding="utf-8") == "print('hi')"

    def test_auto_appends_py(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        server_module.handle_save_script({"name": "foo", "code": "x=1"})
        assert (scripts_dir / "foo.py").exists()

    def test_rejects_invalid_name(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_save_script({"name": "../../etc/passwd", "code": "x"})
        assert "error" in result[0].text.lower()

    def test_rejects_name_with_spaces(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_save_script({"name": "bad name", "code": "x"})
        assert "error" in result[0].text.lower()

    def test_rejects_empty_name(self):
        import kawaiidra_mcp.server as server_module
        result = server_module.handle_save_script({"name": "", "code": "x"})
        assert "error" in result[0].text.lower()

    def test_rejects_empty_code(self):
        import kawaiidra_mcp.server as server_module
        result = server_module.handle_save_script({"name": "test", "code": ""})
        assert "error" in result[0].text.lower()


class TestHandleGetScript:
    """Tests for get_script handler."""

    def test_gets_script(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        (scripts_dir / "my_script.py").write_text("print('hello')", encoding="utf-8")
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_get_script({"name": "my_script"})
        assert "print('hello')" in result[0].text

    def test_returns_error_for_missing_script(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_get_script({"name": "nonexistent"})
        assert "error" in result[0].text.lower() or "not found" in result[0].text.lower()


class TestHandleDeleteScript:
    """Tests for delete_script handler."""

    def test_deletes_script(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        (scripts_dir / "to_delete.py").write_text("x=1", encoding="utf-8")
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_delete_script({"name": "to_delete"})
        assert "deleted" in result[0].text.lower()
        assert not (scripts_dir / "to_delete.py").exists()

    def test_returns_error_for_missing_script(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        scripts_dir.mkdir()
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)
        result = server_module.handle_delete_script({"name": "nonexistent"})
        assert "error" in result[0].text.lower() or "not found" in result[0].text.lower()


class TestScriptCrudRoundTrip:
    """End-to-end test: save → list → get → delete → list."""

    def test_full_crud_lifecycle(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        scripts_dir = tmp_path / "user_scripts"
        monkeypatch.setattr(server_module.config, "user_scripts_dir", scripts_dir)

        # Save
        result = server_module.handle_save_script({"name": "lifecycle_test", "code": "# test\nx=42"})
        assert "saved" in result[0].text.lower() or "lifecycle_test" in result[0].text

        # List
        result = server_module.handle_list_scripts({})
        assert "lifecycle_test.py" in result[0].text

        # Get
        result = server_module.handle_get_script({"name": "lifecycle_test"})
        assert "x=42" in result[0].text

        # Delete
        result = server_module.handle_delete_script({"name": "lifecycle_test"})
        assert "deleted" in result[0].text.lower()

        # List again — should be empty
        result = server_module.handle_list_scripts({})
        assert "lifecycle_test.py" not in result[0].text


# ============================================================================
# Phase 6 Handler Tests — Ghidra-dependent (mocked)
# ============================================================================

class TestHandleListAnalyzers:
    """Tests for list_analyzers handler."""

    @pytest.mark.asyncio
    async def test_returns_analyzer_table(self):
        from kawaiidra_mcp.server import handle_list_analyzers

        mock_result = {
            "analyzers": [
                {"name": "ASCII Strings", "enabled": True},
                {"name": "Decompiler Parameter ID", "enabled": False},
            ],
            "count": 2,
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_list_analyzers({"binary_name": "test.exe"})
            text = result[0].text
            assert "ASCII Strings" in text
            assert "ON" in text
            assert "OFF" in text


class TestHandleRunAnalysis:
    """Tests for run_analysis handler."""

    @pytest.mark.asyncio
    async def test_success(self):
        from kawaiidra_mcp.server import handle_run_analysis

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.clear_cache") as mock_clear:
            mock_run.return_value = ("Analysis complete", "", 0)
            mock_clear.return_value = 3
            result = await handle_run_analysis({"binary_name": "test.exe"})
            text = result[0].text
            assert "completed" in text.lower() or "test.exe" in text
            mock_clear.assert_called_once()

    @pytest.mark.asyncio
    async def test_failure(self):
        from kawaiidra_mcp.server import handle_run_analysis

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.clear_cache"):
            mock_run.return_value = ("", "ERROR: something broke", 1)
            result = await handle_run_analysis({"binary_name": "test.exe"})
            assert "failed" in result[0].text.lower() or "error" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_with_analyzers(self):
        from kawaiidra_mcp.server import handle_run_analysis

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.clear_cache"):
            mock_run.return_value = ("done", "", 0)
            result = await handle_run_analysis({
                "binary_name": "test.exe",
                "analyzers": ["ASCII Strings", "Decompiler"]
            })
            # Verify -analyzer flags were passed
            call_args = mock_run.call_args[0][0]
            assert "-analyzer" in call_args
            assert "ASCII Strings" in call_args


# ============================================================================
# Phase 7 Handler Tests (mocked Ghidra)
# ============================================================================

class TestHandleDetectMalwareBehaviors:
    """Tests for detect_malware_behaviors handler."""

    @pytest.mark.asyncio
    async def test_returns_results(self):
        from kawaiidra_mcp.server import handle_detect_malware_behaviors

        mock_result = {
            "success": True,
            "results": {
                "c2": {"label": "C2 / Command & Control", "hits": [
                    {"function": "sub_401000", "entry": "0x401000",
                     "calls": [{"target": "InternetOpenA", "address": "0x401020"}]}
                ]},
                "injection": {"label": "Process Injection", "hits": []},
            }
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_detect_malware_behaviors({"binary_name": "mal.exe"})
            text = result[0].text
            assert "C2" in text
            assert "InternetOpenA" in text

    @pytest.mark.asyncio
    async def test_handles_error(self):
        from kawaiidra_mcp.server import handle_detect_malware_behaviors

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            mock_run.return_value = ("no markers", "", 0)
            result = await handle_detect_malware_behaviors({"binary_name": "test.exe"})
            assert "error" in result[0].text.lower()


class TestHandleFindAntiAnalysis:
    """Tests for find_anti_analysis handler."""

    @pytest.mark.asyncio
    async def test_returns_results(self):
        from kawaiidra_mcp.server import handle_find_anti_analysis

        mock_result = {
            "success": True,
            "results": {
                "anti_debug": {
                    "label": "Anti-Debugging",
                    "hits": {
                        "api_calls": [{"function": "check_dbg", "entry": "0x401000",
                                       "calls": [{"target": "IsDebuggerPresent", "address": "0x401010"}]}],
                        "string_refs": [{"string": "OllyDbg", "address": "0x500000", "match": "ollydbg"}]
                    }
                },
                "anti_vm": {"label": "Anti-VM", "hits": {"api_calls": [], "string_refs": []}},
                "anti_sandbox": {"label": "Anti-Sandbox", "hits": {"api_calls": [], "string_refs": []}},
                "anti_disassembly": {"label": "Anti-Disassembly", "hits": {"api_calls": [], "string_refs": []}},
            }
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_find_anti_analysis({"binary_name": "test.exe"})
            text = result[0].text
            assert "Anti-Debugging" in text
            assert "IsDebuggerPresent" in text
            assert "OllyDbg" in text


class TestHandleExtractIocs:
    """Tests for extract_iocs handler."""

    @pytest.mark.asyncio
    async def test_returns_iocs(self):
        from kawaiidra_mcp.server import handle_extract_iocs

        mock_result = {
            "success": True,
            "total": 3,
            "iocs": {
                "ip_addresses": [{"value": "192.168.1.100", "address": "0x500000", "context": "test"}],
                "urls": [{"value": "https://evil.com/c2", "address": "0x500100"}],
                "domains": [{"value": "evil.com", "address": "0x500200"}],
                "emails": [],
                "file_paths": [],
                "registry_keys": [],
            }
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_extract_iocs({"binary_name": "test.exe"})
            text = result[0].text
            assert "192.168.1.100" in text
            assert "evil.com" in text
            assert "3" in text  # total


class TestHandleAnalyzeApiChains:
    """Tests for analyze_api_chains handler."""

    @pytest.mark.asyncio
    async def test_returns_chains(self):
        from kawaiidra_mcp.server import handle_analyze_api_chains

        mock_result = {
            "success": True,
            "chains": [
                {
                    "chain": "Process Injection (Classic)",
                    "severity": "critical",
                    "function": "inject_proc",
                    "entry": "0x401000",
                    "matched_apis": [
                        {"api": "OpenProcess", "address": "0x401010"},
                        {"api": "VirtualAllocEx", "address": "0x401020"},
                        {"api": "WriteProcessMemory", "address": "0x401030"},
                    ]
                }
            ]
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_analyze_api_chains({"binary_name": "test.exe"})
            text = result[0].text
            assert "CRITICAL" in text
            assert "Process Injection" in text
            assert "OpenProcess" in text

    @pytest.mark.asyncio
    async def test_no_chains_found(self):
        from kawaiidra_mcp.server import handle_analyze_api_chains

        mock_result = {"success": True, "chains": []}

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_analyze_api_chains({"binary_name": "clean.exe"})
            assert "0" in result[0].text or "no" in result[0].text.lower()


# ============================================================================
# Phase 8 Handler Tests
# ============================================================================

class TestHandleListProjects:
    """Tests for list_projects handler."""

    def test_lists_projects(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module

        # Create mock project structure
        proj_dir = tmp_path / "projects"
        proj_dir.mkdir()
        p1 = proj_dir / "myproject"
        p1.mkdir()
        (p1 / "myproject.rep" / "idata").mkdir(parents=True)
        (p1 / "myproject.rep" / "idata" / "~index.dat").write_text(
            "VERSION=1\n/\n  00000000:test.exe:abc\nNEXT-ID:1\n"
        )

        monkeypatch.setattr(server_module.config, "project_dir", proj_dir)
        result = server_module.handle_list_projects({})
        text = result[0].text
        assert "myproject" in text
        assert "1" in text  # binary count

    def test_no_projects(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        proj_dir = tmp_path / "empty_projects"
        proj_dir.mkdir()
        monkeypatch.setattr(server_module.config, "project_dir", proj_dir)
        result = server_module.handle_list_projects({})
        assert "no" in result[0].text.lower()


class TestHandleDeleteProject:
    """Tests for delete_project handler."""

    def test_requires_confirm(self):
        import kawaiidra_mcp.server as server_module
        result = server_module.handle_delete_project({"project_name": "x", "confirm": False})
        assert "confirm" in result[0].text.lower()

    def test_requires_project_name(self):
        import kawaiidra_mcp.server as server_module
        result = server_module.handle_delete_project({"confirm": True})
        assert "error" in result[0].text.lower()

    def test_deletes_project(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module

        proj_dir = tmp_path / "to_delete"
        proj_dir.mkdir()
        (proj_dir / "to_delete.rep").mkdir()

        monkeypatch.setattr(server_module.config, "project_dir", tmp_path)
        with patch("kawaiidra_mcp.server.clear_cache"):
            result = server_module.handle_delete_project({"project_name": "to_delete", "confirm": True})
        assert "deleted" in result[0].text.lower()
        assert not proj_dir.exists()

    def test_error_for_missing_project(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        monkeypatch.setattr(server_module.config, "project_dir", tmp_path)
        result = server_module.handle_delete_project({"project_name": "ghost", "confirm": True})
        assert "error" in result[0].text.lower() or "not found" in result[0].text.lower()


class TestHandleListProjectBinaries:
    """Tests for list_project_binaries handler."""

    def test_lists_binaries(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module

        proj_dir = tmp_path / "default"
        (proj_dir / "default.rep" / "idata").mkdir(parents=True)
        (proj_dir / "default.rep" / "idata" / "~index.dat").write_text(
            "VERSION=1\n/\n  00000000:hello.exe:abc\n  00000001:world.dll:def\nNEXT-ID:2\n"
        )

        monkeypatch.setattr(server_module.config, "project_dir", tmp_path)
        result = server_module.handle_list_project_binaries({"project_name": "default"})
        text = result[0].text
        assert "hello.exe" in text
        assert "world.dll" in text

    def test_no_binaries(self, tmp_path, monkeypatch):
        import kawaiidra_mcp.server as server_module
        monkeypatch.setattr(server_module.config, "project_dir", tmp_path)
        result = server_module.handle_list_project_binaries({"project_name": "empty"})
        assert "no" in result[0].text.lower()


class TestHandleGetEntryPoints:
    """Tests for get_entry_points handler."""

    @pytest.mark.asyncio
    async def test_returns_entry_points(self):
        from kawaiidra_mcp.server import handle_get_entry_points

        mock_result = {
            "entry_points": [
                {"address": "0x401000", "name": "entry", "type": "entry"},
                {"address": "0x401100", "name": "_start", "type": "entry"},
            ],
            "format": "Portable Executable (PE)",
            "count": 2,
        }

        with patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_get_entry_points({"binary_name": "test.exe"})
            text = result[0].text
            assert "entry" in text.lower()
            assert "0x401000" in text


class TestHandleGetFunctionCount:
    """Tests for get_function_count handler."""

    @pytest.mark.asyncio
    async def test_returns_count_from_ghidra(self):
        from kawaiidra_mcp.server import handle_get_function_count

        mock_result = {"count": 42}

        with patch("kawaiidra_mcp.server.get_backend") as mock_backend, \
             patch("kawaiidra_mcp.server.run_ghidra_headless") as mock_run, \
             patch("kawaiidra_mcp.server.write_ghidra_script"):
            mock_backend.return_value = None  # no bridge
            stdout = f"=== MCP_RESULT_JSON ===\n{json.dumps(mock_result)}\n=== MCP_RESULT_END ==="
            mock_run.return_value = (stdout, "", 0)
            result = await handle_get_function_count({"binary_name": "test.exe"})
            assert "42" in result[0].text

    @pytest.mark.asyncio
    async def test_returns_count_from_backend(self):
        from kawaiidra_mcp.server import handle_get_function_count

        with patch("kawaiidra_mcp.server.get_backend") as mock_get_backend:
            mock_backend = MagicMock()
            mock_backend.list_functions.return_value = {
                "success": True,
                "functions": [{"name": "main"}],
                "total": 99,
            }
            mock_get_backend.return_value = mock_backend
            result = await handle_get_function_count({"binary_name": "test.exe"})
            assert "99" in result[0].text


# ============================================================================
# Config Tests
# ============================================================================

class TestConfigUserScriptsDir:
    """Tests for user_scripts_dir config property."""

    def test_default_user_scripts_dir(self):
        from kawaiidra_mcp.config import config
        assert config.user_scripts_dir is not None
        assert "user_scripts" in str(config.user_scripts_dir)

    def test_env_var_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("KAWAIIDRA_USER_SCRIPTS_DIR", str(tmp_path / "custom"))
        from kawaiidra_mcp.config import Config
        cfg = Config()
        assert cfg.user_scripts_dir == tmp_path / "custom"

    def test_ensure_directories_creates_user_scripts(self, tmp_path, monkeypatch):
        from kawaiidra_mcp.config import config
        custom_dir = tmp_path / "new_user_scripts"
        monkeypatch.setattr(config, "user_scripts_dir", custom_dir)
        # Also need to set other dirs to temp to avoid side effects
        monkeypatch.setattr(config, "project_dir", tmp_path / "p")
        monkeypatch.setattr(config, "binaries_dir", tmp_path / "b")
        monkeypatch.setattr(config, "exports_dir", tmp_path / "e")
        monkeypatch.setattr(config, "log_dir", tmp_path / "l")
        config.ensure_directories()
        assert custom_dir.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
