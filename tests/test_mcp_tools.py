"""
Unit tests for MCP tool handlers.

These tests verify the MCP tool definitions and handlers work correctly.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestToolDefinitions:
    """Tests for MCP tool definitions."""

    def test_all_tools_have_required_fields(self):
        """All tools should have name, description, and inputSchema."""
        from kawaiidra_mcp.server import TOOLS

        for tool in TOOLS:
            assert hasattr(tool, "name"), f"Tool missing name"
            assert hasattr(tool, "description"), f"Tool {tool.name} missing description"
            assert hasattr(tool, "inputSchema"), f"Tool {tool.name} missing inputSchema"

    def test_tool_schemas_are_valid_json_schema(self):
        """All tool inputSchemas should be valid JSON Schema objects."""
        from kawaiidra_mcp.server import TOOLS

        for tool in TOOLS:
            schema = tool.inputSchema
            assert isinstance(schema, dict), f"Tool {tool.name} schema is not a dict"
            assert schema.get("type") == "object", f"Tool {tool.name} schema type should be 'object'"
            assert "properties" in schema, f"Tool {tool.name} schema missing 'properties'"

    def test_required_fields_exist_in_properties(self):
        """Required fields should exist in properties."""
        from kawaiidra_mcp.server import TOOLS

        for tool in TOOLS:
            schema = tool.inputSchema
            required = schema.get("required", [])
            properties = schema.get("properties", {})

            for field in required:
                assert field in properties, (
                    f"Tool {tool.name}: required field '{field}' not in properties"
                )

    def test_analyze_binary_tool_exists(self):
        """analyze_binary tool should be defined."""
        from kawaiidra_mcp.server import TOOLS

        tool_names = [t.name for t in TOOLS]
        assert "analyze_binary" in tool_names

    def test_list_functions_tool_exists(self):
        """list_functions tool should be defined."""
        from kawaiidra_mcp.server import TOOLS

        tool_names = [t.name for t in TOOLS]
        assert "list_functions" in tool_names

    def test_get_function_decompile_tool_exists(self):
        """get_function_decompile tool should be defined."""
        from kawaiidra_mcp.server import TOOLS

        tool_names = [t.name for t in TOOLS]
        assert "get_function_decompile" in tool_names


class TestToolParameterTypes:
    """Tests for correct parameter types in tool schemas."""

    def _get_tool(self, name):
        from kawaiidra_mcp.server import TOOLS
        for tool in TOOLS:
            if tool.name == name:
                return tool
        return None

    def test_binary_name_is_string(self):
        """binary_name parameter should be string type."""
        tool = self._get_tool("list_functions")
        assert tool is not None

        props = tool.inputSchema.get("properties", {})
        assert "binary_name" in props
        assert props["binary_name"].get("type") == "string"

    def test_limit_is_integer(self):
        """limit parameter should be integer type."""
        tool = self._get_tool("list_functions")
        assert tool is not None

        props = tool.inputSchema.get("properties", {})
        assert "limit" in props
        assert props["limit"].get("type") == "integer"

    def test_function_name_is_string(self):
        """function_name parameter should be string type."""
        tool = self._get_tool("get_function_decompile")
        assert tool is not None

        props = tool.inputSchema.get("properties", {})
        assert "function_name" in props
        assert props["function_name"].get("type") == "string"


class TestResolveBinaryPath:
    """Tests for resolve_binary_path function."""

    def test_resolves_absolute_path(self, tmp_path):
        """Should resolve absolute paths that exist."""
        from kawaiidra_mcp.server import resolve_binary_path

        # Create a test file
        test_file = tmp_path / "test_binary"
        test_file.write_text("test")

        result = resolve_binary_path(str(test_file))

        assert result == test_file

    def test_returns_none_for_nonexistent_absolute_path(self):
        """Should return None for nonexistent absolute paths."""
        from kawaiidra_mcp.server import resolve_binary_path

        result = resolve_binary_path("/nonexistent/path/to/binary")

        assert result is None

    def test_resolves_relative_to_binaries_dir(self, tmp_path, monkeypatch):
        """Should resolve paths relative to binaries directory."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import resolve_binary_path

        original_config = server_module.config

        # Create binaries dir with a test file
        binaries_dir = tmp_path / "binaries"
        binaries_dir.mkdir()
        test_file = binaries_dir / "test_binary"
        test_file.write_text("test")

        # Create mock config
        class MockConfig:
            pass
        mock_config = MockConfig()
        mock_config.binaries_dir = binaries_dir

        monkeypatch.setattr(server_module, "config", mock_config)

        try:
            result = resolve_binary_path("test_binary")
            assert result == test_file
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestWriteGhidraScript:
    """Tests for write_ghidra_script function."""

    def test_writes_script_to_scripts_dir(self, tmp_path, monkeypatch):
        """Should write script content to scripts directory."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import write_ghidra_script

        original_config = server_module.config

        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir()

        class MockConfig:
            pass
        mock_config = MockConfig()
        mock_config.scripts_dir = scripts_dir

        monkeypatch.setattr(server_module, "config", mock_config)

        try:
            script_path = write_ghidra_script("TestScript.py", "print('hello')")

            assert script_path.exists()
            assert script_path.read_text() == "print('hello')"
            assert script_path.name == "TestScript.py"
        finally:
            monkeypatch.setattr(server_module, "config", original_config)

    def test_creates_scripts_dir_if_missing(self, tmp_path, monkeypatch):
        """Should create scripts directory if it doesn't exist."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import write_ghidra_script

        original_config = server_module.config

        scripts_dir = tmp_path / "nonexistent" / "scripts"

        class MockConfig:
            pass
        mock_config = MockConfig()
        mock_config.scripts_dir = scripts_dir

        monkeypatch.setattr(server_module, "config", mock_config)

        try:
            script_path = write_ghidra_script("Test.py", "content")

            assert scripts_dir.exists()
            assert script_path.exists()
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestCacheIntegration:
    """Tests for cache functionality."""

    def test_cache_can_be_retrieved(self):
        """Should be able to get cache instance."""
        from kawaiidra_mcp.server import get_cache

        cache = get_cache()
        assert cache is not None

    def test_cache_stats_returns_dict(self):
        """Cache stats should return a dictionary."""
        from kawaiidra_mcp.server import get_cache_stats

        stats = get_cache_stats()
        assert isinstance(stats, dict)
        assert "enabled" in stats or "hits" in stats or "entries" in stats


class TestBackendIntegration:
    """Tests for bridge backend integration."""

    def test_get_backend_returns_instance_or_none(self):
        """get_backend should return backend instance or None."""
        from kawaiidra_mcp.server import get_backend

        backend = get_backend()
        # Either returns a GhidraBackend or None if not available
        assert backend is None or hasattr(backend, "list_functions")


class TestLogFunction:
    """Tests for the log function."""

    def test_log_writes_to_file(self, tmp_path, monkeypatch):
        """Should write log messages to file."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import log

        original_config = server_module.config

        log_dir = tmp_path / "logs"

        class MockConfig:
            def __init__(self):
                self.log_dir = log_dir
        mock_config = MockConfig()

        monkeypatch.setattr(server_module, "config", mock_config)

        try:
            log("Test message")

            log_file = log_dir / "kawaiidra.log"
            assert log_file.exists()
            assert "Test message" in log_file.read_text()
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestParseGhidraJsonOutput:
    """Tests for JSON parsing from Ghidra script output."""

    def test_parses_json_with_markers(self):
        """Should parse JSON between MCP result markers."""
        from kawaiidra_mcp.server import parse_ghidra_json_output

        output = """
Some log output
INFO: Processing...
=== MCP_RESULT_JSON ===
{"result": "success", "data": [1, 2, 3]}
=== MCP_RESULT_END ===
More output
"""
        result = parse_ghidra_json_output(output)

        assert result["result"] == "success"
        assert result["data"] == [1, 2, 3]

    def test_returns_error_for_no_markers(self):
        """Should return error dict if no markers found."""
        from kawaiidra_mcp.server import parse_ghidra_json_output

        output = "Just plain text output\nNo JSON markers here"

        result = parse_ghidra_json_output(output)

        assert result["success"] is False
        assert "error" in result

    def test_handles_json_without_end_marker(self):
        """Should handle JSON with start marker but no end marker."""
        from kawaiidra_mcp.server import parse_ghidra_json_output

        output = """
=== MCP_RESULT_JSON ===
{"key": "value"}
"""
        result = parse_ghidra_json_output(output)

        assert result["key"] == "value"

    def test_returns_error_for_invalid_json(self):
        """Should return error for malformed JSON."""
        from kawaiidra_mcp.server import parse_ghidra_json_output

        output = """
=== MCP_RESULT_JSON ===
{invalid json here}
=== MCP_RESULT_END ===
"""
        result = parse_ghidra_json_output(output)

        assert result["success"] is False
        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
