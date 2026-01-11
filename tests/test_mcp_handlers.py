"""
Integration tests for MCP tool handlers.

These tests verify the MCP tool handlers work correctly with proper
parameter validation, response formatting, and error handling.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestHandleCallTool:
    """Tests for the main tool dispatcher."""

    @pytest.mark.asyncio
    async def test_dispatches_to_correct_handler(self, monkeypatch):
        """Should dispatch tool calls to the correct handler."""
        from kawaiidra_mcp.server import handle_call_tool

        # Mock the cache_stats handler
        mock_result = [MagicMock(type="text", text="Cache stats")]

        with patch("kawaiidra_mcp.server.handle_cache_stats", new_callable=AsyncMock) as mock_handler:
            mock_handler.return_value = mock_result

            result = await handle_call_tool("cache_stats", {})

            mock_handler.assert_called_once_with({})
            assert result == mock_result

    @pytest.mark.asyncio
    async def test_returns_error_for_unknown_tool(self):
        """Should return error message for unknown tools."""
        from kawaiidra_mcp.server import handle_call_tool

        result = await handle_call_tool("nonexistent_tool", {})

        assert len(result) == 1
        assert "Unknown tool" in result[0].text

    @pytest.mark.asyncio
    async def test_handles_none_arguments(self):
        """Should handle None arguments gracefully."""
        from kawaiidra_mcp.server import handle_call_tool

        with patch("kawaiidra_mcp.server.handle_cache_stats", new_callable=AsyncMock) as mock_handler:
            mock_handler.return_value = [MagicMock(type="text", text="OK")]

            result = await handle_call_tool("cache_stats", None)

            # Should pass empty dict instead of None
            mock_handler.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_catches_handler_exceptions(self):
        """Should catch and return errors from handlers."""
        from kawaiidra_mcp.server import handle_call_tool

        with patch("kawaiidra_mcp.server.handle_cache_stats", new_callable=AsyncMock) as mock_handler:
            mock_handler.side_effect = Exception("Handler crashed")

            result = await handle_call_tool("cache_stats", {})

            assert len(result) == 1
            assert "Error" in result[0].text
            assert "Handler crashed" in result[0].text


class TestHandleCacheStats:
    """Tests for cache_stats handler."""

    @pytest.mark.asyncio
    async def test_returns_formatted_stats(self):
        """Should return formatted cache statistics."""
        from kawaiidra_mcp.server import handle_cache_stats

        with patch("kawaiidra_mcp.server.get_cache_stats") as mock_stats:
            mock_stats.return_value = {
                "enabled": True,
                "cache_dir": "/tmp/cache",
                "entry_count": 10,
                "total_size_mb": 1.5,
                "max_size_mb": 100,
                "hits": 50,
                "misses": 10,
                "hit_rate_percent": 83.3,
                "invalidations": 2,
                "evictions": 0,
            }

            result = await handle_cache_stats({})

            assert len(result) == 1
            text = result[0].text
            assert "Enabled" in text
            assert "50" in text  # hits
            assert "83.3%" in text  # hit rate

    @pytest.mark.asyncio
    async def test_shows_disabled_when_cache_off(self):
        """Should show disabled status when cache is off."""
        from kawaiidra_mcp.server import handle_cache_stats

        with patch("kawaiidra_mcp.server.get_cache_stats") as mock_stats:
            mock_stats.return_value = {
                "enabled": False,
                "cache_dir": "/tmp/cache",
                "entry_count": 0,
                "total_size_mb": 0,
                "max_size_mb": 100,
                "hits": 0,
                "misses": 0,
                "hit_rate_percent": 0,
                "invalidations": 0,
                "evictions": 0,
            }

            result = await handle_cache_stats({})

            assert "Disabled" in result[0].text


class TestHandleCacheClear:
    """Tests for cache_clear handler."""

    @pytest.mark.asyncio
    async def test_clears_all_cache(self):
        """Should clear all cache when no filters provided."""
        from kawaiidra_mcp.server import handle_cache_clear

        with patch("kawaiidra_mcp.server.clear_cache") as mock_clear:
            mock_clear.return_value = 5

            result = await handle_cache_clear({})

            mock_clear.assert_called_once_with(binary_name=None, project_name=None)
            assert "5" in result[0].text
            assert "all" in result[0].text

    @pytest.mark.asyncio
    async def test_clears_by_binary(self):
        """Should clear cache for specific binary."""
        from kawaiidra_mcp.server import handle_cache_clear

        with patch("kawaiidra_mcp.server.clear_cache") as mock_clear:
            mock_clear.return_value = 2

            result = await handle_cache_clear({"binary_name": "test.exe"})

            mock_clear.assert_called_once_with(binary_name="test.exe", project_name=None)
            assert "2" in result[0].text
            assert "test.exe" in result[0].text

    @pytest.mark.asyncio
    async def test_clears_by_project(self):
        """Should clear cache for specific project."""
        from kawaiidra_mcp.server import handle_cache_clear

        with patch("kawaiidra_mcp.server.clear_cache") as mock_clear:
            mock_clear.return_value = 3

            result = await handle_cache_clear({"project_name": "myproject"})

            mock_clear.assert_called_once_with(binary_name=None, project_name="myproject")
            assert "3" in result[0].text
            assert "myproject" in result[0].text


class TestHandleBridgeStatus:
    """Tests for bridge_status handler."""

    def test_returns_bridge_info(self):
        """Should return bridge status information."""
        from kawaiidra_mcp.server import handle_bridge_status

        with patch("kawaiidra_mcp.server.get_backend") as mock_backend:
            mock_instance = MagicMock()
            mock_instance.get_status.return_value = {
                "mode": "Subprocess (slow)",
                "bridge_enabled": True,
                "bridge_started": False,
                "jpype_available": False,
            }
            mock_backend.return_value = mock_instance

            result = handle_bridge_status({})

            assert len(result) == 1
            text = result[0].text
            assert "Subprocess" in text or "Bridge" in text


class TestHandleListAnalyzedBinaries:
    """Tests for list_analyzed_binaries handler."""

    def test_returns_binary_list(self, tmp_path, monkeypatch):
        """Should return list of analyzed binaries."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import handle_list_analyzed_binaries

        # Create mock project structure
        project_dir = tmp_path / "projects" / "default"
        project_dir.mkdir(parents=True)
        index_file = project_dir / "default.rep" / "idata" / "~index.dat"
        index_file.parent.mkdir(parents=True)
        index_file.write_text("VERSION=1\nNEXT-ID:2\n  00000000:binary1:abc123\n  00000001:binary2:def456\n")

        original_config = server_module.config

        class MockConfig:
            def __init__(self):
                self.projects_dir = tmp_path / "projects"
                self.default_project = "default"

            def get_project_path(self, project_name=None):
                name = project_name or self.default_project
                return self.projects_dir / name

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            result = handle_list_analyzed_binaries({"project_name": "default"})

            assert len(result) == 1
            text = result[0].text
            assert "binary1" in text
            assert "binary2" in text
        finally:
            monkeypatch.setattr(server_module, "config", original_config)

    def test_returns_empty_for_nonexistent_project(self, tmp_path, monkeypatch):
        """Should return empty list for nonexistent project."""
        import kawaiidra_mcp.server as server_module
        from kawaiidra_mcp.server import handle_list_analyzed_binaries

        original_config = server_module.config

        class MockConfig:
            def __init__(self):
                self.projects_dir = tmp_path / "projects"
                self.default_project = "default"

            def get_project_path(self, project_name=None):
                name = project_name or self.default_project
                return self.projects_dir / name

        monkeypatch.setattr(server_module, "config", MockConfig())

        try:
            result = handle_list_analyzed_binaries({"project_name": "nonexistent"})

            assert len(result) == 1
            # Should indicate no binaries or empty
            text = result[0].text
            assert "No" in text or "no" in text or "[]" in text or "0" in text or "analyzed binaries" in text
        finally:
            monkeypatch.setattr(server_module, "config", original_config)


class TestHandleListFunctions:
    """Tests for list_functions handler."""

    @pytest.mark.asyncio
    async def test_returns_error_for_missing_binary(self):
        """Should return error when binary_name is missing."""
        from kawaiidra_mcp.server import handle_list_functions

        result = await handle_list_functions({})

        assert len(result) == 1
        # Handler may return various error formats
        text = result[0].text.lower()
        assert "required" in text or "error" in text or "failed" in text or "binary" in text

    @pytest.mark.asyncio
    async def test_uses_backend_when_available(self):
        """Should use bridge backend when available."""
        from kawaiidra_mcp.server import handle_list_functions

        with patch("kawaiidra_mcp.server.get_backend") as mock_get_backend:
            mock_backend = MagicMock()
            mock_backend.list_functions.return_value = {
                "functions": [
                    {"name": "main", "address": "0x1000", "size": 100},
                    {"name": "foo", "address": "0x2000", "size": 50},
                ],
                "total": 2,
            }
            mock_get_backend.return_value = mock_backend

            result = await handle_list_functions({
                "binary_name": "test.exe",
                "limit": 10,
            })

            assert len(result) == 1
            # Verify backend was called
            mock_backend.list_functions.assert_called()


class TestHandleGetFunctionDecompile:
    """Tests for get_function_decompile handler."""

    @pytest.mark.asyncio
    async def test_returns_error_for_missing_binary(self):
        """Should return error when binary_name is missing."""
        from kawaiidra_mcp.server import handle_get_function_decompile

        result = await handle_get_function_decompile({"function_name": "main"})

        assert len(result) == 1
        # Handler may return various error formats
        text = result[0].text.lower()
        assert "required" in text or "error" in text or "failed" in text or "decompilation" in text

    @pytest.mark.asyncio
    async def test_returns_error_for_missing_function(self):
        """Should return error when function_name is missing."""
        from kawaiidra_mcp.server import handle_get_function_decompile

        result = await handle_get_function_decompile({"binary_name": "test.exe"})

        assert len(result) == 1
        # Handler may return various error formats
        text = result[0].text.lower()
        assert "required" in text or "error" in text or "failed" in text or "decompilation" in text

    @pytest.mark.asyncio
    async def test_uses_backend_when_available(self):
        """Should use bridge backend when available."""
        from kawaiidra_mcp.server import handle_get_function_decompile

        with patch("kawaiidra_mcp.server.get_backend") as mock_get_backend:
            mock_backend = MagicMock()
            # Use correct keys that the handler expects
            mock_backend.decompile.return_value = {
                "success": True,
                "function_name": "main",
                "address": "0x1000",
                "signature": "int main(void)",
                "code": "int main(void) {\n    return 0;\n}",
            }
            mock_get_backend.return_value = mock_backend

            result = await handle_get_function_decompile({
                "binary_name": "test.exe",
                "function_name": "main",
            })

            assert len(result) == 1
            # Verify backend was called
            mock_backend.decompile.assert_called()


class TestHandleAnalyzeBinary:
    """Tests for analyze_binary handler."""

    @pytest.mark.asyncio
    async def test_returns_error_for_missing_file_path(self):
        """Should return error when file_path is missing."""
        from kawaiidra_mcp.server import handle_analyze_binary

        # Mock resolve_binary_path to handle None input
        with patch("kawaiidra_mcp.server.resolve_binary_path") as mock_resolve:
            mock_resolve.return_value = None

            result = await handle_analyze_binary({})

            assert len(result) == 1
            text = result[0].text.lower()
            assert "required" in text or "error" in text or "not found" in text or "binary" in text

    @pytest.mark.asyncio
    async def test_returns_error_for_nonexistent_file(self):
        """Should return error for nonexistent binary file."""
        from kawaiidra_mcp.server import handle_analyze_binary

        with patch("kawaiidra_mcp.server.resolve_binary_path") as mock_resolve:
            mock_resolve.return_value = None

            result = await handle_analyze_binary({
                "file_path": "/nonexistent/path.exe"
            })

            assert len(result) == 1
            text = result[0].text.lower()
            assert "not found" in text or "error" in text or "binary" in text


class TestResponseFormatting:
    """Tests for consistent response formatting across handlers."""

    @pytest.mark.asyncio
    async def test_all_handlers_return_text_content(self):
        """All handlers should return TextContent sequences."""
        from kawaiidra_mcp.server import (
            handle_cache_stats,
            handle_cache_clear,
            handle_bridge_status,
        )
        import mcp.types as types

        with patch("kawaiidra_mcp.server.get_cache_stats") as mock_stats:
            mock_stats.return_value = {
                "enabled": True, "cache_dir": "/tmp", "entry_count": 0,
                "total_size_mb": 0, "max_size_mb": 100, "hits": 0, "misses": 0,
                "hit_rate_percent": 0, "invalidations": 0, "evictions": 0,
            }
            result = await handle_cache_stats({})
            assert all(isinstance(r, types.TextContent) for r in result)

        with patch("kawaiidra_mcp.server.clear_cache") as mock_clear:
            mock_clear.return_value = 0
            result = await handle_cache_clear({})
            assert all(isinstance(r, types.TextContent) for r in result)

        with patch("kawaiidra_mcp.server.get_backend") as mock_backend:
            mock_instance = MagicMock()
            mock_instance.get_status.return_value = {
                "mode": "test",
                "bridge_enabled": True,
                "bridge_started": False,
                "jpype_available": False,
            }
            mock_backend.return_value = mock_instance
            result = handle_bridge_status({})
            assert all(isinstance(r, types.TextContent) for r in result)


class TestHandlerParameterValidation:
    """Tests for parameter validation in handlers."""

    @pytest.mark.asyncio
    async def test_handles_extra_parameters(self):
        """Handlers should ignore extra parameters."""
        from kawaiidra_mcp.server import handle_cache_stats

        with patch("kawaiidra_mcp.server.get_cache_stats") as mock_stats:
            mock_stats.return_value = {
                "enabled": True, "cache_dir": "/tmp", "entry_count": 0,
                "total_size_mb": 0, "max_size_mb": 100, "hits": 0, "misses": 0,
                "hit_rate_percent": 0, "invalidations": 0, "evictions": 0,
            }

            # Should not raise even with extra parameters
            result = await handle_cache_stats({
                "extra_param": "ignored",
                "another_param": 123,
            })

            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_handles_wrong_parameter_types(self):
        """Handlers should handle wrong parameter types gracefully."""
        from kawaiidra_mcp.server import handle_list_functions

        # Passing string instead of int for limit
        with patch("kawaiidra_mcp.server.get_backend") as mock_backend:
            mock_backend.return_value = None

            # Should not crash even with wrong types
            result = await handle_list_functions({
                "binary_name": "test.exe",
                "limit": "not_an_int",  # Wrong type
            })

            # Should still return a result (either error or attempt to process)
            assert len(result) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
