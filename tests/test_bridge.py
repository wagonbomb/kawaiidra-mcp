"""
Unit tests for the Kawaiidra bridge/backend module.

Tests cover:
- GhidraBackend initialization
- Bridge mode detection
- Fallback to subprocess mode
- Backend operations (mocked)
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestBridgeAvailability:
    """Tests for bridge availability checking."""

    def test_check_bridge_available_without_jpype(self, monkeypatch):
        """Should return False when JPype is not installed."""
        # Reset the cached value
        import kawaiidra_mcp.bridge.backend as backend_module
        monkeypatch.setattr(backend_module, "_bridge_available", None)
        monkeypatch.setattr(backend_module, "_bridge_error", None)

        # Mock jpype import to fail
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "jpype":
                raise ImportError("No module named 'jpype'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        result = backend_module._check_bridge_available()

        assert result is False

    def test_check_bridge_available_caches_result(self, monkeypatch):
        """Should cache the bridge availability result."""
        import kawaiidra_mcp.bridge.backend as backend_module
        monkeypatch.setattr(backend_module, "_bridge_available", True)

        result = backend_module._check_bridge_available()

        assert result is True


class TestGhidraBackendInit:
    """Tests for GhidraBackend initialization."""

    def test_backend_init_with_bridge_disabled(self, monkeypatch, tmp_path):
        """Should initialize without bridge when disabled in config."""
        # Create mock Ghidra installation
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        # Need to reimport to pick up new config
        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        assert backend._use_bridge is False

    def test_backend_mode_description_subprocess(self, monkeypatch, tmp_path):
        """Should report subprocess mode when bridge is disabled."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        assert backend.mode_description == "Subprocess (slow)"


class TestGhidraBackendBridgeMode:
    """Tests for bridge mode operations."""

    def test_is_bridge_mode_false_when_not_started(self, monkeypatch, tmp_path):
        """is_bridge_mode should be False before bridge starts."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Bridge should not be started yet
        assert backend.is_bridge_mode is False

    def test_ensure_bridge_returns_false_when_disabled(self, monkeypatch, tmp_path):
        """_ensure_bridge should return False when bridge is disabled."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()
        result = backend._ensure_bridge()

        assert result is False


class TestGhidraBackendStatus:
    """Tests for backend status reporting."""

    def test_get_status_includes_required_fields(self, monkeypatch, tmp_path):
        """get_status should include all required fields."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()
        status = backend.get_status()

        assert "mode" in status
        assert "bridge_enabled" in status
        assert "bridge_started" in status
        assert "jpype_available" in status


class TestGhidraBackendOperations:
    """Tests for backend operations with mocked bridge."""

    def test_list_functions_returns_none_without_bridge(self, monkeypatch, tmp_path):
        """list_functions should return None when bridge unavailable."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()
        result = backend.list_functions("test.exe", "default", limit=10)

        assert result is None

    def test_decompile_returns_none_without_bridge(self, monkeypatch, tmp_path):
        """decompile should return None when bridge unavailable."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "false")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()
        result = backend.decompile("test.exe", "default", "main")

        assert result is None


class TestGlobalBackendFunctions:
    """Tests for global backend functions."""

    def test_get_backend_returns_instance(self, monkeypatch, tmp_path):
        """get_backend should return a GhidraBackend instance."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        # Reset global backend
        import kawaiidra_mcp.bridge.backend as backend_module
        monkeypatch.setattr(backend_module, "_backend", None)

        from kawaiidra_mcp.bridge.backend import get_backend, GhidraBackend

        backend = get_backend()

        assert isinstance(backend, GhidraBackend)

    def test_get_backend_returns_same_instance(self, monkeypatch, tmp_path):
        """get_backend should return the same singleton instance."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        import kawaiidra_mcp.bridge.backend as backend_module
        monkeypatch.setattr(backend_module, "_backend", None)

        from kawaiidra_mcp.bridge.backend import get_backend

        backend1 = get_backend()
        backend2 = get_backend()

        assert backend1 is backend2

    def test_reset_backend_clears_singleton(self, monkeypatch, tmp_path):
        """reset_backend should clear the singleton instance."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        import kawaiidra_mcp.bridge.backend as backend_module
        monkeypatch.setattr(backend_module, "_backend", None)

        from kawaiidra_mcp.bridge.backend import get_backend, reset_backend

        backend1 = get_backend()
        reset_backend()
        backend2 = get_backend()

        assert backend1 is not backend2


class TestBackendWithMockedBridge:
    """Tests using mocked bridge for more comprehensive coverage."""

    def test_list_functions_with_mocked_bridge(self, monkeypatch, tmp_path):
        """Should call bridge list_functions when available."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Mock the bridge
        mock_bridge = MagicMock()
        mock_bridge.list_functions.return_value = [
            {"name": "main", "address": "0x1000", "size": 100}
        ]
        mock_program = MagicMock()
        mock_bridge.get_program.return_value = mock_program

        backend._bridge = mock_bridge
        backend._bridge_initialized = True
        backend._use_bridge = True

        result = backend.list_functions("test.exe", "default", limit=10)

        assert result is not None
        assert "functions" in result

    def test_decompile_with_mocked_bridge(self, monkeypatch, tmp_path):
        """Should call bridge decompile when available."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Mock the bridge - return dict matching expected format
        mock_bridge = MagicMock()
        mock_bridge.decompile.return_value = {
            "success": True,
            "function": "main",
            "address": "0x1000",
            "signature": "int main(void)",
            "code": "int main() { return 0; }"
        }
        mock_program = MagicMock()
        mock_bridge.get_program.return_value = mock_program

        backend._bridge = mock_bridge
        backend._bridge_initialized = True
        backend._use_bridge = True

        result = backend.decompile("test.exe", "default", "main")

        assert result is not None
        assert result["success"] is True
        assert "code" in result

    def test_analyze_binary_with_mocked_bridge(self, monkeypatch, tmp_path):
        """Should call bridge open_program when available."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        # Create a binary file
        binary_file = tmp_path / "test.exe"
        binary_file.write_bytes(b"\x00\x00\x00\x00")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Mock the bridge
        mock_bridge = MagicMock()
        mock_handle = MagicMock()
        mock_handle.name = "test.exe"
        mock_handle.load_time = 0.5
        mock_bridge.open_program.return_value = mock_handle
        mock_bridge.get_binary_info.return_value = {"format": "PE"}

        backend._bridge = mock_bridge
        backend._bridge_initialized = True
        backend._use_bridge = True

        result = backend.analyze_binary(str(binary_file), "default")

        assert result is not None
        assert result["success"] is True


class TestBackendErrorHandling:
    """Tests for error handling in backend operations."""

    def test_handles_bridge_exception(self, monkeypatch, tmp_path):
        """Should handle exceptions from bridge gracefully."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Mock the bridge to raise an exception
        mock_bridge = MagicMock()
        mock_bridge.get_program.side_effect = Exception("Bridge error")

        backend._bridge = mock_bridge
        backend._bridge_initialized = True
        backend._use_bridge = True

        # Should return None and not raise
        result = backend.list_functions("test.exe", "default")

        assert result is None

    def test_analyze_binary_nonexistent_file(self, monkeypatch, tmp_path):
        """Should return error for nonexistent binary file."""
        ghidra_dir = tmp_path / "ghidra"
        support_dir = ghidra_dir / "support"
        support_dir.mkdir(parents=True)
        (support_dir / "analyzeHeadless").write_text("#!/bin/bash")

        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra_dir))
        monkeypatch.setenv("KAWAIIDRA_USE_BRIDGE", "true")

        import importlib
        import kawaiidra_mcp.config
        importlib.reload(kawaiidra_mcp.config)

        from kawaiidra_mcp.bridge.backend import GhidraBackend

        backend = GhidraBackend()

        # Mock the bridge
        mock_bridge = MagicMock()
        backend._bridge = mock_bridge
        backend._bridge_initialized = True
        backend._use_bridge = True

        result = backend.analyze_binary("/nonexistent/path.exe", "default")

        assert result is not None
        assert result["success"] is False
        assert "not found" in result["error"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
