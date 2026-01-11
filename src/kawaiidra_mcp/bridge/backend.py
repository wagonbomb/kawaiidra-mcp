"""
Backend abstraction for Ghidra operations.

This module provides a unified interface for Ghidra operations that can
use either the fast JPype bridge or fall back to subprocess mode.

Usage:
    from kawaiidra_mcp.bridge.backend import get_backend

    backend = get_backend()

    # Check bridge status
    if backend.is_bridge_mode:
        print("Using fast JPype bridge")

    # All operations work the same regardless of mode
    functions = backend.list_functions(binary_name, project_name, limit=100)
    code = backend.decompile(binary_name, project_name, "main")
"""

import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

logger = logging.getLogger("kawaiidra.backend")

# Track bridge availability
_bridge_available: Optional[bool] = None
_bridge_error: Optional[str] = None


def _check_bridge_available() -> bool:
    """Check if the JPype bridge can be used."""
    global _bridge_available, _bridge_error

    if _bridge_available is not None:
        return _bridge_available

    try:
        import jpype
        _bridge_available = True
        logger.info("JPype is available - bridge mode enabled")
    except ImportError as e:
        _bridge_available = False
        _bridge_error = f"JPype not installed: {e}. Install with: pip install JPype1"
        logger.warning(_bridge_error)

    return _bridge_available


class GhidraBackend:
    """
    Unified backend for Ghidra operations.

    Automatically uses the JPype bridge when available for ~100-1000x
    faster operations, with transparent fallback to subprocess mode.
    """

    def __init__(self):
        from ..config import config
        self.config = config
        self._bridge = None
        self._bridge_initialized = False
        self._use_bridge = config.use_bridge and _check_bridge_available()

    @property
    def is_bridge_mode(self) -> bool:
        """Check if using the fast bridge mode."""
        return self._use_bridge and self._bridge is not None

    @property
    def mode_description(self) -> str:
        """Get a description of the current mode."""
        if self.is_bridge_mode:
            return "JPype Bridge (fast)"
        elif self._use_bridge:
            return "JPype Bridge (not started)"
        else:
            return "Subprocess (slow)"

    def _ensure_bridge(self) -> bool:
        """
        Ensure bridge is started. Returns True if bridge is available.

        This is called lazily on first operation to avoid startup overhead
        if only subprocess operations are needed.
        """
        if not self._use_bridge:
            return False

        if self._bridge_initialized:
            return self._bridge is not None

        self._bridge_initialized = True

        try:
            from .jpype_bridge import get_bridge
            self._bridge = get_bridge()
            self._bridge.ensure_started()
            logger.info("JPype bridge started successfully")
            return True
        except Exception as e:
            logger.warning(f"Failed to start JPype bridge: {e}")
            logger.info("Falling back to subprocess mode")
            self._bridge = None
            return False

    def _get_program_handle(self, binary_name: str, project_name: str):
        """Get a program handle, loading it if necessary."""
        if not self._ensure_bridge():
            return None

        # Try to get from cache first
        try:
            return self._bridge.get_program(project_name, binary_name)
        except Exception:
            pass

        # Need to find the binary path and load it
        # First check if it's already analyzed in the project
        from ..server import get_analyzed_binaries
        analyzed = get_analyzed_binaries(project_name)

        if binary_name not in analyzed:
            raise ValueError(f"Binary '{binary_name}' not found in project '{project_name}'")

        # For already-analyzed binaries, we need to open the project
        # The binary path isn't strictly needed since it's already imported
        project_dir = self.config.get_project_path(project_name)

        # Open the existing program from the project
        return self._bridge.open_program(
            binary_path=project_dir / binary_name,  # May not exist, but project has it
            project_name=project_name,
            project_dir=self.config.project_dir,
            analyze=False  # Already analyzed
        )

    # =========================================================================
    # High-Level Operations (match what handlers need)
    # =========================================================================

    def list_functions(
        self,
        binary_name: str,
        project_name: str,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        List functions in a binary.

        Returns:
            {"success": True, "functions": [...], "total": int}
            or {"success": False, "error": str}
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                functions = self._bridge.list_functions(handle, limit=limit)
                total = handle.program.getFunctionManager().getFunctionCount()
                return {
                    "success": True,
                    "functions": functions,
                    "total": total
                }
            except Exception as e:
                logger.warning(f"Bridge list_functions failed: {e}, falling back to subprocess")

        # Fall back to subprocess - return None to signal handler should use subprocess
        return None

    def find_functions(
        self,
        binary_name: str,
        project_name: str,
        pattern: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find functions matching a pattern.

        Returns:
            {"success": True, "matches": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                matches = self._bridge.find_functions(handle, pattern)
                return {
                    "success": True,
                    "matches": matches
                }
            except Exception as e:
                logger.warning(f"Bridge find_functions failed: {e}")

        return None

    def decompile(
        self,
        binary_name: str,
        project_name: str,
        function_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Decompile a function.

        Returns:
            {"success": True, "function": str, "address": str, "signature": str, "code": str}
            or {"success": False, "error": str}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                result = self._bridge.decompile(handle, function_name)
                return result
            except Exception as e:
                logger.warning(f"Bridge decompile failed: {e}")

        return None

    def get_disassembly(
        self,
        binary_name: str,
        project_name: str,
        function_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get disassembly for a function.

        Returns:
            {"success": True, "function": str, "address": str, "instructions": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                result = self._bridge.get_disassembly(handle, function_name)
                return result
            except Exception as e:
                logger.warning(f"Bridge get_disassembly failed: {e}")

        return None

    def get_xrefs(
        self,
        binary_name: str,
        project_name: str,
        function_name: str,
        direction: str = "both"
    ) -> Optional[Dict[str, Any]]:
        """
        Get cross-references for a function.

        Returns:
            {"success": True, "function_name": str, "references_to": [...], "references_from": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                result = self._bridge.get_xrefs(handle, function_name, direction)
                return result
            except Exception as e:
                logger.warning(f"Bridge get_xrefs failed: {e}")

        return None

    def list_strings(
        self,
        binary_name: str,
        project_name: str,
        min_length: int = 4,
        limit: int = 200
    ) -> Optional[Dict[str, Any]]:
        """
        List strings in a binary.

        Returns:
            {"success": True, "strings": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                strings = self._bridge.list_strings(handle, min_length, limit)
                return {
                    "success": True,
                    "strings": strings,
                    "count": len(strings)
                }
            except Exception as e:
                logger.warning(f"Bridge list_strings failed: {e}")

        return None

    def search_strings(
        self,
        binary_name: str,
        project_name: str,
        pattern: str
    ) -> Optional[Dict[str, Any]]:
        """
        Search for strings matching a pattern.

        Returns:
            {"success": True, "matches": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                matches = self._bridge.search_strings(handle, pattern)
                return {
                    "success": True,
                    "matches": matches
                }
            except Exception as e:
                logger.warning(f"Bridge search_strings failed: {e}")

        return None

    def get_binary_info(
        self,
        binary_name: str,
        project_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get binary metadata.

        Returns:
            {"success": True, "name": str, "format": str, ...}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                return self._bridge.get_binary_info(handle)
            except Exception as e:
                logger.warning(f"Bridge get_binary_info failed: {e}")

        return None

    def get_memory_map(
        self,
        binary_name: str,
        project_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get memory segments.

        Returns:
            {"success": True, "segments": [...]}
            or None to signal fallback to subprocess
        """
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                segments = self._bridge.get_memory_map(handle)
                return {
                    "success": True,
                    "segments": segments
                }
            except Exception as e:
                logger.warning(f"Bridge get_memory_map failed: {e}")

        return None

    def list_imports(
        self,
        binary_name: str,
        project_name: str,
        limit: int = 100
    ) -> Optional[Dict[str, Any]]:
        """List imported symbols."""
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                imports = self._bridge.list_imports(handle, limit)
                return {
                    "success": True,
                    "imports": imports
                }
            except Exception as e:
                logger.warning(f"Bridge list_imports failed: {e}")

        return None

    def list_exports(
        self,
        binary_name: str,
        project_name: str,
        limit: int = 100
    ) -> Optional[Dict[str, Any]]:
        """List exported symbols."""
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                exports = self._bridge.list_exports(handle, limit)
                return {
                    "success": True,
                    "exports": exports
                }
            except Exception as e:
                logger.warning(f"Bridge list_exports failed: {e}")

        return None

    def rename_function(
        self,
        binary_name: str,
        project_name: str,
        old_name: str,
        new_name: str
    ) -> Optional[Dict[str, Any]]:
        """Rename a function."""
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                return self._bridge.rename_function(handle, old_name, new_name)
            except Exception as e:
                logger.warning(f"Bridge rename_function failed: {e}")

        return None

    def set_comment(
        self,
        binary_name: str,
        project_name: str,
        address: str,
        comment: str,
        comment_type: str = "EOL"
    ) -> Optional[Dict[str, Any]]:
        """Set a comment at an address."""
        if self._ensure_bridge():
            try:
                handle = self._get_program_handle(binary_name, project_name)
                return self._bridge.set_comment(handle, address, comment, comment_type)
            except Exception as e:
                logger.warning(f"Bridge set_comment failed: {e}")

        return None

    def analyze_binary(
        self,
        file_path: str,
        project_name: str,
        processor: Optional[str] = None,
        base_address: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Import and analyze a binary.

        Note: This operation always needs to do real work, but with bridge
        the program stays loaded for fast subsequent operations.
        """
        if self._ensure_bridge():
            try:
                binary_path = Path(file_path)
                if not binary_path.is_absolute():
                    binary_path = self.config.binaries_dir / file_path

                if not binary_path.exists():
                    return {"success": False, "error": f"Binary not found: {file_path}"}

                handle = self._bridge.open_program(
                    binary_path=str(binary_path),
                    project_name=project_name,
                    project_dir=self.config.project_dir,
                    analyze=True
                )

                info = self._bridge.get_binary_info(handle)
                return {
                    "success": True,
                    "binary": handle.name,
                    "project": project_name,
                    "load_time": handle.load_time,
                    "info": info
                }
            except Exception as e:
                logger.warning(f"Bridge analyze_binary failed: {e}")

        return None

    def get_status(self) -> Dict[str, Any]:
        """Get backend status information."""
        status = {
            "mode": self.mode_description,
            "bridge_enabled": self._use_bridge,
            "bridge_started": self._bridge is not None,
            "jpype_available": _bridge_available,
        }

        if _bridge_error:
            status["jpype_error"] = _bridge_error

        if self._bridge is not None:
            status["cached_programs"] = len(self._bridge._program_cache)

        return status


# =============================================================================
# Global Backend Instance
# =============================================================================

_backend: Optional[GhidraBackend] = None


def get_backend() -> GhidraBackend:
    """Get the global backend instance."""
    global _backend
    if _backend is None:
        _backend = GhidraBackend()
    return _backend


def reset_backend() -> None:
    """Reset the backend (for testing)."""
    global _backend
    _backend = None
