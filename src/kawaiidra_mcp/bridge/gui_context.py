"""
GUI Context Manager for Kawaiidra MCP.

This module provides two complementary features:
1. Stateful context tracking for headless mode (tracks last-used address/function)
2. GUI bridge connection for real-time Ghidra GUI state queries

The dual-mode approach ensures these tools work in ALL environments:
- Headless mode: Uses context tracking from previous tool calls
- GUI mode: Queries actual selection from running Ghidra GUI

This is an improvement over GUI-only implementations as it provides
full functionality even without a running Ghidra GUI.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from threading import Lock

logger = logging.getLogger("kawaiidra.gui_context")


@dataclass
class AnalysisContext:
    """Tracks the current analysis context state.

    Updated automatically as tools are used, providing stateful
    context for get_current_address and get_current_function
    even in headless mode.
    """
    # Current binary and project being analyzed
    binary_name: Optional[str] = None
    project_name: Optional[str] = None

    # Current address (hex string like "0x401000")
    current_address: Optional[str] = None

    # Current function info
    current_function_name: Optional[str] = None
    current_function_address: Optional[str] = None

    # Entry point (set when binary is analyzed)
    entry_point: Optional[str] = None
    entry_function: Optional[str] = None

    # Statistics
    tool_calls: int = 0
    context_updates: int = 0


class ContextTracker:
    """
    Singleton context tracker that maintains analysis state.

    This is the core of headless mode support for get_current_address
    and get_current_function tools. The context is updated automatically
    by tool handlers as operations are performed.
    """

    _instance: Optional["ContextTracker"] = None
    _lock = Lock()

    def __new__(cls) -> "ContextTracker":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._context = AnalysisContext()
        self._context_lock = Lock()
        self._initialized = True
        logger.info("Context tracker initialized")

    @property
    def context(self) -> AnalysisContext:
        """Get the current context (read-only snapshot)."""
        with self._context_lock:
            return AnalysisContext(
                binary_name=self._context.binary_name,
                project_name=self._context.project_name,
                current_address=self._context.current_address,
                current_function_name=self._context.current_function_name,
                current_function_address=self._context.current_function_address,
                entry_point=self._context.entry_point,
                entry_function=self._context.entry_function,
                tool_calls=self._context.tool_calls,
                context_updates=self._context.context_updates,
            )

    def set_binary(self, binary_name: str, project_name: str,
                   entry_point: Optional[str] = None,
                   entry_function: Optional[str] = None) -> None:
        """Set the current binary context."""
        with self._context_lock:
            self._context.binary_name = binary_name
            self._context.project_name = project_name
            if entry_point:
                self._context.entry_point = entry_point
                self._context.current_address = entry_point
            if entry_function:
                self._context.entry_function = entry_function
                self._context.current_function_name = entry_function
            self._context.context_updates += 1
            logger.debug(f"Set binary context: {binary_name} in {project_name}")

    def set_address(self, address: str) -> None:
        """Set the current address."""
        with self._context_lock:
            self._context.current_address = address
            self._context.context_updates += 1
            logger.debug(f"Set current address: {address}")

    def set_function(self, function_name: str, address: Optional[str] = None) -> None:
        """Set the current function."""
        with self._context_lock:
            self._context.current_function_name = function_name
            if address:
                self._context.current_function_address = address
                self._context.current_address = address
            self._context.context_updates += 1
            logger.debug(f"Set current function: {function_name} at {address}")

    def record_tool_call(self) -> None:
        """Record that a tool was called (for statistics)."""
        with self._context_lock:
            self._context.tool_calls += 1

    def get_current_address(self) -> Optional[str]:
        """Get the current address, falling back to entry point."""
        with self._context_lock:
            return self._context.current_address or self._context.entry_point

    def get_current_function(self) -> Optional[str]:
        """Get the current function name, falling back to entry function."""
        with self._context_lock:
            return self._context.current_function_name or self._context.entry_function

    def reset(self) -> None:
        """Reset context (primarily for testing)."""
        with self._context_lock:
            self._context = AnalysisContext()
            logger.debug("Context reset")


class GUIBridge:
    """
    Bridge to running Ghidra GUI via ghidra_bridge.

    This provides real-time access to Ghidra's GUI state including
    current selection, cursor position, and active function.

    Requires:
    1. ghidra_bridge Python package: pip install ghidra_bridge
    2. ghidra_bridge_server running in Ghidra: Tools > Ghidra Bridge > Run
    """

    _instance: Optional["GUIBridge"] = None
    _lock = Lock()

    def __new__(cls) -> "GUIBridge":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        from ..config import config
        self._config = config
        self._bridge = None
        self._connected = False
        self._connection_error: Optional[str] = None
        self._initialized = True

    @property
    def is_available(self) -> bool:
        """Check if ghidra_bridge package is installed."""
        try:
            import ghidra_bridge
            return True
        except ImportError:
            return False

    @property
    def is_connected(self) -> bool:
        """Check if connected to Ghidra GUI."""
        return self._connected and self._bridge is not None

    def connect(self) -> bool:
        """
        Connect to Ghidra GUI via ghidra_bridge.

        Returns True if connection successful, False otherwise.
        """
        if not self._config.gui_mode:
            self._connection_error = "GUI mode not enabled (set KAWAIIDRA_GUI_MODE=true)"
            return False

        if not self.is_available:
            self._connection_error = "ghidra_bridge not installed (pip install ghidra_bridge)"
            return False

        try:
            import ghidra_bridge

            host = self._config.gui_bridge_host
            port = self._config.gui_bridge_port
            timeout = self._config.gui_bridge_timeout

            logger.info(f"Connecting to Ghidra GUI at {host}:{port}")

            self._bridge = ghidra_bridge.GhidraBridge(
                connect_to_host=host,
                connect_to_port=port,
                response_timeout=timeout,
                namespace={}  # Don't pollute global namespace
            )

            # Test the connection by accessing currentProgram
            _ = self._bridge.remote_eval("currentProgram")

            self._connected = True
            self._connection_error = None
            logger.info("Connected to Ghidra GUI successfully")
            return True

        except Exception as e:
            self._connected = False
            self._connection_error = str(e)
            logger.warning(f"Failed to connect to Ghidra GUI: {e}")
            return False

    def disconnect(self) -> None:
        """Disconnect from Ghidra GUI."""
        if self._bridge is not None:
            try:
                # ghidra_bridge doesn't have explicit disconnect, just dereference
                self._bridge = None
            except Exception:
                pass
        self._connected = False
        logger.info("Disconnected from Ghidra GUI")

    def get_current_address(self) -> Optional[Dict[str, Any]]:
        """
        Get the current address from Ghidra GUI.

        Returns:
            {"address": "0x...", "offset": int, "source": "gui"} on success
            None if not connected or error
        """
        if not self.is_connected:
            if not self.connect():
                return None

        try:
            result = self._bridge.remote_eval("""
import json
addr = currentAddress
if addr:
    json.dumps({
        "address": str(addr),
        "offset": addr.getOffset(),
        "source": "gui"
    })
else:
    json.dumps({"address": None, "source": "gui"})
""")
            import json
            return json.loads(result)
        except Exception as e:
            logger.warning(f"Failed to get current address from GUI: {e}")
            self._connected = False  # Mark as disconnected for retry
            return None

    def get_current_function(self) -> Optional[Dict[str, Any]]:
        """
        Get the current function from Ghidra GUI.

        Returns:
            {"name": "...", "address": "0x...", "source": "gui"} on success
            None if not connected or error
        """
        if not self.is_connected:
            if not self.connect():
                return None

        try:
            result = self._bridge.remote_eval("""
import json
func = getFunctionContaining(currentAddress)
if func:
    json.dumps({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "signature": str(func.getSignature()),
        "source": "gui"
    })
else:
    json.dumps({"name": None, "address": None, "source": "gui"})
""")
            import json
            return json.loads(result)
        except Exception as e:
            logger.warning(f"Failed to get current function from GUI: {e}")
            self._connected = False  # Mark as disconnected for retry
            return None

    def get_current_program(self) -> Optional[Dict[str, Any]]:
        """
        Get the current program info from Ghidra GUI.

        Returns:
            {"name": "...", "path": "...", "source": "gui"} on success
            None if not connected or error
        """
        if not self.is_connected:
            if not self.connect():
                return None

        try:
            result = self._bridge.remote_eval("""
import json
prog = currentProgram
if prog:
    json.dumps({
        "name": prog.getName(),
        "path": str(prog.getExecutablePath()),
        "format": prog.getExecutableFormat(),
        "source": "gui"
    })
else:
    json.dumps({"name": None, "source": "gui"})
""")
            import json
            return json.loads(result)
        except Exception as e:
            logger.warning(f"Failed to get current program from GUI: {e}")
            self._connected = False
            return None

    def get_current_selection(self) -> Optional[Dict[str, Any]]:
        """
        Get the current selection from Ghidra GUI.

        Returns selection info including start/end addresses if there's a selection.
        """
        if not self.is_connected:
            if not self.connect():
                return None

        try:
            result = self._bridge.remote_eval("""
import json
sel = currentSelection
if sel and not sel.isEmpty():
    json.dumps({
        "start": str(sel.getMinAddress()),
        "end": str(sel.getMaxAddress()),
        "num_ranges": sel.getNumAddressRanges(),
        "source": "gui"
    })
else:
    json.dumps({"has_selection": False, "source": "gui"})
""")
            import json
            return json.loads(result)
        except Exception as e:
            logger.warning(f"Failed to get current selection from GUI: {e}")
            self._connected = False
            return None

    def get_status(self) -> Dict[str, Any]:
        """Get GUI bridge status information."""
        return {
            "gui_mode_enabled": self._config.gui_mode,
            "ghidra_bridge_available": self.is_available,
            "connected": self.is_connected,
            "host": self._config.gui_bridge_host,
            "port": self._config.gui_bridge_port,
            "error": self._connection_error,
        }


# =============================================================================
# Module-level convenience functions
# =============================================================================

_context_tracker: Optional[ContextTracker] = None
_gui_bridge: Optional[GUIBridge] = None


def get_context_tracker() -> ContextTracker:
    """Get the global context tracker instance."""
    global _context_tracker
    if _context_tracker is None:
        _context_tracker = ContextTracker()
    return _context_tracker


def get_gui_bridge() -> GUIBridge:
    """Get the global GUI bridge instance."""
    global _gui_bridge
    if _gui_bridge is None:
        _gui_bridge = GUIBridge()
    return _gui_bridge


def get_current_address() -> Dict[str, Any]:
    """
    Get the current address from the best available source.

    Priority:
    1. GUI bridge (if enabled and connected)
    2. Context tracker (headless mode fallback)
    3. None with appropriate message

    Returns:
        Dict with address info and source indication
    """
    from ..config import config

    # Try GUI mode first if enabled
    if config.gui_mode:
        bridge = get_gui_bridge()
        result = bridge.get_current_address()
        if result and result.get("address"):
            return result

    # Fall back to context tracker
    tracker = get_context_tracker()
    address = tracker.get_current_address()

    if address:
        return {
            "address": address,
            "source": "context_tracker",
            "binary": tracker.context.binary_name,
            "project": tracker.context.project_name,
        }

    return {
        "address": None,
        "source": "none",
        "message": "No current address. Analyze a binary or use set_current_address first.",
    }


def get_current_function() -> Dict[str, Any]:
    """
    Get the current function from the best available source.

    Priority:
    1. GUI bridge (if enabled and connected)
    2. Context tracker (headless mode fallback)
    3. None with appropriate message

    Returns:
        Dict with function info and source indication
    """
    from ..config import config

    # Try GUI mode first if enabled
    if config.gui_mode:
        bridge = get_gui_bridge()
        result = bridge.get_current_function()
        if result and result.get("name"):
            return result

    # Fall back to context tracker
    tracker = get_context_tracker()
    func_name = tracker.get_current_function()
    ctx = tracker.context

    if func_name:
        return {
            "name": func_name,
            "address": ctx.current_function_address,
            "source": "context_tracker",
            "binary": ctx.binary_name,
            "project": ctx.project_name,
        }

    return {
        "name": None,
        "source": "none",
        "message": "No current function. Analyze a binary or use set_current_function first.",
    }


def update_context_from_decompile(binary_name: str, project_name: str,
                                   function_name: str, address: str) -> None:
    """Update context after a decompile operation."""
    tracker = get_context_tracker()
    tracker.set_binary(binary_name, project_name)
    tracker.set_function(function_name, address)
    tracker.record_tool_call()


def update_context_from_analysis(binary_name: str, project_name: str,
                                  entry_point: Optional[str] = None,
                                  entry_function: Optional[str] = None) -> None:
    """Update context after analyzing a binary."""
    tracker = get_context_tracker()
    tracker.set_binary(binary_name, project_name, entry_point, entry_function)
    tracker.record_tool_call()
