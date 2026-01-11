"""
JPype-based Ghidra Bridge for Kawaiidra MCP Server.

This module provides direct JVM access to Ghidra APIs, eliminating the
subprocess overhead of analyzeHeadless. Performance improvement: ~100-1000x
faster for sequential operations.

Usage:
    from kawaiidra_mcp.bridge import get_bridge

    bridge = get_bridge()
    bridge.ensure_started()

    # Load a program (cached after first load)
    program = bridge.open_program("/path/to/binary", "project_name")

    # Direct API calls - microseconds instead of seconds
    functions = bridge.list_functions(program, limit=100)
    code = bridge.decompile(program, "main")

For MCP tool handlers, use the backend abstraction:
    from kawaiidra_mcp.bridge import get_backend

    backend = get_backend()
    result = backend.list_functions(binary_name, project_name, limit=100)
    # Returns None if bridge unavailable, falls back to subprocess in handlers
"""

from .jpype_bridge import GhidraBridge, get_bridge, BridgeNotStartedError, BridgeError
from .backend import GhidraBackend, get_backend, reset_backend

__all__ = [
    # Low-level bridge
    "GhidraBridge",
    "get_bridge",
    "BridgeNotStartedError",
    "BridgeError",
    # High-level backend
    "GhidraBackend",
    "get_backend",
    "reset_backend",
]
