#!/usr/bin/env python3
"""
Kawaiidra MCP Server - General-purpose binary analysis via Model Context Protocol.

Provides tools for analyzing executables, libraries, and firmware files using
Ghidra's headless analyzer and decompiler.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

try:
    from mcp.server import Server, NotificationOptions
    from mcp.server.models import InitializationOptions
    import mcp.server.stdio
    import mcp.types as types
except ImportError:
    print("Error: MCP SDK not installed. Run: pip install mcp", file=sys.stderr)
    sys.exit(1)

from .config import config


# Initialize MCP server
server = Server("kawaiidra")


def log(message: str) -> None:
    """Log message to file."""
    try:
        log_file = config.log_dir / "kawaiidra.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(f"{message}\n")
    except Exception:
        pass


def _quote_windows_arg(arg: str) -> str:
    """Quote an argument for Windows cmd.exe if it contains special characters."""
    # Characters that need quoting in cmd.exe
    special_chars = ' \t()&^|<>!'
    if any(c in arg for c in special_chars) or '"' in arg:
        # Escape special cmd.exe characters with ^ and wrap in double quotes
        escaped = arg
        for char in '^&|<>':  # Characters that need escaping even in quotes
            escaped = escaped.replace(char, f'^{char}')
        # Parentheses need escaping in cmd.exe
        escaped = escaped.replace('(', '^(').replace(')', '^)')
        # Escape any existing double quotes
        escaped = escaped.replace('"', '""')
        return '"' + escaped + '"'
    return arg


def run_ghidra_headless(
    command_args: list[str],
    timeout: Optional[int] = None
) -> tuple[str, str, int]:
    """Run Ghidra headless analyzer with given arguments.

    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    timeout = timeout or config.analysis_timeout

    try:
        analyze_headless = config.analyze_headless
    except FileNotFoundError as e:
        return "", str(e), 1

    # On Windows with batch files, we need to manually quote arguments for cmd.exe
    if sys.platform == "win32" and str(analyze_headless).endswith(".bat"):
        quoted_args = [_quote_windows_arg(arg) for arg in command_args]
        cmd_str = f'"{analyze_headless}" ' + ' '.join(quoted_args)
        log(f"Running: {cmd_str}")
        try:
            result = subprocess.run(
                cmd_str,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(config.project_dir),
                shell=True
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", 1
        except Exception as e:
            return "", str(e), 1
    else:
        cmd = [str(analyze_headless)] + command_args
        log(f"Running: {cmd}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(config.project_dir)
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", 1
        except Exception as e:
            return "", str(e), 1


def parse_ghidra_json_output(stdout: str) -> dict[str, Any]:
    """Parse JSON output from Ghidra scripts.

    Scripts should output JSON between markers:
        === MCP_RESULT_JSON ===
        {"key": "value"}
        === MCP_RESULT_END ===
    """
    if "=== MCP_RESULT_JSON ===" in stdout:
        try:
            json_part = stdout.split("=== MCP_RESULT_JSON ===")[1]
            if "=== MCP_RESULT_END ===" in json_part:
                json_part = json_part.split("=== MCP_RESULT_END ===")[0]
            return json.loads(json_part.strip())
        except (IndexError, json.JSONDecodeError) as e:
            return {"success": False, "error": f"Failed to parse output: {e}"}

    return {"success": False, "error": "No JSON result in output", "raw": stdout[-2000:]}


def resolve_binary_path(file_path: str) -> Optional[Path]:
    """Resolve a binary path - can be absolute or relative to binaries dir."""
    path = Path(file_path)

    # If absolute and exists, use it
    if path.is_absolute():
        return path if path.exists() else None

    # Try relative to binaries directory
    rel_path = config.binaries_dir / file_path
    if rel_path.exists():
        return rel_path

    return None


def get_analyzed_binaries(project_name: Optional[str] = None) -> list[str]:
    """List binaries that have been analyzed in a project."""
    project_path = config.get_project_path(project_name)
    rep_dir = project_path / f"{project_name or config.default_project}.rep"

    if not rep_dir.exists():
        return []

    # Look for .prp files which indicate analyzed programs
    binaries = []
    idata_dir = rep_dir / "idata"
    if idata_dir.exists():
        for item in idata_dir.iterdir():
            if item.is_dir():
                binaries.append(item.name)

    return binaries


def write_ghidra_script(script_name: str, content: str) -> Path:
    """Write a Ghidra script to the scripts directory."""
    config.scripts_dir.mkdir(parents=True, exist_ok=True)
    script_path = config.scripts_dir / script_name
    script_path.write_text(content, encoding="utf-8")
    return script_path


# ============================================================================
# Tool Definitions
# ============================================================================

TOOLS = [
    types.Tool(
        name="analyze_binary",
        description="Import and analyze a binary file with Ghidra. Supports PE, ELF, Mach-O, and raw formats.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary file (absolute, or relative to binaries directory)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "processor": {
                    "type": "string",
                    "description": "Processor ID for raw binaries (e.g., 'x86:LE:64:default', 'ARM:LE:32:v7')"
                },
                "base_address": {
                    "type": "string",
                    "description": "Base address for raw binaries (hex, e.g., '0x10000')"
                }
            },
            "required": ["file_path"]
        }
    ),
    types.Tool(
        name="list_analyzed_binaries",
        description="List all binaries that have been analyzed in a project",
        inputSchema={
            "type": "object",
            "properties": {
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            }
        }
    ),
    types.Tool(
        name="list_functions",
        description="List all functions in an analyzed binary",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum functions to return (default: 100)"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_functions",
        description="Search for functions by name pattern",
        inputSchema={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for (case-insensitive substring match)"
                },
                "binary_name": {
                    "type": "string",
                    "description": "Binary to search in (optional, searches all if not specified)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["pattern"]
        }
    ),
    types.Tool(
        name="get_function_decompile",
        description="Get decompiled C code for a specific function",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address (e.g., 'main' or '0x401000')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="get_function_disassembly",
        description="Get assembly listing for a specific function",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="get_function_xrefs",
        description="Get cross-references to and from a function",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "direction": {
                    "type": "string",
                    "enum": ["to", "from", "both"],
                    "description": "Direction of references (default: 'both')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="search_strings",
        description="Search for strings matching a pattern in a binary",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "pattern": {
                    "type": "string",
                    "description": "Pattern to search for (case-insensitive)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "pattern"]
        }
    ),
    types.Tool(
        name="list_strings",
        description="List all defined strings in a binary",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "min_length": {
                    "type": "integer",
                    "description": "Minimum string length (default: 4)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum strings to return (default: 200)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="get_binary_info",
        description="Get metadata about an analyzed binary (architecture, format, sections)",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="get_memory_map",
        description="Get memory segments and sections of an analyzed binary",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="export_analysis",
        description="Export analysis results (functions, symbols) to JSON file",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "output_name": {
                    "type": "string",
                    "description": "Output filename (default: <binary_name>_analysis.json)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    # ========================================================================
    # Advanced Analysis Tools (LLM-Optimized)
    # ========================================================================
    types.Tool(
        name="get_call_graph",
        description="Extract call hierarchy showing function relationships. Returns a tree/graph of which functions call which other functions.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Root function to start from (optional, shows full graph if not specified)"
                },
                "depth": {
                    "type": "integer",
                    "description": "Maximum traversal depth (default: 3, max: 5)"
                },
                "direction": {
                    "type": "string",
                    "enum": ["callers", "callees", "both"],
                    "description": "Direction to traverse (default: 'both')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="detect_libraries",
        description="Identify standard libraries, frameworks, and third-party code by analyzing imports and function names.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "detailed": {
                    "type": "boolean",
                    "description": "Include function-level details (default: false)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="semantic_code_search",
        description="Search for code by behavior patterns like file I/O, networking, cryptography, string operations, or memory allocation.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "pattern": {
                    "type": "string",
                    "enum": ["file_io", "network", "crypto", "string_ops", "memory_alloc", "registry", "process"],
                    "description": "Behavior pattern to search for"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "pattern"]
        }
    ),
    types.Tool(
        name="get_function_with_context",
        description="Extract function decompilation along with all dependencies (called functions, data types, strings) for complete LLM understanding.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "include_callees": {
                    "type": "boolean",
                    "description": "Include decompilation of called functions (default: true)"
                },
                "include_callers": {
                    "type": "boolean",
                    "description": "Include decompilation of calling functions (default: false)"
                },
                "include_data_types": {
                    "type": "boolean",
                    "description": "Include referenced data type definitions (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="get_data_structures",
        description="Extract struct/class definitions and data type information from the binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "structure_name": {
                    "type": "string",
                    "description": "Specific structure to retrieve (optional, lists all if not specified)"
                },
                "include_usage": {
                    "type": "boolean",
                    "description": "Show where structures are used (default: false)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="get_control_flow_graph",
        description="Extract control flow graph with basic blocks for understanding function logic flow.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "include_instructions": {
                    "type": "boolean",
                    "description": "Include assembly instructions in each block (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="detect_vulnerabilities",
        description="Detect potential security vulnerabilities using pattern analysis. Identifies unsafe functions, buffer issues, format strings, etc.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Specific function to analyze (optional, scans all if not specified)"
                },
                "severity": {
                    "type": "string",
                    "enum": ["all", "critical", "high", "medium"],
                    "description": "Minimum severity level to report (default: 'medium')"
                },
                "check_cves": {
                    "type": "boolean",
                    "description": "Check against CVE database for known vulnerabilities (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_similar_functions",
        description="Find functions similar to a reference function based on structure, instructions, and patterns.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Reference function to compare against"
                },
                "threshold": {
                    "type": "number",
                    "description": "Similarity threshold 0.0-1.0 (default: 0.7)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="get_annotated_disassembly",
        description="Get richly annotated disassembly with cross-references, comments, and mapped decompiled code lines.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function name or address"
                },
                "include_comments": {
                    "type": "boolean",
                    "description": "Include existing comments (default: true)"
                },
                "include_xrefs": {
                    "type": "boolean",
                    "description": "Include cross-references at each instruction (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    types.Tool(
        name="suggest_symbol_names",
        description="Suggest better variable and function names based on usage patterns, string references, and API calls.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Function to analyze for naming suggestions"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name"]
        }
    ),
    # ========================================================================
    # iOS Security Research Tools
    # ========================================================================
    types.Tool(
        name="detect_kpp_ktrr",
        description="Detect Kernel Patch Protection (KPP) and Kernel Text Read-only Region (KTRR) markers and related code in iOS/macOS kernels.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed kernel or kernelcache"
                },
                "detailed": {
                    "type": "boolean",
                    "description": "Include detailed analysis of protection mechanisms (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="analyze_mach_traps",
        description="Analyze Mach trap table and system call handlers in XNU kernel.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed kernel"
                },
                "trap_number": {
                    "type": "integer",
                    "description": "Specific trap number to analyze (optional)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_pac_gadgets",
        description="Find Pointer Authentication Code (PAC) bypass gadgets and signing/auth operations for ARM64e research.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "gadget_type": {
                    "type": "string",
                    "enum": ["signing", "auth", "bypass", "all"],
                    "description": "Type of PAC gadgets to find (default: 'all')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="analyze_sandbox_ops",
        description="Analyze sandbox operations, profiles, and policy checks in iOS/macOS binaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "operation": {
                    "type": "string",
                    "description": "Specific sandbox operation to search for (optional)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_iokit_classes",
        description="Find and analyze IOKit class hierarchies, vtables, and user client interfaces.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed kext or kernel"
                },
                "class_name": {
                    "type": "string",
                    "description": "Specific class name to search for (optional)"
                },
                "include_vtable": {
                    "type": "boolean",
                    "description": "Include vtable analysis (default: true)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="detect_entitlement_checks",
        description="Find entitlement validation code and checks in iOS/macOS binaries.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "entitlement": {
                    "type": "string",
                    "description": "Specific entitlement to search for (optional)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_kernel_symbols",
        description="Find and analyze kernel symbols, including unexported symbols, for XNU research.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed kernel"
                },
                "pattern": {
                    "type": "string",
                    "description": "Symbol name pattern to search (optional)"
                },
                "symbol_type": {
                    "type": "string",
                    "enum": ["functions", "data", "all"],
                    "description": "Type of symbols to find (default: 'all')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="analyze_mach_ports",
        description="Analyze Mach port operations, message handlers, and IPC patterns.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "port_type": {
                    "type": "string",
                    "enum": ["task", "thread", "host", "all"],
                    "description": "Type of port operations to analyze (default: 'all')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    # ========================================================================
    # Android/Mobile & General RE Tools
    # ========================================================================
    types.Tool(
        name="find_crypto_constants",
        description="Find cryptographic constants like AES S-boxes, CRC tables, and magic numbers. Useful for identifying crypto implementations.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "include_crc": {
                    "type": "boolean",
                    "description": "Include CRC table detection (default: true)"
                },
                "include_aes": {
                    "type": "boolean",
                    "description": "Include AES S-box detection (default: true)"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="analyze_jni_methods",
        description="Find JNI methods in Android native libraries. Locates JNI_OnLoad, RegisterNatives calls, and Java_* exported functions.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "include_decompile": {
                    "type": "boolean",
                    "description": "Include decompiled code for JNI_OnLoad (default: false)"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="extract_api_endpoints",
        description="Extract API endpoints, URLs, hostnames, and paths from binary strings. Useful for finding cloud services and backends.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "include_paths": {
                    "type": "boolean",
                    "description": "Include URL paths like /api/v1/... (default: true)"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="find_hardcoded_secrets",
        description="Find potential hardcoded secrets: API keys, tokens, passwords, private keys, and credentials in strings.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "sensitivity": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Detection sensitivity - higher means more results but more false positives (default: 'medium')"
                }
            },
            "required": ["binary_name"]
        }
    ),
    types.Tool(
        name="compare_binaries",
        description="Compare two analyzed binaries to find added, removed, and modified functions. Useful for diffing versions or patches.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name_a": {
                    "type": "string",
                    "description": "Name of the first binary (base/old version)"
                },
                "binary_name_b": {
                    "type": "string",
                    "description": "Name of the second binary (new version)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                },
                "match_by": {
                    "type": "string",
                    "enum": ["name", "address", "both"],
                    "description": "How to match functions between binaries (default: 'name')"
                }
            },
            "required": ["binary_name_a", "binary_name_b"]
        }
    ),
]


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available Ghidra analysis tools."""
    return TOOLS


# ============================================================================
# Tool Handlers
# ============================================================================

@server.call_tool()
async def handle_call_tool(
    name: str,
    arguments: dict[str, Any] | None
) -> Sequence[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution."""
    arguments = arguments or {}
    log(f"Tool call: {name} with {arguments}")

    try:
        if name == "analyze_binary":
            return await handle_analyze_binary(arguments)
        elif name == "list_analyzed_binaries":
            return handle_list_analyzed_binaries(arguments)
        elif name == "list_functions":
            return await handle_list_functions(arguments)
        elif name == "find_functions":
            return await handle_find_functions(arguments)
        elif name == "get_function_decompile":
            return await handle_get_function_decompile(arguments)
        elif name == "get_function_disassembly":
            return await handle_get_function_disassembly(arguments)
        elif name == "get_function_xrefs":
            return await handle_get_function_xrefs(arguments)
        elif name == "search_strings":
            return await handle_search_strings(arguments)
        elif name == "list_strings":
            return await handle_list_strings(arguments)
        elif name == "get_binary_info":
            return await handle_get_binary_info(arguments)
        elif name == "get_memory_map":
            return await handle_get_memory_map(arguments)
        elif name == "export_analysis":
            return await handle_export_analysis(arguments)
        # Advanced Analysis Tools
        elif name == "get_call_graph":
            return await handle_get_call_graph(arguments)
        elif name == "detect_libraries":
            return await handle_detect_libraries(arguments)
        elif name == "semantic_code_search":
            return await handle_semantic_code_search(arguments)
        elif name == "get_function_with_context":
            return await handle_get_function_with_context(arguments)
        elif name == "get_data_structures":
            return await handle_get_data_structures(arguments)
        elif name == "get_control_flow_graph":
            return await handle_get_control_flow_graph(arguments)
        elif name == "detect_vulnerabilities":
            return await handle_detect_vulnerabilities(arguments)
        elif name == "find_similar_functions":
            return await handle_find_similar_functions(arguments)
        elif name == "get_annotated_disassembly":
            return await handle_get_annotated_disassembly(arguments)
        elif name == "suggest_symbol_names":
            return await handle_suggest_symbol_names(arguments)
        # iOS Security Research Tools
        elif name == "detect_kpp_ktrr":
            return await handle_detect_kpp_ktrr(arguments)
        elif name == "analyze_mach_traps":
            return await handle_analyze_mach_traps(arguments)
        elif name == "find_pac_gadgets":
            return await handle_find_pac_gadgets(arguments)
        elif name == "analyze_sandbox_ops":
            return await handle_analyze_sandbox_ops(arguments)
        elif name == "find_iokit_classes":
            return await handle_find_iokit_classes(arguments)
        elif name == "detect_entitlement_checks":
            return await handle_detect_entitlement_checks(arguments)
        elif name == "find_kernel_symbols":
            return await handle_find_kernel_symbols(arguments)
        elif name == "analyze_mach_ports":
            return await handle_analyze_mach_ports(arguments)
        # Android/Mobile & General RE Tools
        elif name == "find_crypto_constants":
            return await handle_find_crypto_constants(arguments)
        elif name == "analyze_jni_methods":
            return await handle_analyze_jni_methods(arguments)
        elif name == "extract_api_endpoints":
            return await handle_extract_api_endpoints(arguments)
        elif name == "find_hardcoded_secrets":
            return await handle_find_hardcoded_secrets(arguments)
        elif name == "compare_binaries":
            return await handle_compare_binaries(arguments)
        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        log(f"Error in {name}: {e}")
        return [types.TextContent(type="text", text=f"Error: {str(e)}")]


async def handle_analyze_binary(args: dict) -> Sequence[types.TextContent]:
    """Import and analyze a binary with Ghidra."""
    file_path = args.get("file_path")
    project_name = args.get("project_name", config.default_project)
    processor = args.get("processor")
    base_address = args.get("base_address")

    # Resolve path
    binary_path = resolve_binary_path(file_path)
    if not binary_path:
        return [types.TextContent(
            type="text",
            text=f"Binary not found: {file_path}\n\nTip: Use absolute path or place file in: {config.binaries_dir}"
        )]

    # Ensure project directory exists
    project_path = config.get_project_path(project_name)
    project_path.mkdir(parents=True, exist_ok=True)

    # Build command
    cmd_args = [
        str(project_path),
        project_name,
        "-import", str(binary_path),
        "-overwrite"
    ]

    # Add processor if specified (for raw binaries)
    if processor:
        cmd_args.extend(["-processor", processor])

    if base_address:
        cmd_args.extend(["-loader", "BinaryLoader"])
        cmd_args.extend(["-loader-baseAddr", base_address])

    result_text = f"Analyzing {binary_path.name}...\n\n"

    stdout, stderr, code = run_ghidra_headless(cmd_args, timeout=config.analysis_timeout)

    if code == 0:
        result_text += f"Analysis complete!\n\n"
        result_text += f"Binary: {binary_path.name}\n"
        result_text += f"Project: {project_name}\n\n"

        # Extract key info from output
        if "Import succeeded" in stdout or "IMPORT" in stdout:
            result_text += "Import: Success\n"

        if processor:
            result_text += f"Processor: {processor}\n"

        # Show analysis summary
        func_match = re.search(r"(\d+)\s+functions", stdout)
        if func_match:
            result_text += f"Functions found: {func_match.group(1)}\n"

    else:
        result_text += f"Analysis failed (code {code})\n\n"
        result_text += "Error output:\n"
        result_text += (stderr or stdout)[-1500:]

    return [types.TextContent(type="text", text=result_text)]


def handle_list_analyzed_binaries(args: dict) -> Sequence[types.TextContent]:
    """List analyzed binaries in a project."""
    project_name = args.get("project_name", config.default_project)

    binaries = get_analyzed_binaries(project_name)

    if not binaries:
        return [types.TextContent(
            type="text",
            text=f"No analyzed binaries in project '{project_name}'.\n\nUse analyze_binary to import a binary first."
        )]

    result = f"Analyzed binaries in '{project_name}':\n\n"
    for binary in binaries:
        result += f"  - {binary}\n"

    return [types.TextContent(type="text", text=result)]


async def handle_list_functions(args: dict) -> Sequence[types.TextContent]:
    """List functions in an analyzed binary."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    limit = args.get("limit", 100)

    script = f'''# @category MCP
# @runtime Jython
import json

results = []
fm = currentProgram.getFunctionManager()
count = 0
limit = {limit}

for func in fm.getFunctions(True):
    if count >= limit:
        break
    results.append({{
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses()
    }})
    count += 1

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "functions": results, "total": fm.getFunctionCount()}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListFunctions.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListFunctions.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        funcs = result.get("functions", [])
        total = result.get("total", len(funcs))
        text = f"Functions in {binary_name} ({len(funcs)}/{total} shown):\n\n"
        for f in funcs:
            text += f"  {f['address']}: {f['name']} ({f['size']} bytes)\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}\n\n{stderr}")]


async def handle_find_functions(args: dict) -> Sequence[types.TextContent]:
    """Find functions matching a pattern."""
    pattern = args.get("pattern", "").lower()
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

pattern = "{pattern}".lower()
results = []
fm = currentProgram.getFunctionManager()

for func in fm.getFunctions(True):
    if pattern in func.getName().lower():
        results.append({{
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        }})

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "matches": results}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindFunctions.py", script)

    project_path = config.get_project_path(project_name)

    # Determine which binary to process
    if binary_name:
        process_args = ["-process", binary_name]
    else:
        process_args = ["-process"]  # Process all

    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        *process_args,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindFunctions.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        matches = result.get("matches", [])
        if matches:
            text = f"Functions matching '{pattern}':\n\n"
            for f in matches[:50]:  # Limit display
                text += f"  {f['address']}: {f['name']}\n"
            if len(matches) > 50:
                text += f"\n  ... and {len(matches) - 50} more\n"
        else:
            text = f"No functions found matching '{pattern}'"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_function_decompile(args: dict) -> Sequence[types.TextContent]:
    """Decompile a function."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def find_function(name):
    # Try by name
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]

    # Try as address
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr)
        if not func:
            func = getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("{function_name}")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())

    if results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        print("=== MCP_RESULT_JSON ===")
        print(json.dumps({{
            "success": True,
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "code": code
        }}))
        print("=== MCP_RESULT_END ===")
    else:
        print("=== MCP_RESULT_JSON ===")
        print(json.dumps({{"success": False, "error": results.getErrorMessage()}}))
        print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("DecompileFunction.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "DecompileFunction.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Decompiled {result['function']} @ {result['address']}:\n\n"
        text += f"Signature: {result['signature']}\n\n"
        text += f"```c\n{result['code']}\n```"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Decompilation failed: {result.get('error', 'Unknown error')}")]


async def handle_get_function_disassembly(args: dict) -> Sequence[types.TextContent]:
    """Get assembly for a function."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("{function_name}")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    listing = currentProgram.getListing()
    body = func.getBody()
    instructions = []

    inst = listing.getInstructionAt(body.getMinAddress())
    while inst and body.contains(inst.getAddress()):
        instructions.append({{
            "address": str(inst.getAddress()),
            "mnemonic": inst.getMnemonicString(),
            "operands": str(inst)
        }})
        inst = inst.getNext()

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "instructions": instructions
    }}))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetDisassembly.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetDisassembly.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Disassembly of {result['function']} @ {result['address']}:\n\n```asm\n"
        for inst in result.get("instructions", []):
            text += f"{inst['address']}:  {inst['operands']}\n"
        text += "```"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_function_xrefs(args: dict) -> Sequence[types.TextContent]:
    """Get cross-references for a function."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    direction = args.get("direction", "both")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import RefType

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("{function_name}")
direction = "{direction}"

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    refs_to = []
    refs_from = []
    ref_mgr = currentProgram.getReferenceManager()

    # References TO this function
    if direction in ["to", "both"]:
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            caller = getFunctionContaining(ref.getFromAddress())
            refs_to.append({{
                "from_addr": str(ref.getFromAddress()),
                "from_func": caller.getName() if caller else "unknown",
                "type": str(ref.getReferenceType())
            }})

    # References FROM this function
    if direction in ["from", "both"]:
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.isMemoryReference():
                    target_func = getFunctionAt(ref.getToAddress())
                    if target_func:
                        refs_from.append({{
                            "to_addr": str(ref.getToAddress()),
                            "to_func": target_func.getName(),
                            "type": str(ref.getReferenceType())
                        }})

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{
        "success": True,
        "function": func.getName(),
        "refs_to": refs_to[:50],
        "refs_from": refs_from[:50]
    }}))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetXrefs.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetXrefs.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Cross-references for {result['function']}:\n\n"

        refs_to = result.get("refs_to", [])
        refs_from = result.get("refs_from", [])

        if refs_to:
            text += f"Called BY ({len(refs_to)} refs):\n"
            for ref in refs_to:
                text += f"  {ref['from_addr']}: {ref['from_func']} ({ref['type']})\n"
            text += "\n"

        if refs_from:
            text += f"Calls TO ({len(refs_from)} refs):\n"
            for ref in refs_from:
                text += f"  {ref['to_addr']}: {ref['to_func']} ({ref['type']})\n"

        if not refs_to and not refs_from:
            text += "No cross-references found."

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_search_strings(args: dict) -> Sequence[types.TextContent]:
    """Search for strings matching a pattern."""
    binary_name = args.get("binary_name")
    pattern = args.get("pattern", "").lower()
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

pattern = "{pattern}".lower()
results = []
data_mgr = currentProgram.getListing()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val and pattern in str(val).lower():
            results.append({{
                "address": str(data.getAddress()),
                "value": str(val)[:200]
            }})

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "matches": results[:100]}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SearchStrings.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SearchStrings.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        matches = result.get("matches", [])
        if matches:
            text = f"Strings matching '{pattern}' in {binary_name}:\n\n"
            for m in matches:
                text += f"  {m['address']}: {m['value']}\n"
        else:
            text = f"No strings found matching '{pattern}'"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_list_strings(args: dict) -> Sequence[types.TextContent]:
    """List all strings in a binary."""
    binary_name = args.get("binary_name")
    min_length = args.get("min_length", 4)
    limit = args.get("limit", 200)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

min_len = {min_length}
limit = {limit}
results = []
data_mgr = currentProgram.getListing()
count = 0

for data in data_mgr.getDefinedData(True):
    if count >= limit:
        break
    if data.hasStringValue():
        val = data.getValue()
        if val and len(str(val)) >= min_len:
            results.append({{
                "address": str(data.getAddress()),
                "value": str(val)[:200],
                "length": len(str(val))
            }})
            count += 1

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "strings": results}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListStrings.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListStrings.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        strings = result.get("strings", [])
        text = f"Strings in {binary_name} ({len(strings)} shown):\n\n"
        for s in strings:
            text += f"  {s['address']}: {s['value']}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_binary_info(args: dict) -> Sequence[types.TextContent]:
    """Get metadata about a binary."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)

    script = '''# @category MCP
# @runtime Jython
import json

prog = currentProgram
lang = prog.getLanguage()
compiler = prog.getCompilerSpec()
mem = prog.getMemory()
fm = prog.getFunctionManager()

info = {
    "name": prog.getName(),
    "path": prog.getExecutablePath(),
    "format": prog.getExecutableFormat(),
    "processor": str(lang.getProcessor()),
    "language": str(lang.getLanguageID()),
    "endian": str(lang.isBigEndian() and "big" or "little"),
    "pointer_size": lang.getDefaultSpace().getPointerSize(),
    "compiler": str(compiler.getCompilerSpecID()),
    "image_base": str(prog.getImageBase()),
    "min_address": str(mem.getMinAddress()),
    "max_address": str(mem.getMaxAddress()),
    "memory_size": mem.getSize(),
    "function_count": fm.getFunctionCount(),
    "creation_date": str(prog.getCreationDate())
}

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "info": info}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetBinaryInfo.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetBinaryInfo.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        info = result.get("info", {})
        text = f"Binary Info: {binary_name}\n\n"
        text += f"Format:       {info.get('format', 'unknown')}\n"
        text += f"Processor:    {info.get('processor', 'unknown')}\n"
        text += f"Language:     {info.get('language', 'unknown')}\n"
        text += f"Endianness:   {info.get('endian', 'unknown')}\n"
        text += f"Pointer size: {info.get('pointer_size', 'unknown')} bytes\n"
        text += f"Compiler:     {info.get('compiler', 'unknown')}\n"
        text += f"Image base:   {info.get('image_base', 'unknown')}\n"
        text += f"Address range: {info.get('min_address', '?')} - {info.get('max_address', '?')}\n"
        text += f"Memory size:  {info.get('memory_size', 0):,} bytes\n"
        text += f"Functions:    {info.get('function_count', 0)}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_memory_map(args: dict) -> Sequence[types.TextContent]:
    """Get memory segments."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)

    script = '''# @category MCP
# @runtime Jython
import json

mem = currentProgram.getMemory()
blocks = []

for block in mem.getBlocks():
    blocks.append({
        "name": block.getName(),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
        "permissions": (
            ("r" if block.isRead() else "-") +
            ("w" if block.isWrite() else "-") +
            ("x" if block.isExecute() else "-")
        ),
        "type": str(block.getType()),
        "initialized": block.isInitialized()
    })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "blocks": blocks}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetMemoryMap.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetMemoryMap.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        blocks = result.get("blocks", [])
        text = f"Memory Map for {binary_name}:\n\n"
        text += f"{'Name':<20} {'Start':<18} {'End':<18} {'Size':>12} {'Perms':<6}\n"
        text += "-" * 80 + "\n"
        for b in blocks:
            text += f"{b['name']:<20} {b['start']:<18} {b['end']:<18} {b['size']:>12,} {b['permissions']:<6}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_export_analysis(args: dict) -> Sequence[types.TextContent]:
    """Export analysis to JSON."""
    binary_name = args.get("binary_name")
    output_name = args.get("output_name", f"{binary_name}_analysis.json")
    project_name = args.get("project_name", config.default_project)

    script = '''# @category MCP
# @runtime Jython
import json

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()

# Collect functions
functions = []
for func in fm.getFunctions(True):
    functions.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "signature": str(func.getSignature())
    })

# Collect strings
strings = []
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            strings.append({
                "address": str(data.getAddress()),
                "value": str(val)[:500]
            })

# Collect imports/exports
imports = []
exports = []
sym_table = prog.getSymbolTable()
for sym in sym_table.getAllSymbols(True):
    if sym.isExternal():
        imports.append({
            "name": sym.getName(),
            "address": str(sym.getAddress())
        })
    elif sym.getSymbolType().toString() == "Function" and sym.isGlobal():
        exports.append({
            "name": sym.getName(),
            "address": str(sym.getAddress())
        })

result = {
    "binary": prog.getName(),
    "functions": functions,
    "strings": strings[:500],
    "imports": imports,
    "exports": exports[:100]
}

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "data": result}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ExportAnalysis.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ExportAnalysis.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        data = result.get("data", {})

        # Save to file
        output_path = config.exports_dir / output_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        text = f"Analysis exported to: {output_path}\n\n"
        text += f"Summary:\n"
        text += f"  Functions: {len(data.get('functions', []))}\n"
        text += f"  Strings:   {len(data.get('strings', []))}\n"
        text += f"  Imports:   {len(data.get('imports', []))}\n"
        text += f"  Exports:   {len(data.get('exports', []))}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


# ============================================================================
# Advanced Analysis Tool Handlers
# ============================================================================

async def handle_get_call_graph(args: dict) -> Sequence[types.TextContent]:
    """Extract call graph from a binary."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    depth = min(args.get("depth", 3), 5)  # Max depth of 5
    direction = args.get("direction", "both")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

def find_function(name):
    if not name:
        return None
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

def get_callees(func, visited, current_depth, max_depth):
    if current_depth >= max_depth or func is None:
        return None

    func_addr = str(func.getEntryPoint())
    if func_addr in visited:
        return {{"name": func.getName(), "address": func_addr, "circular": True}}

    visited.add(func_addr)
    callees = []

    ref_mgr = currentProgram.getReferenceManager()
    for addr in func.getBody().getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target_func = getFunctionAt(ref.getToAddress())
                if target_func and not target_func.isThunk():
                    child = get_callees(target_func, visited.copy(), current_depth + 1, max_depth)
                    if child:
                        callees.append(child)

    return {{
        "name": func.getName(),
        "address": func_addr,
        "callees": callees[:20]  # Limit children
    }}

def get_callers(func, visited, current_depth, max_depth):
    if current_depth >= max_depth or func is None:
        return None

    func_addr = str(func.getEntryPoint())
    if func_addr in visited:
        return {{"name": func.getName(), "address": func_addr, "circular": True}}

    visited.add(func_addr)
    callers = []

    ref_mgr = currentProgram.getReferenceManager()
    for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
        if ref.getReferenceType().isCall():
            caller_func = getFunctionContaining(ref.getFromAddress())
            if caller_func:
                parent = get_callers(caller_func, visited.copy(), current_depth + 1, max_depth)
                if parent:
                    callers.append(parent)

    return {{
        "name": func.getName(),
        "address": func_addr,
        "callers": callers[:20]
    }}

root_func_name = "{function_name}" if "{function_name}" else None
max_depth = {depth}
direction = "{direction}"

result = {{"success": True}}

if root_func_name:
    root_func = find_function(root_func_name)
    if not root_func:
        result = {{"success": False, "error": "Function not found: {function_name}"}}
    else:
        if direction in ["callees", "both"]:
            result["callees"] = get_callees(root_func, set(), 0, max_depth)
        if direction in ["callers", "both"]:
            result["callers"] = get_callers(root_func, set(), 0, max_depth)
        result["root"] = {{"name": root_func.getName(), "address": str(root_func.getEntryPoint())}}
else:
    # Get top-level call graph overview
    fm = currentProgram.getFunctionManager()
    functions = []
    for func in fm.getFunctions(True):
        if len(functions) >= 50:
            break
        ref_mgr = currentProgram.getReferenceManager()
        caller_count = len(list(ref_mgr.getReferencesTo(func.getEntryPoint())))
        functions.append({{
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "caller_count": caller_count
        }})
    result["overview"] = functions

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetCallGraph.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetCallGraph.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Call Graph for {binary_name}"
        if result.get("root"):
            text += f" (root: {result['root']['name']})\n\n"
        else:
            text += " (overview)\n\n"

        def format_tree(node, indent=0, prefix=""):
            if not node:
                return ""
            s = " " * indent + prefix + f"{node['name']} @ {node['address']}"
            if node.get("circular"):
                s += " [circular]"
            s += "\n"
            for child in node.get("callees", []):
                s += format_tree(child, indent + 2, "-> ")
            for parent in node.get("callers", []):
                s += format_tree(parent, indent + 2, "<- ")
            return s

        if result.get("callees"):
            text += "Callees (functions called):\n"
            text += format_tree(result["callees"])
        if result.get("callers"):
            text += "\nCallers (functions calling):\n"
            text += format_tree(result["callers"])
        if result.get("overview"):
            text += "Function Overview (top 50):\n"
            for f in result["overview"]:
                text += f"  {f['address']}: {f['name']} ({f['caller_count']} callers)\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_detect_libraries(args: dict) -> Sequence[types.TextContent]:
    """Detect libraries used in a binary."""
    binary_name = args.get("binary_name")
    detailed = args.get("detailed", False)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
import re

# Library detection patterns
LIBRARY_PATTERNS = {{
    "OpenSSL": {{
        "functions": ["SSL_", "EVP_", "CRYPTO_", "BIO_", "PEM_", "X509_", "RSA_", "AES_"],
        "strings": ["OpenSSL", "libssl", "libcrypto"]
    }},
    "zlib": {{
        "functions": ["inflate", "deflate", "compress", "uncompress", "gzip"],
        "strings": ["zlib", "1.2."]
    }},
    "libcurl": {{
        "functions": ["curl_", "CURL"],
        "strings": ["libcurl", "curl/"]
    }},
    "Qt": {{
        "functions": ["Q", "_ZN"],  # Qt classes start with Q, mangled names
        "strings": ["Qt", "QObject", "QWidget"]
    }},
    "Boost": {{
        "functions": ["boost_", "_ZN5boost"],
        "strings": ["boost::", "Boost"]
    }},
    "libc/msvcrt": {{
        "functions": ["printf", "malloc", "free", "strcpy", "strlen", "fopen", "fclose"],
        "strings": []
    }},
    "Windows API": {{
        "functions": ["CreateFile", "ReadFile", "WriteFile", "GetProcAddress", "LoadLibrary",
                     "VirtualAlloc", "CreateProcess", "RegOpenKey", "WSA"],
        "strings": ["kernel32", "ntdll", "user32", "advapi32", "ws2_32"]
    }},
    "pthread": {{
        "functions": ["pthread_"],
        "strings": ["libpthread"]
    }},
    "SQLite": {{
        "functions": ["sqlite3_"],
        "strings": ["sqlite", "SQLite"]
    }},
    "libpng": {{
        "functions": ["png_"],
        "strings": ["libpng", "PNG"]
    }},
    "libjpeg": {{
        "functions": ["jpeg_"],
        "strings": ["libjpeg", "JPEG"]
    }}
}}

detected = {{}}
detailed_flag = {str(detailed).lower()}

# Collect all function names
fm = currentProgram.getFunctionManager()
all_funcs = []
for func in fm.getFunctions(True):
    all_funcs.append(func.getName())

# Collect all strings
all_strings = []
listing = currentProgram.getListing()
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            all_strings.append(str(val))

# Collect import names
imports = []
sym_table = currentProgram.getSymbolTable()
for sym in sym_table.getExternalSymbols():
    imports.append(sym.getName())

# Check each library
for lib_name, patterns in LIBRARY_PATTERNS.items():
    matches = {{"functions": [], "strings": [], "imports": []}}

    for func_name in all_funcs:
        for pattern in patterns["functions"]:
            if pattern in func_name:
                matches["functions"].append(func_name)
                break

    for string in all_strings[:1000]:  # Limit string search
        for pattern in patterns["strings"]:
            if pattern.lower() in string.lower():
                matches["strings"].append(string[:100])
                break

    for imp in imports:
        for pattern in patterns["functions"]:
            if pattern in imp:
                matches["imports"].append(imp)
                break

    total = len(matches["functions"]) + len(matches["strings"]) + len(matches["imports"])
    if total > 0:
        confidence = "high" if total > 5 else "medium" if total > 2 else "low"
        detected[lib_name] = {{
            "confidence": confidence,
            "match_count": total,
            "matches": matches if detailed_flag else None
        }}

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "libraries": detected, "total_functions": len(all_funcs), "total_imports": len(imports)}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("DetectLibraries.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "DetectLibraries.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        libs = result.get("libraries", {})
        text = f"Library Detection for {binary_name}\n"
        text += f"(Analyzed {result.get('total_functions', 0)} functions, {result.get('total_imports', 0)} imports)\n\n"

        if libs:
            for lib_name, info in sorted(libs.items(), key=lambda x: x[1]["match_count"], reverse=True):
                text += f"  [{info['confidence'].upper()}] {lib_name} ({info['match_count']} matches)\n"
                if detailed and info.get("matches"):
                    matches = info["matches"]
                    if matches.get("functions"):
                        text += f"    Functions: {', '.join(matches['functions'][:5])}\n"
                    if matches.get("imports"):
                        text += f"    Imports: {', '.join(matches['imports'][:5])}\n"
        else:
            text += "  No known libraries detected.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_semantic_code_search(args: dict) -> Sequence[types.TextContent]:
    """Search for code by semantic patterns."""
    binary_name = args.get("binary_name")
    pattern = args.get("pattern")
    project_name = args.get("project_name", config.default_project)

    # Define semantic patterns
    patterns_map = {
        "file_io": ["fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fprintf", "fscanf",
                   "open", "close", "read", "write", "lseek", "CreateFile", "ReadFile", "WriteFile",
                   "CloseHandle", "DeleteFile", "CopyFile", "MoveFile", "GetFileSize"],
        "network": ["socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto",
                   "recvfrom", "getaddrinfo", "gethostbyname", "inet_", "htons", "ntohs",
                   "WSAStartup", "WSASocket", "WSAConnect", "InternetOpen", "HttpOpenRequest"],
        "crypto": ["crypt", "hash", "md5", "sha1", "sha256", "sha512", "aes", "des", "rsa",
                  "encrypt", "decrypt", "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
                  "EVP_", "SSL_", "HMAC", "PBKDF2", "bcrypt", "scrypt"],
        "string_ops": ["strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strlen",
                      "strstr", "strchr", "sprintf", "snprintf", "sscanf", "memcpy", "memmove",
                      "memset", "memcmp", "wstrcpy", "wcscpy", "lstrcpy"],
        "memory_alloc": ["malloc", "calloc", "realloc", "free", "new", "delete", "HeapAlloc",
                        "HeapFree", "VirtualAlloc", "VirtualFree", "GlobalAlloc", "LocalAlloc",
                        "mmap", "munmap", "brk", "sbrk"],
        "registry": ["RegOpenKey", "RegCloseKey", "RegQueryValue", "RegSetValue", "RegDeleteKey",
                    "RegEnumKey", "RegCreateKey", "RegGetValue", "RegNotifyChangeKeyValue"],
        "process": ["CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess",
                   "fork", "exec", "system", "popen", "WinExec", "ShellExecute", "CreateThread",
                   "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory"]
    }

    search_terms = patterns_map.get(pattern, [])
    search_terms_str = json.dumps(search_terms)

    script = f'''# @category MCP
# @runtime Jython
import json

search_terms = {search_terms_str}
matches = []

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

# Find functions that call any of the search terms
for func in fm.getFunctions(True):
    func_matches = []

    # Check if function name matches
    func_name = func.getName().lower()
    for term in search_terms:
        if term.lower() in func_name:
            func_matches.append({{"type": "name_match", "term": term}})

    # Check calls from this function
    for addr in func.getBody().getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target_func = getFunctionAt(ref.getToAddress())
                if target_func:
                    target_name = target_func.getName().lower()
                    for term in search_terms:
                        if term.lower() in target_name:
                            func_matches.append({{
                                "type": "calls",
                                "target": target_func.getName(),
                                "address": str(ref.getFromAddress())
                            }})

    if func_matches:
        matches.append({{
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "matches": func_matches[:10]  # Limit matches per function
        }})

    if len(matches) >= 100:  # Limit total results
        break

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "pattern": "{pattern}", "results": matches}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SemanticCodeSearch.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SemanticCodeSearch.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        results = result.get("results", [])
        text = f"Semantic Search: '{pattern}' in {binary_name}\n"
        text += f"Found {len(results)} functions with matching behavior\n\n"

        for r in results[:50]:
            text += f"  {r['address']}: {r['function']}\n"
            for m in r.get("matches", [])[:3]:
                if m["type"] == "calls":
                    text += f"    -> calls {m['target']} at {m['address']}\n"
                else:
                    text += f"    -> name matches '{m['term']}'\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_function_with_context(args: dict) -> Sequence[types.TextContent]:
    """Get function decompilation with full context."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    include_callees = args.get("include_callees", True)
    include_callers = args.get("include_callers", False)
    include_data_types = args.get("include_data_types", True)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

def decompile_func(func, decompiler):
    if not func:
        return None
    results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
    if results.decompileCompleted():
        return {{
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "code": results.getDecompiledFunction().getC()
        }}
    return None

func = find_function("{function_name}")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = {{"success": True}}

    # Decompile main function
    main_decomp = decompile_func(func, decompiler)
    if main_decomp:
        result["function"] = main_decomp

    # Get callees
    if {str(include_callees).lower()}:
        callees = []
        ref_mgr = currentProgram.getReferenceManager()
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.getReferenceType().isCall():
                    target = getFunctionAt(ref.getToAddress())
                    if target and not target.isThunk() and len(callees) < 10:
                        decomp = decompile_func(target, decompiler)
                        if decomp:
                            callees.append(decomp)
        result["callees"] = callees

    # Get callers
    if {str(include_callers).lower()}:
        callers = []
        ref_mgr = currentProgram.getReferenceManager()
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and len(callers) < 5:
                    decomp = decompile_func(caller, decompiler)
                    if decomp:
                        callers.append(decomp)
        result["callers"] = callers

    # Get referenced strings
    strings = []
    listing = currentProgram.getListing()
    for addr in func.getBody().getAddresses(True):
        refs = currentProgram.getReferenceManager().getReferencesFrom(addr)
        for ref in refs:
            data = listing.getDataAt(ref.getToAddress())
            if data and data.hasStringValue():
                val = data.getValue()
                if val:
                    strings.append({{"address": str(data.getAddress()), "value": str(val)[:200]}})
    result["strings"] = strings[:20]

    # Get data types (if enabled)
    if {str(include_data_types).lower()}:
        types_used = []
        # Get parameter types
        for param in func.getParameters():
            dt = param.getDataType()
            types_used.append({{"name": dt.getName(), "size": dt.getLength(), "source": "parameter"}})
        # Get return type
        rt = func.getReturnType()
        if rt:
            types_used.append({{"name": rt.getName(), "size": rt.getLength(), "source": "return"}})
        result["data_types"] = types_used[:20]

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetFunctionWithContext.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetFunctionWithContext.py"
    ], timeout=config.decompile_timeout * 2)  # Double timeout for context

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Function with Context: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        if result.get("function"):
            f = result["function"]
            text += f"### Main Function: {f['name']} @ {f['address']}\n"
            text += f"Signature: {f['signature']}\n\n"
            text += f"```c\n{f['code']}\n```\n\n"

        if result.get("strings"):
            text += "### Referenced Strings\n"
            for s in result["strings"]:
                text += f"  {s['address']}: {s['value']}\n"
            text += "\n"

        if result.get("data_types"):
            text += "### Data Types Used\n"
            for dt in result["data_types"]:
                text += f"  {dt['name']} ({dt['size']} bytes) - {dt['source']}\n"
            text += "\n"

        if result.get("callees"):
            text += "### Called Functions\n"
            for f in result["callees"]:
                text += f"\n--- {f['name']} @ {f['address']} ---\n"
                text += f"```c\n{f['code'][:1000]}\n```\n"

        if result.get("callers"):
            text += "\n### Calling Functions\n"
            for f in result["callers"]:
                text += f"\n--- {f['name']} @ {f['address']} ---\n"
                text += f"```c\n{f['code'][:1000]}\n```\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_data_structures(args: dict) -> Sequence[types.TextContent]:
    """Get data structure definitions from a binary."""
    binary_name = args.get("binary_name")
    structure_name = args.get("structure_name")
    include_usage = args.get("include_usage", False)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.data import Structure, Union, Enum

structure_filter = "{structure_name}" if "{structure_name}" else None
include_usage = {str(include_usage).lower()}

dtm = currentProgram.getDataTypeManager()
structures = []

# Get all data types
for dt in dtm.getAllDataTypes():
    if isinstance(dt, (Structure, Union)):
        if structure_filter and structure_filter.lower() not in dt.getName().lower():
            continue

        components = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            if comp:
                components.append({{
                    "offset": comp.getOffset(),
                    "name": comp.getFieldName() or f"field_{{comp.getOffset():x}}",
                    "type": str(comp.getDataType().getName()),
                    "size": comp.getLength()
                }})

        struct_info = {{
            "name": dt.getName(),
            "category": str(dt.getCategoryPath()),
            "size": dt.getLength(),
            "type": "struct" if isinstance(dt, Structure) else "union",
            "components": components
        }}

        structures.append(struct_info)

        if len(structures) >= 100:
            break

# Get enums as well
enums = []
for dt in dtm.getAllDataTypes():
    if isinstance(dt, Enum):
        if structure_filter and structure_filter.lower() not in dt.getName().lower():
            continue
        values = []
        for name in dt.getNames():
            values.append({{"name": name, "value": dt.getValue(name)}})
        enums.append({{
            "name": dt.getName(),
            "size": dt.getLength(),
            "values": values[:50]
        }})
        if len(enums) >= 50:
            break

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "structures": structures, "enums": enums}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetDataStructures.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetDataStructures.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        structures = result.get("structures", [])
        enums = result.get("enums", [])

        text = f"Data Structures in {binary_name}\n"
        text += "=" * 60 + "\n\n"

        if structures:
            text += f"### Structures/Unions ({len(structures)})\n\n"
            for s in structures:
                text += f"```c\n{s['type']} {s['name']} {{ // size: {s['size']} bytes\n"
                for comp in s.get("components", []):
                    text += f"    /* 0x{comp['offset']:04x} */ {comp['type']} {comp['name']}; // {comp['size']} bytes\n"
                text += f"}};\n```\n\n"

        if enums:
            text += f"### Enumerations ({len(enums)})\n\n"
            for e in enums:
                text += f"```c\nenum {e['name']} {{\n"
                for v in e.get("values", []):
                    text += f"    {v['name']} = {v['value']},\n"
                text += f"}};\n```\n\n"

        if not structures and not enums:
            text += "No data structures found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_control_flow_graph(args: dict) -> Sequence[types.TextContent]:
    """Get control flow graph for a function."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    include_instructions = args.get("include_instructions", True)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.block import BasicBlockModel

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("{function_name}")
include_insts = {str(include_instructions).lower()}

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    bbm = BasicBlockModel(currentProgram)
    blocks = []
    edges = []
    block_map = {{}}

    # Get all basic blocks in function
    block_iter = bbm.getCodeBlocksContaining(func.getBody(), monitor)
    while block_iter.hasNext():
        block = block_iter.next()
        block_id = str(block.getFirstStartAddress())
        block_map[block_id] = len(blocks)

        block_info = {{
            "id": block_id,
            "start": str(block.getFirstStartAddress()),
            "end": str(block.getMaxAddress()),
            "size": block.getNumAddresses()
        }}

        # Get instructions if requested
        if include_insts:
            insts = []
            listing = currentProgram.getListing()
            inst = listing.getInstructionAt(block.getFirstStartAddress())
            while inst and block.contains(inst.getAddress()):
                insts.append({{
                    "address": str(inst.getAddress()),
                    "mnemonic": inst.getMnemonicString(),
                    "operands": str(inst)
                }})
                inst = inst.getNext()
                if len(insts) >= 50:  # Limit instructions per block
                    break
            block_info["instructions"] = insts

        blocks.append(block_info)

        # Get outgoing edges
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            dest_addr = str(dest.getDestinationAddress())
            flow_type = str(dest.getFlowType())
            edges.append({{
                "from": block_id,
                "to": dest_addr,
                "type": flow_type
            }})

        if len(blocks) >= 200:  # Limit total blocks
            break

    result = {{
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "block_count": len(blocks),
        "edge_count": len(edges),
        "blocks": blocks,
        "edges": edges
    }}

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetControlFlowGraph.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetControlFlowGraph.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Control Flow Graph: {result['function']} @ {result['address']}\n"
        text += f"Blocks: {result['block_count']}, Edges: {result['edge_count']}\n"
        text += "=" * 60 + "\n\n"

        for block in result.get("blocks", []):
            text += f"Block {block['id']} ({block['size']} bytes)\n"
            text += f"  Range: {block['start']} - {block['end']}\n"

            if block.get("instructions"):
                text += "  Instructions:\n"
                for inst in block["instructions"]:
                    text += f"    {inst['address']}: {inst['operands']}\n"

            # Find outgoing edges
            out_edges = [e for e in result.get("edges", []) if e["from"] == block["id"]]
            if out_edges:
                text += "  Edges:\n"
                for e in out_edges:
                    text += f"    -> {e['to']} ({e['type']})\n"
            text += "\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_detect_vulnerabilities(args: dict) -> Sequence[types.TextContent]:
    """Detect potential security vulnerabilities."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    severity = args.get("severity", "medium")
    check_cves = args.get("check_cves", True)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

# Vulnerability patterns
VULN_PATTERNS = {{
    "buffer_overflow": {{
        "severity": "high",
        "cwe": "CWE-120",
        "functions": ["strcpy", "strcat", "gets", "sprintf", "scanf", "vsprintf",
                     "lstrcpy", "lstrcpyA", "lstrcpyW", "StrCpy"],
        "description": "Unbounded string copy - potential buffer overflow"
    }},
    "format_string": {{
        "severity": "high",
        "cwe": "CWE-134",
        "functions": ["printf", "fprintf", "sprintf", "snprintf", "vprintf",
                     "syslog", "wprintf"],
        "description": "Potential format string vulnerability"
    }},
    "command_injection": {{
        "severity": "critical",
        "cwe": "CWE-78",
        "functions": ["system", "popen", "exec", "execl", "execle", "execlp",
                     "execv", "execve", "execvp", "ShellExecute", "WinExec",
                     "CreateProcess"],
        "description": "Command execution - potential command injection"
    }},
    "path_traversal": {{
        "severity": "high",
        "cwe": "CWE-22",
        "functions": ["fopen", "open", "CreateFile", "DeleteFile", "CopyFile",
                     "MoveFile", "LoadLibrary"],
        "description": "File operation - check for path traversal"
    }},
    "memory_corruption": {{
        "severity": "high",
        "cwe": "CWE-119",
        "functions": ["memcpy", "memmove", "memset", "bcopy", "CopyMemory"],
        "description": "Memory operation - verify bounds checking"
    }},
    "integer_overflow": {{
        "severity": "medium",
        "cwe": "CWE-190",
        "functions": ["malloc", "calloc", "realloc", "alloca", "HeapAlloc",
                     "VirtualAlloc", "LocalAlloc", "GlobalAlloc"],
        "description": "Memory allocation - check for integer overflow in size"
    }},
    "use_after_free": {{
        "severity": "critical",
        "cwe": "CWE-416",
        "functions": ["free", "delete", "HeapFree", "VirtualFree", "LocalFree",
                     "GlobalFree"],
        "description": "Memory deallocation - potential use-after-free"
    }},
    "race_condition": {{
        "severity": "medium",
        "cwe": "CWE-362",
        "functions": ["CreateThread", "pthread_create", "fork", "_beginthread",
                     "_beginthreadex"],
        "description": "Thread creation - check for race conditions"
    }},
    "crypto_weak": {{
        "severity": "medium",
        "cwe": "CWE-327",
        "functions": ["MD5", "SHA1", "DES", "RC4", "rand", "srand", "random"],
        "description": "Potentially weak cryptographic algorithm"
    }}
}}

severity_filter = "{severity}"
function_filter = "{function_name}" if "{function_name}" else None
severity_order = {{"critical": 4, "high": 3, "medium": 2, "low": 1, "all": 0}}

vulnerabilities = []
fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

# Determine which functions to analyze
if function_filter:
    funcs = getGlobalFunctions(function_filter)
    if not funcs:
        try:
            addr = toAddr(function_filter)
            f = getFunctionAt(addr) or getFunctionContaining(addr)
            funcs = [f] if f else []
        except:
            funcs = []
else:
    funcs = list(fm.getFunctions(True))[:500]  # Limit scan

for func in funcs:
    if not func:
        continue

    # Check calls from this function
    for addr in func.getBody().getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target = getFunctionAt(ref.getToAddress())
                if target:
                    target_name = target.getName()

                    # Check against vulnerability patterns
                    for vuln_type, vuln_info in VULN_PATTERNS.items():
                        if severity_order.get(vuln_info["severity"], 0) < severity_order.get(severity_filter, 0):
                            continue

                        for pattern in vuln_info["functions"]:
                            if pattern.lower() in target_name.lower():
                                vulnerabilities.append({{
                                    "type": vuln_type,
                                    "severity": vuln_info["severity"],
                                    "cwe": vuln_info["cwe"],
                                    "function": func.getName(),
                                    "function_address": str(func.getEntryPoint()),
                                    "call_address": str(addr),
                                    "target": target_name,
                                    "description": vuln_info["description"]
                                }})
                                break

# Sort by severity
vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "vulnerabilities": vulnerabilities[:100], "functions_scanned": len(funcs)}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("DetectVulnerabilities.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "DetectVulnerabilities.py"
    ], timeout=config.analysis_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        vulns = result.get("vulnerabilities", [])
        text = f"Vulnerability Scan: {binary_name}\n"
        text += f"Functions scanned: {result.get('functions_scanned', 0)}\n"
        text += f"Issues found: {len(vulns)}\n"
        text += "=" * 60 + "\n\n"

        if vulns:
            # Group by severity
            by_severity = {}
            for v in vulns:
                sev = v["severity"]
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(v)

            for sev in ["critical", "high", "medium", "low"]:
                if sev in by_severity:
                    text += f"### {sev.upper()} ({len(by_severity[sev])})\n\n"
                    for v in by_severity[sev]:
                        text += f"  [{v['cwe']}] {v['type']}\n"
                        text += f"    Location: {v['function']} @ {v['call_address']}\n"
                        text += f"    Calls: {v['target']}\n"
                        text += f"    {v['description']}\n\n"
        else:
            text += "No vulnerabilities detected with current severity filter.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_find_similar_functions(args: dict) -> Sequence[types.TextContent]:
    """Find functions similar to a reference function."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    threshold = args.get("threshold", 0.7)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
from collections import Counter

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

def get_function_fingerprint(func):
    """Create a fingerprint of the function for comparison."""
    if not func:
        return None

    listing = currentProgram.getListing()
    body = func.getBody()

    # Collect mnemonics
    mnemonics = []
    inst = listing.getInstructionAt(body.getMinAddress())
    while inst and body.contains(inst.getAddress()):
        mnemonics.append(inst.getMnemonicString())
        inst = inst.getNext()

    # Count mnemonic frequencies
    mnem_counts = Counter(mnemonics)

    # Get reference counts
    ref_mgr = currentProgram.getReferenceManager()
    call_count = 0
    data_ref_count = 0
    for addr in body.getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                call_count += 1
            elif ref.getReferenceType().isData():
                data_ref_count += 1

    return {{
        "size": body.getNumAddresses(),
        "instruction_count": len(mnemonics),
        "mnemonic_counts": dict(mnem_counts),
        "call_count": call_count,
        "data_ref_count": data_ref_count,
        "param_count": func.getParameterCount()
    }}

def compare_fingerprints(fp1, fp2):
    """Compare two fingerprints and return similarity score."""
    if not fp1 or not fp2:
        return 0.0

    # Size similarity
    size_sim = 1.0 - abs(fp1["size"] - fp2["size"]) / max(fp1["size"], fp2["size"], 1)

    # Instruction count similarity
    inst_sim = 1.0 - abs(fp1["instruction_count"] - fp2["instruction_count"]) / max(fp1["instruction_count"], fp2["instruction_count"], 1)

    # Mnemonic distribution similarity (Jaccard)
    m1 = set(fp1["mnemonic_counts"].keys())
    m2 = set(fp2["mnemonic_counts"].keys())
    mnem_sim = len(m1 & m2) / max(len(m1 | m2), 1)

    # Call count similarity
    call_sim = 1.0 - abs(fp1["call_count"] - fp2["call_count"]) / max(fp1["call_count"], fp2["call_count"], 1)

    # Parameter count similarity
    param_sim = 1.0 if fp1["param_count"] == fp2["param_count"] else 0.5

    # Weighted average
    return (size_sim * 0.2 + inst_sim * 0.2 + mnem_sim * 0.3 + call_sim * 0.2 + param_sim * 0.1)

ref_func = find_function("{function_name}")
threshold = {threshold}

if not ref_func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    ref_fp = get_function_fingerprint(ref_func)
    similar = []

    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getEntryPoint() == ref_func.getEntryPoint():
            continue

        fp = get_function_fingerprint(func)
        sim = compare_fingerprints(ref_fp, fp)

        if sim >= threshold:
            similar.append({{
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "similarity": round(sim, 3),
                "size": fp["size"] if fp else 0,
                "instruction_count": fp["instruction_count"] if fp else 0
            }})

    # Sort by similarity
    similar.sort(key=lambda x: x["similarity"], reverse=True)

    result = {{
        "success": True,
        "reference": {{
            "name": ref_func.getName(),
            "address": str(ref_func.getEntryPoint()),
            "fingerprint": ref_fp
        }},
        "similar_functions": similar[:50],
        "threshold": threshold
    }}

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindSimilarFunctions.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindSimilarFunctions.py"
    ], timeout=config.analysis_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        ref = result.get("reference", {})
        similar = result.get("similar_functions", [])

        text = f"Similar Functions to {ref['name']} @ {ref['address']}\n"
        text += f"Threshold: {result['threshold']}\n"
        text += "=" * 60 + "\n\n"

        if ref.get("fingerprint"):
            fp = ref["fingerprint"]
            text += f"Reference fingerprint:\n"
            text += f"  Size: {fp['size']} bytes, {fp['instruction_count']} instructions\n"
            text += f"  Calls: {fp['call_count']}, Data refs: {fp['data_ref_count']}\n"
            text += f"  Parameters: {fp['param_count']}\n\n"

        if similar:
            text += f"Found {len(similar)} similar functions:\n\n"
            for s in similar:
                text += f"  {s['similarity']:.1%} - {s['name']} @ {s['address']}\n"
                text += f"        ({s['size']} bytes, {s['instruction_count']} instructions)\n"
        else:
            text += "No similar functions found above threshold.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_get_annotated_disassembly(args: dict) -> Sequence[types.TextContent]:
    """Get annotated disassembly with comments and xrefs."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    include_comments = args.get("include_comments", True)
    include_xrefs = args.get("include_xrefs", True)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("{function_name}")
include_comments = {str(include_comments).lower()}
include_xrefs = {str(include_xrefs).lower()}

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()
    body = func.getBody()

    instructions = []
    inst = listing.getInstructionAt(body.getMinAddress())

    while inst and body.contains(inst.getAddress()):
        addr = inst.getAddress()

        inst_info = {{
            "address": str(addr),
            "bytes": " ".join(["%02x" % (b & 0xff) for b in inst.getBytes()]),
            "mnemonic": inst.getMnemonicString(),
            "operands": str(inst),
            "label": None,
            "comments": [],
            "xrefs_to": [],
            "xrefs_from": []
        }}

        # Get labels/symbols
        sym = getSymbolAt(addr)
        if sym:
            inst_info["label"] = sym.getName()

        # Get comments
        if include_comments:
            eol_comment = listing.getComment(0, addr)  # EOL_COMMENT
            pre_comment = listing.getComment(1, addr)  # PRE_COMMENT
            post_comment = listing.getComment(2, addr)  # POST_COMMENT
            plate_comment = listing.getComment(3, addr)  # PLATE_COMMENT

            if eol_comment:
                inst_info["comments"].append({{"type": "eol", "text": eol_comment}})
            if pre_comment:
                inst_info["comments"].append({{"type": "pre", "text": pre_comment}})
            if post_comment:
                inst_info["comments"].append({{"type": "post", "text": post_comment}})

        # Get cross-references
        if include_xrefs:
            # References TO this address
            for ref in ref_mgr.getReferencesTo(addr):
                from_func = getFunctionContaining(ref.getFromAddress())
                inst_info["xrefs_to"].append({{
                    "from": str(ref.getFromAddress()),
                    "from_func": from_func.getName() if from_func else None,
                    "type": str(ref.getReferenceType())
                }})

            # References FROM this address
            for ref in ref_mgr.getReferencesFrom(addr):
                target_func = getFunctionAt(ref.getToAddress())
                # Check if it's a string reference
                data = listing.getDataAt(ref.getToAddress())
                string_val = None
                if data and data.hasStringValue():
                    val = data.getValue()
                    if val:
                        string_val = str(val)[:50]

                inst_info["xrefs_from"].append({{
                    "to": str(ref.getToAddress()),
                    "to_func": target_func.getName() if target_func else None,
                    "to_string": string_val,
                    "type": str(ref.getReferenceType())
                }})

        instructions.append(inst_info)
        inst = inst.getNext()

        if len(instructions) >= 500:  # Limit
            break

    result = {{
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "instruction_count": len(instructions),
        "instructions": instructions
    }}

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetAnnotatedDisassembly.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetAnnotatedDisassembly.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Annotated Disassembly: {result['function']} @ {result['address']}\n"
        text += f"Instructions: {result['instruction_count']}\n"
        text += "=" * 60 + "\n\n"

        for inst in result.get("instructions", []):
            # Pre-comments
            for c in inst.get("comments", []):
                if c["type"] == "pre":
                    text += f"; {c['text']}\n"

            # Label
            if inst.get("label"):
                text += f"\n{inst['label']}:\n"

            # Instruction with xrefs
            line = f"  {inst['address']}:  {inst['bytes']:<20}  {inst['operands']}"

            # EOL comment
            for c in inst.get("comments", []):
                if c["type"] == "eol":
                    line += f"  ; {c['text']}"

            # String reference annotation
            for xref in inst.get("xrefs_from", []):
                if xref.get("to_string"):
                    line += f'  ; "{xref["to_string"]}"'
                elif xref.get("to_func"):
                    line += f"  ; -> {xref['to_func']}"

            text += line + "\n"

            # Post-comments
            for c in inst.get("comments", []):
                if c["type"] == "post":
                    text += f"; {c['text']}\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_suggest_symbol_names(args: dict) -> Sequence[types.TextContent]:
    """Suggest better names for symbols based on usage patterns."""
    binary_name = args.get("binary_name")
    function_name = args.get("function_name")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json
import re

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

# Name suggestion patterns based on API calls
API_HINTS = {{
    "fopen": "file", "fclose": "file", "fread": "file", "fwrite": "file",
    "CreateFile": "file", "ReadFile": "file", "WriteFile": "file",
    "malloc": "buffer", "calloc": "buffer", "alloc": "buffer",
    "socket": "network", "connect": "network", "send": "network", "recv": "network",
    "printf": "print", "sprintf": "format", "snprintf": "format",
    "strcpy": "string", "strcat": "string", "strlen": "string",
    "crypt": "crypto", "hash": "hash", "encrypt": "encrypt", "decrypt": "decrypt",
    "RegOpenKey": "registry", "RegQueryValue": "registry",
    "CreateProcess": "process", "OpenProcess": "process",
    "CreateThread": "thread", "pthread_create": "thread",
    "LoadLibrary": "dll", "GetProcAddress": "dll"
}}

func = find_function("{function_name}")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({{"success": False, "error": "Function not found: {function_name}"}}))
    print("=== MCP_RESULT_END ===")
else:
    suggestions = []

    # Analyze function name
    func_name = func.getName()
    if func_name.startswith("FUN_") or func_name.startswith("sub_"):
        # Unnamed function - suggest based on behavior
        listing = currentProgram.getListing()
        ref_mgr = currentProgram.getReferenceManager()

        # Collect called functions
        called_funcs = []
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.getReferenceType().isCall():
                    target = getFunctionAt(ref.getToAddress())
                    if target:
                        called_funcs.append(target.getName())

        # Collect referenced strings
        ref_strings = []
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                data = listing.getDataAt(ref.getToAddress())
                if data and data.hasStringValue():
                    val = data.getValue()
                    if val:
                        ref_strings.append(str(val))

        # Generate suggestions based on API calls
        api_hints = []
        for called in called_funcs:
            for api, hint in API_HINTS.items():
                if api.lower() in called.lower():
                    api_hints.append(hint)

        if api_hints:
            # Most common hint
            from collections import Counter
            common_hint = Counter(api_hints).most_common(1)[0][0]
            suggestions.append({{
                "symbol": func_name,
                "suggested_name": common_hint + "_handler",
                "confidence": "medium",
                "reason": f"Calls {common_hint}-related APIs"
            }})

        # Extract keywords from strings
        for s in ref_strings[:5]:
            # Simple word extraction
            words = re.findall(r'[a-zA-Z]{{4,}}', s)
            for word in words[:2]:
                if len(word) <= 20:
                    suggestions.append({{
                        "symbol": func_name,
                        "suggested_name": word.lower() + "_func",
                        "confidence": "low",
                        "reason": f'References string containing "{{word}}"'
                    }})

    # Analyze parameters
    for i, param in enumerate(func.getParameters()):
        param_name = param.getName()
        param_type = param.getDataType().getName()

        if param_name.startswith("param_") or param_name.startswith("arg_"):
            suggested = None

            if "char*" in param_type or "char *" in param_type:
                suggested = "str" if i == 0 else f"str{{i}}"
            elif "int" in param_type.lower():
                suggested = "count" if i > 0 else "value"
            elif "*" in param_type:
                suggested = "ptr" if i == 0 else f"ptr{{i}}"

            if suggested:
                suggestions.append({{
                    "symbol": param_name,
                    "suggested_name": suggested,
                    "confidence": "low",
                    "reason": f"Based on type: {{param_type}}"
                }})

    result = {{
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "suggestions": suggestions[:20]
    }}

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SuggestSymbolNames.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SuggestSymbolNames.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        suggestions = result.get("suggestions", [])
        text = f"Symbol Name Suggestions for {result['function']} @ {result['address']}\n"
        text += "=" * 60 + "\n\n"

        if suggestions:
            for s in suggestions:
                text += f"  {s['symbol']} -> {s['suggested_name']}\n"
                text += f"    Confidence: {s['confidence']}\n"
                text += f"    Reason: {s['reason']}\n\n"
        else:
            text += "No naming suggestions available for this function.\n"
            text += "The function may already have meaningful names or lacks analyzable patterns.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


# ============================================================================
# iOS Security Research Tool Handlers
# ============================================================================

async def handle_detect_kpp_ktrr(args: dict) -> Sequence[types.TextContent]:
    """Detect KPP/KTRR and kernel protection mechanisms."""
    binary_name = args.get("binary_name")
    detailed = args.get("detailed", True)
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

# KPP/KTRR detection patterns
KPP_INDICATORS = {{
    "functions": [
        "kpp_", "monitor_", "rorgn_", "lockdown_",
        "ml_static_mfree", "pmap_protect", "kernel_memory_allocate",
        "PPL", "ppl_", "gxf_", "AMFI", "AppleMobileFileIntegrity"
    ],
    "strings": [
        "KTRR", "KPP", "Kernel Patch Protection", "text_readonly",
        "rorgn_begin", "rorgn_end", "__TEXT_EXEC", "__PPLTEXT",
        "Kernel text locked", "amfi_", "cs_enforcement",
        "APRR", "PPL violation", "code signature"
    ],
    "segments": ["__PPLTEXT", "__PPLDATA", "__TEXT_EXEC", "__KLD"]
}}

detailed_flag = {str(detailed).lower()}

results = {{
    "kpp_detected": False,
    "ktrr_detected": False,
    "ppl_detected": False,
    "amfi_detected": False,
    "indicators": [],
    "protection_functions": [],
    "protection_strings": [],
    "protected_segments": []
}}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

# Check for protection-related functions
for func in fm.getFunctions(True):
    func_name = func.getName().lower()
    for indicator in KPP_INDICATORS["functions"]:
        if indicator.lower() in func_name:
            results["protection_functions"].append({{
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "indicator": indicator
            }})
            if "kpp" in indicator.lower():
                results["kpp_detected"] = True
            if "ppl" in indicator.lower():
                results["ppl_detected"] = True
            if "amfi" in indicator.lower():
                results["amfi_detected"] = True

# Check for protection-related strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)
            for indicator in KPP_INDICATORS["strings"]:
                if indicator.lower() in str_val.lower():
                    results["protection_strings"].append({{
                        "address": str(data.getAddress()),
                        "value": str_val[:100],
                        "indicator": indicator
                    }})
                    if "ktrr" in indicator.lower():
                        results["ktrr_detected"] = True
                    if "kpp" in indicator.lower():
                        results["kpp_detected"] = True
                    if "ppl" in indicator.lower():
                        results["ppl_detected"] = True
                    if "amfi" in indicator.lower():
                        results["amfi_detected"] = True

# Check memory segments
for block in mem.getBlocks():
    block_name = block.getName()
    for seg in KPP_INDICATORS["segments"]:
        if seg in block_name:
            results["protected_segments"].append({{
                "name": block_name,
                "start": str(block.getStart()),
                "size": block.getSize(),
                "permissions": (
                    ("r" if block.isRead() else "-") +
                    ("w" if block.isWrite() else "-") +
                    ("x" if block.isExecute() else "-")
                )
            }})

# Build summary
results["summary"] = []
if results["kpp_detected"]:
    results["summary"].append("KPP (Kernel Patch Protection) detected")
if results["ktrr_detected"]:
    results["summary"].append("KTRR (Kernel Text Read-only Region) detected")
if results["ppl_detected"]:
    results["summary"].append("PPL (Page Protection Layer) detected")
if results["amfi_detected"]:
    results["summary"].append("AMFI (Apple Mobile File Integrity) detected")

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("DetectKPPKTRR.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "DetectKPPKTRR.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"iOS Kernel Protection Analysis: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        # Summary
        if result.get("summary"):
            text += "### Protections Detected\n"
            for s in result["summary"]:
                text += f"  [+] {s}\n"
            text += "\n"
        else:
            text += "### No kernel protections detected\n\n"

        # Protected segments
        if result.get("protected_segments"):
            text += f"### Protected Segments ({len(result['protected_segments'])})\n"
            for seg in result["protected_segments"]:
                text += f"  {seg['name']}: {seg['start']} ({seg['size']} bytes) [{seg['permissions']}]\n"
            text += "\n"

        # Protection functions
        if result.get("protection_functions") and detailed:
            text += f"### Protection Functions ({len(result['protection_functions'])})\n"
            for f in result["protection_functions"][:20]:
                text += f"  {f['address']}: {f['name']}\n"
            text += "\n"

        # Protection strings
        if result.get("protection_strings") and detailed:
            text += f"### Protection Strings ({len(result['protection_strings'])})\n"
            for s in result["protection_strings"][:15]:
                text += f"  {s['address']}: {s['value']}\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_analyze_mach_traps(args: dict) -> Sequence[types.TextContent]:
    """Analyze Mach trap table and syscall handlers."""
    binary_name = args.get("binary_name")
    trap_number = args.get("trap_number")
    project_name = args.get("project_name", config.default_project)

    trap_filter = f"trap_number = {trap_number}" if trap_number else "trap_number = None"

    script = f'''# @category MCP
# @runtime Jython
import json

{trap_filter}

# Known Mach trap names
MACH_TRAPS = {{
    -10: "kern_invalid",
    -26: "mach_reply_port",
    -27: "thread_self_trap",
    -28: "task_self_trap",
    -29: "host_self_trap",
    -31: "mach_msg_trap",
    -32: "mach_msg_overwrite_trap",
    -33: "semaphore_signal_trap",
    -34: "semaphore_signal_all_trap",
    -36: "semaphore_wait_trap",
    -41: "task_for_pid",
    -45: "pid_for_task",
    -48: "macx_swapon",
    -49: "macx_swapoff",
    -51: "macx_triggers",
    -59: "swtch_pri",
    -60: "swtch",
    -61: "thread_switch",
    -89: "mach_timebase_info_trap",
    -90: "mach_wait_until_trap",
    -91: "mk_timer_create_trap",
    -92: "mk_timer_destroy_trap",
    -93: "mk_timer_arm_trap",
    -94: "mk_timer_cancel_trap"
}}

results = {{
    "trap_table_found": False,
    "traps": [],
    "syscall_handlers": []
}}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()

# Search for mach trap table
for sym in sym_table.getAllSymbols(True):
    sym_name = sym.getName()
    if "mach_trap_table" in sym_name.lower() or "mach_trap" in sym_name.lower():
        results["trap_table_found"] = True
        results["traps"].append({{
            "symbol": sym_name,
            "address": str(sym.getAddress())
        }})

# Search for known trap handler functions
for func in fm.getFunctions(True):
    func_name = func.getName()

    # Check against known trap names
    for trap_num, trap_name in MACH_TRAPS.items():
        if trap_name in func_name or func_name.startswith("_" + trap_name):
            if trap_number is None or trap_num == trap_number:
                results["syscall_handlers"].append({{
                    "trap_number": trap_num,
                    "name": func_name,
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses()
                }})

    # Also check for generic mach_msg patterns
    if any(x in func_name.lower() for x in ["mach_msg", "mach_port", "ipc_", "mig_"]):
        if trap_number is None:
            results["syscall_handlers"].append({{
                "trap_number": "N/A",
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses()
            }})

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("AnalyzeMachTraps.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "AnalyzeMachTraps.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Mach Trap Analysis: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        if result.get("trap_table_found"):
            text += "[+] Mach trap table found\n"
            for t in result.get("traps", []):
                text += f"    {t['symbol']} @ {t['address']}\n"
            text += "\n"

        handlers = result.get("syscall_handlers", [])
        if handlers:
            text += f"### Mach Trap Handlers ({len(handlers)})\n\n"
            # Sort by trap number
            sorted_handlers = sorted(handlers, key=lambda x: x["trap_number"] if isinstance(x["trap_number"], int) else 0)
            for h in sorted_handlers[:50]:
                text += f"  [{h['trap_number']:>4}] {h['name']}\n"
                text += f"         @ {h['address']} ({h['size']} bytes)\n"
        else:
            text += "No Mach trap handlers found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_find_pac_gadgets(args: dict) -> Sequence[types.TextContent]:
    """Find PAC gadgets for ARM64e research."""
    binary_name = args.get("binary_name")
    gadget_type = args.get("gadget_type", "all")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

gadget_type = "{gadget_type}"

# PAC instruction patterns (ARM64e)
PAC_SIGNING = ["pacia", "pacib", "pacda", "pacdb", "paciza", "pacizb", "pacdza", "pacdzb", "pacga"]
PAC_AUTH = ["autia", "autib", "autda", "autdb", "autiza", "autizb", "autdza", "autdzb"]
PAC_COMBINED = ["blraa", "blrab", "braa", "brab", "retaa", "retab", "eretaa", "eretab"]

results = {{
    "signing_gadgets": [],
    "auth_gadgets": [],
    "bypass_candidates": [],
    "pac_instructions_found": 0
}}

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# Scan all instructions
for func in fm.getFunctions(True):
    body = func.getBody()
    inst = listing.getInstructionAt(body.getMinAddress())

    while inst and body.contains(inst.getAddress()):
        mnemonic = inst.getMnemonicString().lower()

        # Check for PAC signing instructions
        if gadget_type in ["signing", "all"]:
            for pac_inst in PAC_SIGNING:
                if pac_inst in mnemonic:
                    results["signing_gadgets"].append({{
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    }})
                    results["pac_instructions_found"] += 1

        # Check for PAC auth instructions
        if gadget_type in ["auth", "all"]:
            for pac_inst in PAC_AUTH:
                if pac_inst in mnemonic:
                    results["auth_gadgets"].append({{
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    }})
                    results["pac_instructions_found"] += 1

        # Check for combined PAC+branch (potential bypass gadgets)
        if gadget_type in ["bypass", "all"]:
            for pac_inst in PAC_COMBINED:
                if pac_inst in mnemonic:
                    results["bypass_candidates"].append({{
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    }})
                    results["pac_instructions_found"] += 1

        inst = inst.getNext()

    # Limit results
    if len(results["signing_gadgets"]) + len(results["auth_gadgets"]) + len(results["bypass_candidates"]) > 500:
        break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindPACGadgets.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindPACGadgets.py"
    ], timeout=config.analysis_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"PAC Gadget Analysis: {binary_name}\n"
        text += f"Total PAC instructions found: {result.get('pac_instructions_found', 0)}\n"
        text += "=" * 60 + "\n\n"

        # Signing gadgets
        signing = result.get("signing_gadgets", [])
        if signing:
            text += f"### PAC Signing Gadgets ({len(signing)})\n"
            for g in signing[:30]:
                text += f"  {g['address']}: {g['instruction']}\n"
                text += f"    in {g['function']}\n"
            text += "\n"

        # Auth gadgets
        auth = result.get("auth_gadgets", [])
        if auth:
            text += f"### PAC Auth Gadgets ({len(auth)})\n"
            for g in auth[:30]:
                text += f"  {g['address']}: {g['instruction']}\n"
                text += f"    in {g['function']}\n"
            text += "\n"

        # Bypass candidates
        bypass = result.get("bypass_candidates", [])
        if bypass:
            text += f"### PAC Bypass Candidates ({len(bypass)})\n"
            for g in bypass[:30]:
                text += f"  {g['address']}: {g['instruction']}\n"
                text += f"    in {g['function']}\n"

        if not signing and not auth and not bypass:
            text += "No PAC gadgets found. Binary may not be ARM64e or PAC is not used.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_analyze_sandbox_ops(args: dict) -> Sequence[types.TextContent]:
    """Analyze sandbox operations and policy checks."""
    binary_name = args.get("binary_name")
    operation = args.get("operation")
    project_name = args.get("project_name", config.default_project)

    op_filter = f'operation_filter = "{operation}"' if operation else 'operation_filter = None'

    script = f'''# @category MCP
# @runtime Jython
import json

{op_filter}

# Known sandbox operations
SANDBOX_OPS = [
    "file-read-data", "file-write-data", "file-read-metadata",
    "file-write-create", "file-write-unlink", "file-read-xattr",
    "process-fork", "process-exec", "signal",
    "mach-lookup", "mach-register", "mach-task-name",
    "network-outbound", "network-inbound", "network-bind",
    "ipc-posix-shm", "ipc-posix-sem", "sysctl-read", "sysctl-write",
    "iokit-open", "iokit-get-properties", "iokit-set-properties",
    "system-socket", "system-sysctl", "nvram-get", "nvram-set"
]

# Sandbox-related functions
SANDBOX_FUNCS = [
    "sandbox_check", "sandbox_init", "sandbox_free_error",
    "sandbox_apply", "sandbox_extension", "sandbox_container",
    "sb_evaluate", "mac_sandbox", "mpo_", "cred_check"
]

results = {{
    "sandbox_functions": [],
    "sandbox_ops_strings": [],
    "policy_checks": [],
    "mach_lookups": []
}}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

# Find sandbox-related functions
for func in fm.getFunctions(True):
    func_name = func.getName().lower()
    for sb_func in SANDBOX_FUNCS:
        if sb_func.lower() in func_name:
            results["sandbox_functions"].append({{
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses()
            }})
            break

# Find sandbox operation strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)

            # Check if it's a sandbox operation
            for op in SANDBOX_OPS:
                if op in str_val.lower():
                    if operation_filter is None or operation_filter.lower() in str_val.lower():
                        # Find references to this string
                        refs = list(ref_mgr.getReferencesTo(data.getAddress()))
                        ref_funcs = []
                        for ref in refs[:5]:
                            func = getFunctionContaining(ref.getFromAddress())
                            if func:
                                ref_funcs.append(func.getName())

                        results["sandbox_ops_strings"].append({{
                            "operation": str_val[:100],
                            "address": str(data.getAddress()),
                            "referenced_by": ref_funcs
                        }})
                    break

            # Check for mach-lookup operations
            if "mach-lookup" in str_val.lower() or str_val.startswith("com.apple."):
                results["mach_lookups"].append({{
                    "service": str_val[:100],
                    "address": str(data.getAddress())
                }})

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("AnalyzeSandboxOps.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "AnalyzeSandboxOps.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Sandbox Analysis: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        # Sandbox functions
        funcs = result.get("sandbox_functions", [])
        if funcs:
            text += f"### Sandbox Functions ({len(funcs)})\n"
            for f in funcs[:20]:
                text += f"  {f['address']}: {f['name']} ({f['size']} bytes)\n"
            text += "\n"

        # Sandbox operations
        ops = result.get("sandbox_ops_strings", [])
        if ops:
            text += f"### Sandbox Operations ({len(ops)})\n"
            for op in ops[:30]:
                text += f"  {op['operation']}\n"
                text += f"    @ {op['address']}\n"
                if op.get("referenced_by"):
                    text += f"    Used by: {', '.join(op['referenced_by'])}\n"
            text += "\n"

        # Mach lookups
        mach = result.get("mach_lookups", [])
        if mach:
            text += f"### Mach Service Lookups ({len(mach)})\n"
            for m in mach[:30]:
                text += f"  {m['service']}\n"

        if not funcs and not ops and not mach:
            text += "No sandbox-related code found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_find_iokit_classes(args: dict) -> Sequence[types.TextContent]:
    """Find IOKit classes and vtables."""
    binary_name = args.get("binary_name")
    class_name = args.get("class_name")
    include_vtable = args.get("include_vtable", True)
    project_name = args.get("project_name", config.default_project)

    class_filter = f'class_filter = "{class_name}"' if class_name else 'class_filter = None'

    script = f'''# @category MCP
# @runtime Jython
import json

{class_filter}
include_vtable = {str(include_vtable).lower()}

# Known IOKit base classes
IOKIT_BASE_CLASSES = [
    "IOService", "IOUserClient", "IORegistryEntry", "IOCommand",
    "IOEventSource", "IOMemoryDescriptor", "IOBufferMemoryDescriptor",
    "IODMACommand", "IOWorkLoop", "IOInterruptEventSource"
]

results = {{
    "iokit_classes": [],
    "user_clients": [],
    "vtables": []
}}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()
listing = currentProgram.getListing()

# Find IOKit class symbols (usually in __DATA.__const or similar)
for sym in sym_table.getAllSymbols(True):
    sym_name = sym.getName()

    # Look for metaclass or vtable symbols
    if "::MetaClass" in sym_name or "_METACLASS_" in sym_name or "ZTV" in sym_name:
        class_detected = None

        # Extract class name from symbol
        for base in IOKIT_BASE_CLASSES:
            if base in sym_name:
                class_detected = base
                break

        if class_detected or class_filter:
            if class_filter is None or class_filter.lower() in sym_name.lower():
                results["iokit_classes"].append({{
                    "symbol": sym_name,
                    "address": str(sym.getAddress()),
                    "base_class": class_detected
                }})

                # Check for UserClient (security-sensitive)
                if "UserClient" in sym_name:
                    results["user_clients"].append({{
                        "name": sym_name,
                        "address": str(sym.getAddress())
                    }})

# Find external/dispatch methods (common attack surface)
for func in fm.getFunctions(True):
    func_name = func.getName()
    if any(x in func_name for x in ["externalMethod", "getTargetAndMethodForIndex",
                                    "clientClose", "clientMemoryForType",
                                    "registerNotificationPort"]):
        if class_filter is None or class_filter.lower() in func_name.lower():
            results["iokit_classes"].append({{
                "symbol": func_name,
                "address": str(func.getEntryPoint()),
                "type": "dispatch_method"
            }})

# Look for vtables if requested
if include_vtable:
    for sym in sym_table.getAllSymbols(True):
        if "vtable" in sym.getName().lower() or sym.getName().startswith("_ZTV"):
            if class_filter is None or class_filter.lower() in sym.getName().lower():
                results["vtables"].append({{
                    "symbol": sym.getName(),
                    "address": str(sym.getAddress())
                }})

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindIOKitClasses.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindIOKitClasses.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"IOKit Class Analysis: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        # User clients (security-critical)
        clients = result.get("user_clients", [])
        if clients:
            text += f"### IOUserClient Classes ({len(clients)}) [Security-Sensitive]\n"
            for c in clients[:20]:
                text += f"  {c['address']}: {c['name']}\n"
            text += "\n"

        # IOKit classes
        classes = result.get("iokit_classes", [])
        if classes:
            text += f"### IOKit Classes/Methods ({len(classes)})\n"
            for c in classes[:30]:
                text += f"  {c['address']}: {c['symbol']}\n"
                if c.get("base_class"):
                    text += f"    inherits: {c['base_class']}\n"
            text += "\n"

        # VTables
        vtables = result.get("vtables", [])
        if vtables and include_vtable:
            text += f"### VTables ({len(vtables)})\n"
            for v in vtables[:20]:
                text += f"  {v['address']}: {v['symbol']}\n"

        if not clients and not classes and not vtables:
            text += "No IOKit classes found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_detect_entitlement_checks(args: dict) -> Sequence[types.TextContent]:
    """Find entitlement validation checks."""
    binary_name = args.get("binary_name")
    entitlement = args.get("entitlement")
    project_name = args.get("project_name", config.default_project)

    ent_filter = f'ent_filter = "{entitlement}"' if entitlement else 'ent_filter = None'

    script = f'''# @category MCP
# @runtime Jython
import json

{ent_filter}

# Common iOS/macOS entitlements
KNOWN_ENTITLEMENTS = [
    "com.apple.private.security.container-required",
    "com.apple.private.skip-library-validation",
    "com.apple.private.amfi.can-load-cdhash",
    "platform-application",
    "get-task-allow",
    "task_for_pid-allow",
    "com.apple.system-task-ports",
    "com.apple.private.kernel.jit",
    "com.apple.private.kernel.override-cpufeatures",
    "com.apple.rootless.install",
    "com.apple.rootless.storage",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation"
]

# Entitlement check functions
ENT_CHECK_FUNCS = [
    "IOTaskHasEntitlement", "amfi_check_dyld_policy_self",
    "csblob_get_entitlements", "cs_entitlement_check",
    "sandbox_check_by_audit_token", "SecTaskCopyValueForEntitlement",
    "xpc_connection_get_entitlement_value", "proc_has_entitlement"
]

results = {{
    "entitlement_strings": [],
    "check_functions": [],
    "check_sites": []
}}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

# Find entitlement strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)

            is_entitlement = False
            if str_val.startswith("com.apple."):
                is_entitlement = True
            elif any(ent in str_val for ent in KNOWN_ENTITLEMENTS):
                is_entitlement = True

            if is_entitlement:
                if ent_filter is None or ent_filter.lower() in str_val.lower():
                    refs = list(ref_mgr.getReferencesTo(data.getAddress()))
                    ref_funcs = []
                    for ref in refs[:5]:
                        func = getFunctionContaining(ref.getFromAddress())
                        if func:
                            ref_funcs.append({{
                                "name": func.getName(),
                                "address": str(ref.getFromAddress())
                            }})

                    results["entitlement_strings"].append({{
                        "entitlement": str_val[:150],
                        "address": str(data.getAddress()),
                        "checked_in": ref_funcs
                    }})

# Find entitlement check functions
for func in fm.getFunctions(True):
    func_name = func.getName()
    for check_func in ENT_CHECK_FUNCS:
        if check_func.lower() in func_name.lower():
            # Find callers
            callers = []
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller:
                    callers.append(caller.getName())

            results["check_functions"].append({{
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "called_by": list(set(callers))[:10]
            }})
            break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("DetectEntitlementChecks.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "DetectEntitlementChecks.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Entitlement Check Analysis: {binary_name}\n"
        text += "=" * 60 + "\n\n"

        # Check functions
        funcs = result.get("check_functions", [])
        if funcs:
            text += f"### Entitlement Check Functions ({len(funcs)})\n"
            for f in funcs:
                text += f"  {f['address']}: {f['name']}\n"
                if f.get("called_by"):
                    text += f"    Called by: {', '.join(f['called_by'][:5])}\n"
            text += "\n"

        # Entitlement strings
        ents = result.get("entitlement_strings", [])
        if ents:
            text += f"### Entitlements Referenced ({len(ents)})\n"
            for e in ents[:40]:
                text += f"  {e['entitlement']}\n"
                text += f"    @ {e['address']}\n"
                if e.get("checked_in"):
                    for ref in e["checked_in"][:2]:
                        text += f"    Checked in: {ref['name']} @ {ref['address']}\n"
            text += "\n"

        if not funcs and not ents:
            text += "No entitlement checks found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_find_kernel_symbols(args: dict) -> Sequence[types.TextContent]:
    """Find kernel symbols for XNU research."""
    binary_name = args.get("binary_name")
    pattern = args.get("pattern")
    symbol_type = args.get("symbol_type", "all")
    project_name = args.get("project_name", config.default_project)

    pattern_filter = f'pattern_filter = "{pattern}".lower()' if pattern else 'pattern_filter = None'

    script = f'''# @category MCP
# @runtime Jython
import json

{pattern_filter}
symbol_type = "{symbol_type}"

# Important kernel symbols for research
IMPORTANT_SYMBOLS = [
    "kernel_map", "kernel_task", "kernproc", "realhost",
    "zone_array", "kalloc", "kfree", "ipc_port_alloc",
    "task_zone", "thread_zone", "ipc_space_kernel",
    "IORegistryEntry::getProperty", "copyin", "copyout",
    "current_task", "current_thread", "proc_find"
]

results = {{
    "functions": [],
    "data_symbols": [],
    "important_symbols": [],
    "total_count": 0
}}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()

# Find functions
if symbol_type in ["functions", "all"]:
    for func in fm.getFunctions(True):
        func_name = func.getName()
        include = False

        if pattern_filter:
            if pattern_filter in func_name.lower():
                include = True
        else:
            include = True

        if include:
            is_important = any(imp.lower() in func_name.lower() for imp in IMPORTANT_SYMBOLS)

            entry = {{
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "important": is_important
            }}

            if is_important:
                results["important_symbols"].append(entry)
            else:
                results["functions"].append(entry)

            results["total_count"] += 1

            if results["total_count"] >= 500:
                break

# Find data symbols
if symbol_type in ["data", "all"] and results["total_count"] < 500:
    for sym in sym_table.getAllSymbols(True):
        if sym.getSymbolType().toString() == "Label":
            sym_name = sym.getName()
            include = False

            if pattern_filter:
                if pattern_filter in sym_name.lower():
                    include = True
            else:
                # Only include if it matches important patterns
                include = any(imp.lower() in sym_name.lower() for imp in IMPORTANT_SYMBOLS)

            if include:
                is_important = any(imp.lower() in sym_name.lower() for imp in IMPORTANT_SYMBOLS)

                entry = {{
                    "name": sym_name,
                    "address": str(sym.getAddress()),
                    "important": is_important
                }}

                if is_important:
                    results["important_symbols"].append(entry)
                else:
                    results["data_symbols"].append(entry)

                results["total_count"] += 1

                if results["total_count"] >= 500:
                    break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindKernelSymbols.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindKernelSymbols.py"
    ], timeout=config.analysis_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Kernel Symbol Analysis: {binary_name}\n"
        if pattern:
            text += f"Filter: '{pattern}'\n"
        text += f"Total symbols found: {result.get('total_count', 0)}\n"
        text += "=" * 60 + "\n\n"

        # Important symbols first
        important = result.get("important_symbols", [])
        if important:
            text += f"### Important Symbols ({len(important)})\n"
            for s in important[:30]:
                text += f"  {s['address']}: {s['name']}"
                if s.get("size"):
                    text += f" ({s['size']} bytes)"
                text += "\n"
            text += "\n"

        # Functions
        funcs = result.get("functions", [])
        if funcs:
            text += f"### Functions ({len(funcs)})\n"
            for f in funcs[:40]:
                text += f"  {f['address']}: {f['name']} ({f['size']} bytes)\n"
            text += "\n"

        # Data symbols
        data = result.get("data_symbols", [])
        if data:
            text += f"### Data Symbols ({len(data)})\n"
            for d in data[:30]:
                text += f"  {d['address']}: {d['name']}\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_analyze_mach_ports(args: dict) -> Sequence[types.TextContent]:
    """Analyze Mach port operations and IPC patterns."""
    binary_name = args.get("binary_name")
    port_type = args.get("port_type", "all")
    project_name = args.get("project_name", config.default_project)

    script = f'''# @category MCP
# @runtime Jython
import json

port_type_filter = "{port_type}"

# Mach port functions by category
PORT_FUNCTIONS = {{
    "task": [
        "task_get_special_port", "task_set_special_port",
        "mach_port_allocate", "mach_port_insert_right",
        "task_suspend", "task_resume", "task_threads",
        "task_for_pid", "pid_for_task"
    ],
    "thread": [
        "thread_create", "thread_terminate", "thread_suspend",
        "thread_get_state", "thread_set_state", "thread_create_running"
    ],
    "host": [
        "host_get_special_port", "host_set_special_port",
        "host_processor_info", "host_info", "host_priv_port"
    ],
    "general": [
        "mach_msg", "mach_msg_overwrite", "mach_port_deallocate",
        "mach_port_mod_refs", "mach_port_destroy", "ipc_port",
        "convert_port_to_task", "convert_task_to_port"
    ]
}}

results = {{
    "port_operations": [],
    "ipc_patterns": [],
    "dangerous_operations": []
}}

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

# Build list of functions to search for
search_funcs = []
if port_type_filter == "all":
    for funcs in PORT_FUNCTIONS.values():
        search_funcs.extend(funcs)
else:
    search_funcs = PORT_FUNCTIONS.get(port_type_filter, [])
    search_funcs.extend(PORT_FUNCTIONS.get("general", []))

# Dangerous operations (security-sensitive)
DANGEROUS_OPS = ["task_for_pid", "convert_port_to_task", "thread_create_running",
                 "mach_port_insert_right", "host_priv_port"]

# Find port-related functions
for func in fm.getFunctions(True):
    func_name = func.getName()

    for search_func in search_funcs:
        if search_func.lower() in func_name.lower():
            # Get callers
            callers = []
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and caller.getName() != func_name:
                    callers.append(caller.getName())

            entry = {{
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "called_by": list(set(callers))[:10],
                "category": next((cat for cat, funcs in PORT_FUNCTIONS.items() if search_func in funcs), "general")
            }}

            # Check if dangerous
            if any(danger in func_name.lower() for danger in [d.lower() for d in DANGEROUS_OPS]):
                results["dangerous_operations"].append(entry)
            else:
                results["port_operations"].append(entry)

            break

# Find mach_msg patterns (IPC)
for func in fm.getFunctions(True):
    func_name = func.getName()
    if "mach_msg" in func_name.lower() or "mig_" in func_name.lower():
        results["ipc_patterns"].append({{
            "name": func_name,
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        }})

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("AnalyzeMachPorts.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "AnalyzeMachPorts.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        text = f"Mach Port Analysis: {binary_name}\n"
        text += f"Filter: {port_type}\n"
        text += "=" * 60 + "\n\n"

        # Dangerous operations first
        dangerous = result.get("dangerous_operations", [])
        if dangerous:
            text += f"### Dangerous Operations ({len(dangerous)}) [Security-Sensitive]\n"
            for op in dangerous:
                text += f"  {op['address']}: {op['name']}\n"
                if op.get("called_by"):
                    text += f"    Called by: {', '.join(op['called_by'][:3])}\n"
            text += "\n"

        # Port operations
        ops = result.get("port_operations", [])
        if ops:
            text += f"### Port Operations ({len(ops)})\n"
            # Group by category
            by_category = {}
            for op in ops:
                cat = op.get("category", "general")
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(op)

            for cat, cat_ops in by_category.items():
                text += f"\n  [{cat.upper()}]\n"
                for op in cat_ops[:10]:
                    text += f"    {op['address']}: {op['name']}\n"
            text += "\n"

        # IPC patterns
        ipc = result.get("ipc_patterns", [])
        if ipc:
            text += f"### IPC Patterns ({len(ipc)})\n"
            for p in ipc[:20]:
                text += f"  {p['address']}: {p['name']}\n"

        if not dangerous and not ops and not ipc:
            text += "No Mach port operations found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


# ============================================================================
# Android/Mobile & General RE Tool Handlers
# ============================================================================

async def handle_find_crypto_constants(args: dict) -> Sequence[types.TextContent]:
    """Find cryptographic constants like AES S-boxes and CRC tables."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    include_crc = args.get("include_crc", True)
    include_aes = args.get("include_aes", True)

    script = f'''# @category MCP
# @runtime Jython
import json
import struct

# Known crypto constants
AES_SBOX_START = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]
AES_INV_SBOX_START = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]
CRC32_TABLE_START = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba]
CRC16_TABLE_START = [0x0000, 0xc0c1, 0xc181, 0x0140]

# Magic numbers for various algorithms
MAGIC_NUMBERS = {{
    0x67452301: "MD5/SHA1 init A",
    0xefcdab89: "MD5/SHA1 init B",
    0x98badcfe: "MD5/SHA1 init C",
    0x10325476: "MD5/SHA1 init D",
    0xc3d2e1f0: "SHA1 init E",
    0x6a09e667: "SHA256 init",
    0xbb67ae85: "SHA256 init",
    0x3c6ef372: "SHA256 init",
    0xa54ff53a: "SHA256 init",
    0x5be0cd19: "SHA256 init",
    0x428a2f98: "SHA256 K constant",
    0x71374491: "SHA256 K constant",
    0x27b70a85: "ChaCha20 constant",
    0x61707865: "ChaCha20 'expa'",
    0x3320646e: "ChaCha20 'nd 3'",
    0x79622d32: "ChaCha20 '2-by'",
    0x6b206574: "ChaCha20 'tek '",
}}

results = {{
    "aes_sbox": [],
    "aes_inv_sbox": [],
    "crc_tables": [],
    "magic_numbers": [],
    "potential_keys": []
}}

memory = currentProgram.getMemory()
listing = currentProgram.getListing()

# Search for AES S-box
if {str(include_aes).lower()}:
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        try:
            addr = block.getStart()
            end = block.getEnd()
            while addr and addr.compareTo(end) < 0:
                # Check for AES S-box
                bytes_match = True
                for i, expected in enumerate(AES_SBOX_START):
                    try:
                        b = memory.getByte(addr.add(i)) & 0xFF
                        if b != expected:
                            bytes_match = False
                            break
                    except:
                        bytes_match = False
                        break

                if bytes_match:
                    results["aes_sbox"].append({{
                        "address": str(addr),
                        "type": "AES S-box (256 bytes)"
                    }})
                    addr = addr.add(256)
                    continue

                # Check for inverse S-box
                bytes_match = True
                for i, expected in enumerate(AES_INV_SBOX_START):
                    try:
                        b = memory.getByte(addr.add(i)) & 0xFF
                        if b != expected:
                            bytes_match = False
                            break
                    except:
                        bytes_match = False
                        break

                if bytes_match:
                    results["aes_inv_sbox"].append({{
                        "address": str(addr),
                        "type": "AES Inverse S-box (256 bytes)"
                    }})
                    addr = addr.add(256)
                    continue

                addr = addr.add(1)
        except:
            continue

# Search for CRC tables
if {str(include_crc).lower()}:
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        try:
            addr = block.getStart()
            end = block.getEnd()
            while addr and addr.compareTo(end) < 0:
                # Check for CRC32 table
                try:
                    val0 = memory.getInt(addr) & 0xFFFFFFFF
                    val1 = memory.getInt(addr.add(4)) & 0xFFFFFFFF
                    if val0 == 0x00000000 and val1 == 0x77073096:
                        results["crc_tables"].append({{
                            "address": str(addr),
                            "type": "CRC32 table (1024 bytes)",
                            "polynomial": "0x04C11DB7 (standard)"
                        }})
                        addr = addr.add(1024)
                        continue
                except:
                    pass

                # Check for CRC8 table (256 bytes of single bytes)
                try:
                    b0 = memory.getByte(addr) & 0xFF
                    b1 = memory.getByte(addr.add(1)) & 0xFF
                    # Common CRC8 tables start with 0x00
                    if b0 == 0x00 and b1 != 0x00:
                        # Verify it looks like a lookup table
                        unique_vals = set()
                        is_table = True
                        for i in range(min(32, 256)):
                            try:
                                unique_vals.add(memory.getByte(addr.add(i)) & 0xFF)
                            except:
                                is_table = False
                                break
                        if is_table and len(unique_vals) > 20:
                            results["crc_tables"].append({{
                                "address": str(addr),
                                "type": "Potential CRC8/lookup table (256 bytes)"
                            }})
                            addr = addr.add(256)
                            continue
                except:
                    pass

                addr = addr.add(4)
        except:
            continue

# Search for magic numbers in data
for block in memory.getBlocks():
    if not block.isInitialized():
        continue
    try:
        addr = block.getStart()
        end = block.getEnd()
        while addr and addr.compareTo(end) < 0:
            try:
                val = memory.getInt(addr) & 0xFFFFFFFF
                if val in MAGIC_NUMBERS:
                    results["magic_numbers"].append({{
                        "address": str(addr),
                        "value": hex(val),
                        "meaning": MAGIC_NUMBERS[val]
                    }})
            except:
                pass
            addr = addr.add(4)
    except:
        continue

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "results": results}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindCryptoConstants.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindCryptoConstants.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        data = result.get("results", {})
        text = f"# Crypto Constants in {binary_name}\n\n"

        total = 0

        if data.get("aes_sbox"):
            text += f"## AES S-boxes ({len(data['aes_sbox'])})\n"
            for item in data["aes_sbox"]:
                text += f"  {item['address']}: {item['type']}\n"
            total += len(data["aes_sbox"])

        if data.get("aes_inv_sbox"):
            text += f"\n## AES Inverse S-boxes ({len(data['aes_inv_sbox'])})\n"
            for item in data["aes_inv_sbox"]:
                text += f"  {item['address']}: {item['type']}\n"
            total += len(data["aes_inv_sbox"])

        if data.get("crc_tables"):
            text += f"\n## CRC Tables ({len(data['crc_tables'])})\n"
            for item in data["crc_tables"]:
                text += f"  {item['address']}: {item['type']}\n"
            total += len(data["crc_tables"])

        if data.get("magic_numbers"):
            text += f"\n## Crypto Magic Numbers ({len(data['magic_numbers'])})\n"
            for item in data["magic_numbers"][:50]:
                text += f"  {item['address']}: {item['value']} ({item['meaning']})\n"
            total += len(data["magic_numbers"])

        if total == 0:
            text += "No crypto constants found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_analyze_jni_methods(args: dict) -> Sequence[types.TextContent]:
    """Find JNI methods in Android native libraries."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    include_decompile = args.get("include_decompile", False)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

results = {{
    "jni_onload": None,
    "jni_onunload": None,
    "java_methods": [],
    "register_natives_calls": [],
    "jni_env_calls": []
}}

func_mgr = currentProgram.getFunctionManager()
symbol_table = currentProgram.getSymbolTable()

# Find JNI_OnLoad and JNI_OnUnload
for func in func_mgr.getFunctions(True):
    name = func.getName()
    if name == "JNI_OnLoad":
        results["jni_onload"] = {{
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature())
        }}

        # Optionally decompile JNI_OnLoad
        if {str(include_decompile).lower()}:
            try:
                decompiler = DecompInterface()
                decompiler.openProgram(currentProgram)
                decomp_results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
                if decomp_results.decompileCompleted():
                    results["jni_onload"]["code"] = decomp_results.getDecompiledFunction().getC()
            except:
                pass

    elif name == "JNI_OnUnload":
        results["jni_onunload"] = {{
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature())
        }}

    # Find Java_* methods (JNI native method exports)
    elif name.startswith("Java_"):
        # Parse the Java method signature from the name
        parts = name.split("_")
        if len(parts) >= 3:
            # Format: Java_package_class_method
            java_class = "_".join(parts[1:-1]).replace("_", ".")
            java_method = parts[-1]
            results["java_methods"].append({{
                "address": str(func.getEntryPoint()),
                "native_name": name,
                "java_class": java_class,
                "java_method": java_method,
                "signature": str(func.getSignature()),
                "size": func.getBody().getNumAddresses()
            }})

# Find RegisterNatives calls (dynamic JNI registration)
for func in func_mgr.getFunctions(True):
    name = func.getName().lower()
    if "registernatives" in name or "register_natives" in name:
        results["register_natives_calls"].append({{
            "address": str(func.getEntryPoint()),
            "name": func.getName()
        }})

# Find common JNI environment function references
jni_functions = [
    "FindClass", "GetMethodID", "GetStaticMethodID", "GetFieldID",
    "CallVoidMethod", "CallObjectMethod", "CallIntMethod", "CallBooleanMethod",
    "NewStringUTF", "GetStringUTFChars", "ReleaseStringUTFChars",
    "NewByteArray", "GetByteArrayElements", "ReleaseByteArrayElements",
    "GetEnv", "AttachCurrentThread", "DetachCurrentThread"
]

for jni_func in jni_functions:
    for symbol in symbol_table.getSymbols(jni_func):
        results["jni_env_calls"].append({{
            "name": jni_func,
            "address": str(symbol.getAddress())
        }})

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "results": results}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("AnalyzeJNI.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "AnalyzeJNI.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        data = result.get("results", {})
        text = f"# JNI Analysis: {binary_name}\n\n"

        # JNI_OnLoad
        if data.get("jni_onload"):
            jni = data["jni_onload"]
            text += f"## JNI_OnLoad\n"
            text += f"  Address: {jni['address']}\n"
            text += f"  Signature: {jni['signature']}\n"
            if jni.get("code"):
                text += f"\n```c\n{jni['code']}\n```\n"
            text += "\n"

        # JNI_OnUnload
        if data.get("jni_onunload"):
            jni = data["jni_onunload"]
            text += f"## JNI_OnUnload\n"
            text += f"  Address: {jni['address']}\n\n"

        # Java_* methods
        java_methods = data.get("java_methods", [])
        if java_methods:
            text += f"## Native Methods ({len(java_methods)})\n\n"
            text += "| Address | Java Class | Method | Size |\n"
            text += "|---------|------------|--------|------|\n"
            for m in java_methods[:50]:
                text += f"| {m['address']} | {m['java_class']} | {m['java_method']} | {m['size']} |\n"
            text += "\n"

        # RegisterNatives
        reg_natives = data.get("register_natives_calls", [])
        if reg_natives:
            text += f"## Dynamic Registration (RegisterNatives)\n"
            for r in reg_natives:
                text += f"  {r['address']}: {r['name']}\n"
            text += "\n"

        # JNI env calls
        jni_calls = data.get("jni_env_calls", [])
        if jni_calls:
            text += f"## JNI Environment Calls ({len(jni_calls)})\n"
            by_name = {}
            for c in jni_calls:
                if c['name'] not in by_name:
                    by_name[c['name']] = []
                by_name[c['name']].append(c['address'])
            for name, addrs in sorted(by_name.items()):
                text += f"  {name}: {len(addrs)} references\n"

        if not java_methods and not data.get("jni_onload"):
            text += "No JNI methods found. This may not be an Android native library.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_extract_api_endpoints(args: dict) -> Sequence[types.TextContent]:
    """Extract API endpoints and URLs from strings."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    include_paths = args.get("include_paths", True)

    script = f'''# @category MCP
# @runtime Jython
import json
import re

results = {{
    "urls": [],
    "hostnames": [],
    "ip_addresses": [],
    "paths": []
}}

# Patterns
url_pattern = re.compile(r'https?://[a-zA-Z0-9][a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+', re.IGNORECASE)
hostname_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+[a-zA-Z]{{2,}}')
ip_pattern = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)+(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
path_pattern = re.compile(r'/(?:api|v[0-9]+|rest|graphql|ws|wss)/[a-zA-Z0-9/_\-]+')

seen_urls = set()
seen_hosts = set()
seen_ips = set()
seen_paths = set()

data_mgr = currentProgram.getListing()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        val = str(data.getValue())
        addr = str(data.getAddress())

        # Find URLs
        for match in url_pattern.finditer(val):
            url = match.group(0)
            if url not in seen_urls:
                seen_urls.add(url)
                results["urls"].append({{
                    "address": addr,
                    "url": url
                }})

        # Find hostnames (not already in URLs)
        for match in hostname_pattern.finditer(val):
            hostname = match.group(0).lower()
            # Filter out common false positives
            if hostname not in seen_hosts and not hostname.endswith(('.so', '.dll', '.exe', '.png', '.jpg', '.xml', '.json')):
                if '.' in hostname and len(hostname) > 4:
                    seen_hosts.add(hostname)
                    results["hostnames"].append({{
                        "address": addr,
                        "hostname": hostname
                    }})

        # Find IP addresses
        for match in ip_pattern.finditer(val):
            ip = match.group(0)
            if ip not in seen_ips and not ip.startswith('0.') and not ip.startswith('255.'):
                seen_ips.add(ip)
                results["ip_addresses"].append({{
                    "address": addr,
                    "ip": ip
                }})

        # Find API paths
        if {str(include_paths).lower()}:
            for match in path_pattern.finditer(val):
                path = match.group(0)
                if path not in seen_paths:
                    seen_paths.add(path)
                    results["paths"].append({{
                        "address": addr,
                        "path": path
                    }})

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "results": results}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ExtractEndpoints.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ExtractEndpoints.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        data = result.get("results", {})
        text = f"# API Endpoints: {binary_name}\n\n"

        urls = data.get("urls", [])
        if urls:
            text += f"## URLs ({len(urls)})\n"
            for u in urls[:100]:
                text += f"  {u['address']}: {u['url']}\n"
            text += "\n"

        hosts = data.get("hostnames", [])
        if hosts:
            text += f"## Hostnames ({len(hosts)})\n"
            for h in hosts[:50]:
                text += f"  {h['address']}: {h['hostname']}\n"
            text += "\n"

        ips = data.get("ip_addresses", [])
        if ips:
            text += f"## IP Addresses ({len(ips)})\n"
            for ip in ips[:30]:
                text += f"  {ip['address']}: {ip['ip']}\n"
            text += "\n"

        paths = data.get("paths", [])
        if paths:
            text += f"## API Paths ({len(paths)})\n"
            for p in paths[:50]:
                text += f"  {p['address']}: {p['path']}\n"

        total = len(urls) + len(hosts) + len(ips) + len(paths)
        if total == 0:
            text += "No API endpoints found.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_find_hardcoded_secrets(args: dict) -> Sequence[types.TextContent]:
    """Find potential hardcoded secrets in strings."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    sensitivity = args.get("sensitivity", "medium")

    script = f'''# @category MCP
# @runtime Jython
import json
import re

sensitivity = "{sensitivity}"

results = {{
    "api_keys": [],
    "passwords": [],
    "tokens": [],
    "private_keys": [],
    "credentials": [],
    "base64_secrets": []
}}

# Patterns for different secret types
patterns = {{
    "aws_key": re.compile(r'AKIA[0-9A-Z]{{16}}'),
    "aws_secret": re.compile(r'[0-9a-zA-Z/+]{{40}}'),
    "google_api": re.compile(r'AIza[0-9A-Za-z\-_]{{35}}'),
    "firebase": re.compile(r'AAAA[A-Za-z0-9_-]{{7}}:[A-Za-z0-9_-]{{140}}'),
    "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{{36,}}'),
    "jwt": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "password_field": re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|auth_token|access_token)["\']?\s*[:=]\s*["\']([^"\'\\s]{{8,}})["\']', re.IGNORECASE),
    "bearer_token": re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    "basic_auth": re.compile(r'[Bb]asic\s+[A-Za-z0-9+/=]{{20,}}'),
    "hex_key": re.compile(r'["\'][0-9a-fA-F]{{32,64}}["\']'),
}}

# Additional patterns for medium/high sensitivity
if sensitivity in ["medium", "high"]:
    patterns["base64_long"] = re.compile(r'[A-Za-z0-9+/]{{40,}}={0,2}')
    patterns["connection_string"] = re.compile(r'(?:mongodb|mysql|postgres|redis|amqp)://[^\\s"\']+')

if sensitivity == "high":
    patterns["potential_secret"] = re.compile(r'(?:secret|key|token|password|credential|auth)[_-]?[A-Za-z0-9]{{0,20}}["\']?\s*[:=]\s*["\']?[^\\s"\'{{}}]{{6,}}', re.IGNORECASE)

data_mgr = currentProgram.getListing()
seen = set()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        val = str(data.getValue())
        addr = str(data.getAddress())

        # Skip short strings
        if len(val) < 8:
            continue

        # Check each pattern
        for pattern_name, pattern in patterns.items():
            for match in pattern.finditer(val):
                secret = match.group(0)
                if secret in seen:
                    continue
                seen.add(secret)

                entry = {{
                    "address": addr,
                    "pattern": pattern_name,
                    "value": secret[:100] + ("..." if len(secret) > 100 else ""),
                    "context": val[:200] if len(val) > len(secret) else ""
                }}

                # Categorize
                if pattern_name in ["aws_key", "aws_secret", "google_api", "firebase"]:
                    results["api_keys"].append(entry)
                elif pattern_name in ["password_field"]:
                    results["passwords"].append(entry)
                elif pattern_name in ["jwt", "bearer_token", "github_token", "basic_auth"]:
                    results["tokens"].append(entry)
                elif pattern_name == "private_key":
                    results["private_keys"].append(entry)
                elif pattern_name in ["connection_string", "hex_key"]:
                    results["credentials"].append(entry)
                elif pattern_name in ["base64_long", "potential_secret"]:
                    results["base64_secrets"].append(entry)

print("=== MCP_RESULT_JSON ===")
print(json.dumps({{"success": True, "results": results, "sensitivity": sensitivity}}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("FindSecrets.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "FindSecrets.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)

    if result.get("success"):
        data = result.get("results", {})
        sens = result.get("sensitivity", "medium")
        text = f"# Hardcoded Secrets: {binary_name}\n"
        text += f"**Sensitivity**: {sens}\n\n"

        total = 0

        api_keys = data.get("api_keys", [])
        if api_keys:
            text += f"## API Keys ({len(api_keys)})\n"
            for s in api_keys[:20]:
                text += f"  {s['address']}: [{s['pattern']}] {s['value']}\n"
            total += len(api_keys)
            text += "\n"

        passwords = data.get("passwords", [])
        if passwords:
            text += f"## Passwords ({len(passwords)})\n"
            for s in passwords[:20]:
                text += f"  {s['address']}: {s['value']}\n"
            total += len(passwords)
            text += "\n"

        tokens = data.get("tokens", [])
        if tokens:
            text += f"## Tokens ({len(tokens)})\n"
            for s in tokens[:20]:
                text += f"  {s['address']}: [{s['pattern']}] {s['value']}\n"
            total += len(tokens)
            text += "\n"

        private_keys = data.get("private_keys", [])
        if private_keys:
            text += f"## Private Keys ({len(private_keys)})\n"
            for s in private_keys[:10]:
                text += f"  {s['address']}: {s['value']}\n"
            total += len(private_keys)
            text += "\n"

        credentials = data.get("credentials", [])
        if credentials:
            text += f"## Credentials/Connection Strings ({len(credentials)})\n"
            for s in credentials[:20]:
                text += f"  {s['address']}: [{s['pattern']}] {s['value']}\n"
            total += len(credentials)
            text += "\n"

        base64 = data.get("base64_secrets", [])
        if base64:
            text += f"## Potential Base64 Secrets ({len(base64)})\n"
            for s in base64[:20]:
                text += f"  {s['address']}: {s['value']}\n"
            total += len(base64)

        if total == 0:
            text += "No hardcoded secrets detected.\n"
        else:
            text += f"\n**Total findings: {total}**\n"
            text += "\nNote: Review findings manually to confirm they are actual secrets.\n"

        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_compare_binaries(args: dict) -> Sequence[types.TextContent]:
    """Compare two binaries to find differences."""
    binary_name_a = args.get("binary_name_a")
    binary_name_b = args.get("binary_name_b")
    project_name = args.get("project_name", config.default_project)
    match_by = args.get("match_by", "name")

    # First, get functions from binary A
    script_a = '''# @category MCP
# @runtime Jython
import json

functions = {}
func_mgr = currentProgram.getFunctionManager()

for func in func_mgr.getFunctions(True):
    name = func.getName()
    addr = str(func.getEntryPoint())
    size = func.getBody().getNumAddresses()

    # Get function hash based on bytes
    body = func.getBody()
    byte_hash = 0
    memory = currentProgram.getMemory()
    try:
        for i in range(min(size, 64)):
            b = memory.getByte(body.getMinAddress().add(i)) & 0xFF
            byte_hash = (byte_hash * 31 + b) & 0xFFFFFFFF
    except:
        pass

    functions[name] = {
        "address": addr,
        "size": size,
        "hash": byte_hash
    }

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "functions": functions, "count": len(functions)}))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GetFunctions_A.py", script_a)

    project_path = config.get_project_path(project_name)

    # Get binary A functions
    stdout_a, stderr_a, code_a = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name_a,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetFunctions_A.py"
    ], timeout=config.decompile_timeout)

    result_a = parse_ghidra_json_output(stdout_a)
    if not result_a.get("success"):
        return [types.TextContent(type="text", text=f"Error analyzing {binary_name_a}: {result_a.get('error')}")]

    # Get binary B functions
    stdout_b, stderr_b, code_b = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", binary_name_b,
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GetFunctions_A.py"  # Reuse same script
    ], timeout=config.decompile_timeout)

    result_b = parse_ghidra_json_output(stdout_b)
    if not result_b.get("success"):
        return [types.TextContent(type="text", text=f"Error analyzing {binary_name_b}: {result_b.get('error')}")]

    # Compare
    funcs_a = result_a.get("functions", {})
    funcs_b = result_b.get("functions", {})

    names_a = set(funcs_a.keys())
    names_b = set(funcs_b.keys())

    added = names_b - names_a
    removed = names_a - names_b
    common = names_a & names_b

    modified = []
    unchanged = []

    for name in common:
        fa = funcs_a[name]
        fb = funcs_b[name]

        if match_by == "name":
            # Compare by hash and size
            if fa["hash"] != fb["hash"] or fa["size"] != fb["size"]:
                modified.append({
                    "name": name,
                    "old_addr": fa["address"],
                    "new_addr": fb["address"],
                    "old_size": fa["size"],
                    "new_size": fb["size"],
                    "size_delta": fb["size"] - fa["size"]
                })
            else:
                unchanged.append(name)
        else:
            # Match by address or both
            if fa["address"] == fb["address"]:
                if fa["hash"] != fb["hash"]:
                    modified.append({
                        "name": name,
                        "old_addr": fa["address"],
                        "new_addr": fb["address"],
                        "old_size": fa["size"],
                        "new_size": fb["size"],
                        "size_delta": fb["size"] - fa["size"]
                    })
                else:
                    unchanged.append(name)

    text = f"# Binary Comparison\n\n"
    text += f"**Base**: {binary_name_a} ({len(funcs_a)} functions)\n"
    text += f"**New**: {binary_name_b} ({len(funcs_b)} functions)\n"
    text += f"**Match by**: {match_by}\n\n"

    text += f"## Summary\n"
    text += f"- Added: {len(added)} functions\n"
    text += f"- Removed: {len(removed)} functions\n"
    text += f"- Modified: {len(modified)} functions\n"
    text += f"- Unchanged: {len(unchanged)} functions\n\n"

    if added:
        text += f"## Added Functions ({len(added)})\n"
        for name in sorted(list(added))[:50]:
            fb = funcs_b[name]
            text += f"  + {fb['address']}: {name} ({fb['size']} bytes)\n"
        if len(added) > 50:
            text += f"  ... and {len(added) - 50} more\n"
        text += "\n"

    if removed:
        text += f"## Removed Functions ({len(removed)})\n"
        for name in sorted(list(removed))[:50]:
            fa = funcs_a[name]
            text += f"  - {fa['address']}: {name} ({fa['size']} bytes)\n"
        if len(removed) > 50:
            text += f"  ... and {len(removed) - 50} more\n"
        text += "\n"

    if modified:
        text += f"## Modified Functions ({len(modified)})\n"
        # Sort by size delta
        modified.sort(key=lambda x: abs(x["size_delta"]), reverse=True)
        for m in modified[:50]:
            delta = m["size_delta"]
            delta_str = f"+{delta}" if delta > 0 else str(delta)
            text += f"  * {m['name']}: {m['old_size']} -> {m['new_size']} bytes ({delta_str})\n"
        if len(modified) > 50:
            text += f"  ... and {len(modified) - 50} more\n"

    return [types.TextContent(type="text", text=text)]


# ============================================================================
# Main Entry Point
# ============================================================================

async def main():
    """Run the MCP server."""
    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            print(f"Configuration error: {error}", file=sys.stderr)
        sys.exit(1)

    # Ensure directories exist
    config.ensure_directories()

    log(f"Starting Kawaiidra MCP Server")
    log(f"Ghidra home: {config.ghidra_home}")
    log(f"Project dir: {config.project_dir}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="kawaiidra",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
