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
from .cache import get_cache, clear_cache, get_cache_stats

# Import bridge backend for fast operations
try:
    from .bridge.backend import get_backend
    _backend_available = True
except ImportError:
    _backend_available = False
    def get_backend():
        return None


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


# Regex pattern for Ghidra index entries: "  XXXXXXXX:name:hash" (indented, 8 hex digits ID)
_GHIDRA_INDEX_ENTRY_PATTERN = re.compile(r'^\s+([0-9a-fA-F]{8}):([^:]+):([0-9a-fA-F]+)$')


def parse_ghidra_index(index_file: Path) -> list[dict[str, str]]:
    """Parse a Ghidra project index file and return binary entries.

    Args:
        index_file: Path to the ~index.dat file

    Returns:
        List of dicts with 'id', 'name', and 'hash' keys for each binary
    """
    entries = []

    if not index_file.exists():
        return entries

    try:
        content = index_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            match = _GHIDRA_INDEX_ENTRY_PATTERN.match(line)
            if match:
                entries.append({
                    'id': match.group(1),
                    'name': match.group(2),
                    'hash': match.group(3)
                })
    except Exception:
        pass

    return entries


def get_analyzed_binaries(project_name: Optional[str] = None) -> list[str]:
    """List binaries that have been analyzed in a project."""
    project_path = config.get_project_path(project_name)
    rep_dir = project_path / f"{project_name or config.default_project}.rep"

    if not rep_dir.exists():
        return []

    # Parse the index file to get actual binary names
    idata_dir = rep_dir / "idata"
    index_file = idata_dir / "~index.dat"

    entries = parse_ghidra_index(index_file)
    if entries:
        return [entry['name'] for entry in entries]

    # Fallback to directory listing if index parsing fails
    binaries = []
    if idata_dir.exists():
        for item in idata_dir.iterdir():
            if item.is_dir():
                binaries.append(item.name)

    return binaries


def binary_exists(binary_name: str, project_name: Optional[str] = None) -> bool:
    """Check if a binary exists in a project.

    Args:
        binary_name: Name of the binary to check
        project_name: Ghidra project name (uses default if None)

    Returns:
        True if the binary exists in the project
    """
    return binary_name in get_analyzed_binaries(project_name)


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

    # =========================================================================
    # Missing Tools from LaurieWired + Modification Tools
    # =========================================================================
    types.Tool(
        name="list_exports",
        description="List exported functions and symbols from the binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset (default: 0)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
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
        name="list_imports",
        description="List imported functions and symbols from external libraries.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset (default: 0)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
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
        name="list_data_items",
        description="List defined data labels and their values.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset (default: 0)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
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
        name="list_namespaces",
        description="List all namespaces and classes in the binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "offset": {
                    "type": "integer",
                    "description": "Pagination offset (default: 0)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 100)"
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
        name="rename_function",
        description="Rename a function in the binary analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "old_name": {
                    "type": "string",
                    "description": "Current function name or address (e.g., 'FUN_00401000' or '0x401000')"
                },
                "new_name": {
                    "type": "string",
                    "description": "New name for the function"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "old_name", "new_name"]
        }
    ),
    types.Tool(
        name="rename_data",
        description="Rename a data label at a specified address.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "address": {
                    "type": "string",
                    "description": "Address of the data label (e.g., '0x401000')"
                },
                "new_name": {
                    "type": "string",
                    "description": "New name for the data label"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "address", "new_name"]
        }
    ),
    types.Tool(
        name="rename_variable",
        description="Rename a local variable within a function.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Name or address of the function containing the variable"
                },
                "old_name": {
                    "type": "string",
                    "description": "Current variable name"
                },
                "new_name": {
                    "type": "string",
                    "description": "New name for the variable"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name", "old_name", "new_name"]
        }
    ),
    types.Tool(
        name="set_comment",
        description="Set a comment at a specified address (EOL, PRE, POST, or PLATE comment).",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "address": {
                    "type": "string",
                    "description": "Address to add comment (e.g., '0x401000')"
                },
                "comment": {
                    "type": "string",
                    "description": "Comment text to set"
                },
                "comment_type": {
                    "type": "string",
                    "enum": ["EOL", "PRE", "POST", "PLATE"],
                    "description": "Type of comment (default: 'EOL')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "address", "comment"]
        }
    ),
    types.Tool(
        name="set_function_prototype",
        description="Set a function's prototype/signature.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Name or address of the function"
                },
                "prototype": {
                    "type": "string",
                    "description": "New prototype (e.g., 'int myFunc(char *buf, int size)')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name", "prototype"]
        }
    ),
    types.Tool(
        name="set_local_variable_type",
        description="Set the type of a local variable within a function.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "function_name": {
                    "type": "string",
                    "description": "Name or address of the function"
                },
                "variable_name": {
                    "type": "string",
                    "description": "Name of the variable to retype"
                },
                "new_type": {
                    "type": "string",
                    "description": "New type for the variable (e.g., 'char *', 'int', 'struct MyStruct')"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name", "function_name", "variable_name", "new_type"]
        }
    ),

    # =========================================================================
    # Exhaustive Report Generator
    # =========================================================================
    types.Tool(
        name="generate_report",
        description="Generate an exhaustive, ground-truth binary analysis report. Extracts all available information in a single pass: metadata, symbols, functions, strings, vulnerabilities, behavioral patterns, and platform-specific analysis. Output is a comprehensive markdown report.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Name of the analyzed binary"
                },
                "depth": {
                    "type": "string",
                    "enum": ["quick", "standard", "full", "exhaustive"],
                    "description": "Analysis depth: quick (metadata+stats), standard (+ functions/strings), full (+ decompilation of key funcs), exhaustive (everything including behavioral analysis). Default: standard"
                },
                "include_decompilation": {
                    "type": "boolean",
                    "description": "Include decompiled code for top functions (default: true for full/exhaustive)"
                },
                "max_functions_decompile": {
                    "type": "integer",
                    "description": "Max functions to decompile (default: 20 for full, 50 for exhaustive)"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["markdown", "json"],
                    "description": "Output format (default: markdown)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Ghidra project name (default: 'default')"
                }
            },
            "required": ["binary_name"]
        }
    ),

    # =========================================================================
    # Cache Management Tools
    # =========================================================================
    types.Tool(
        name="cache_stats",
        description="Get cache statistics including hit rate, size, and entry count. Use this to monitor cache performance.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
        }
    ),
    types.Tool(
        name="cache_clear",
        description="Clear cached analysis results. Can clear all cache or filter by binary/project.",
        inputSchema={
            "type": "object",
            "properties": {
                "binary_name": {
                    "type": "string",
                    "description": "Clear cache only for this binary (optional)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Clear cache only for this project (optional)"
                }
            },
            "required": []
        }
    ),
    types.Tool(
        name="bridge_status",
        description="Get JPype bridge status. Shows if the fast bridge mode is active (100-1000x faster than subprocess) or if falling back to subprocess mode.",
        inputSchema={
            "type": "object",
            "properties": {},
            "required": []
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
        # LaurieWired-compatible tools + Modification tools
        elif name == "list_exports":
            return await handle_list_exports(arguments)
        elif name == "list_imports":
            return await handle_list_imports(arguments)
        elif name == "list_data_items":
            return await handle_list_data_items(arguments)
        elif name == "list_namespaces":
            return await handle_list_namespaces(arguments)
        elif name == "rename_function":
            return await handle_rename_function(arguments)
        elif name == "rename_data":
            return await handle_rename_data(arguments)
        elif name == "rename_variable":
            return await handle_rename_variable(arguments)
        elif name == "set_comment":
            return await handle_set_comment(arguments)
        elif name == "set_function_prototype":
            return await handle_set_function_prototype(arguments)
        elif name == "set_local_variable_type":
            return await handle_set_local_variable_type(arguments)
        # Exhaustive Report Generator
        elif name == "generate_report":
            return await handle_generate_report(arguments)
        # Cache Management
        elif name == "cache_stats":
            return await handle_cache_stats(arguments)
        elif name == "cache_clear":
            return await handle_cache_clear(arguments)
        # Bridge Status
        elif name == "bridge_status":
            return handle_bridge_status(arguments)
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

    # Check cache first
    cache = get_cache()
    cache_params = {"limit": limit}
    cached = cache.get("list_functions", binary_name, project_name, cache_params,
                       project_dir=config.get_project_path(project_name))
    if cached is not None:
        funcs = cached.get("functions", [])
        total = cached.get("total", len(funcs))
        text = f"Functions in {binary_name} ({len(funcs)}/{total} shown) [CACHED]:\n\n"
        for f in funcs:
            text += f"  {f['address']}: {f['name']} ({f.get('size', 0)} bytes)\n"
        return [types.TextContent(type="text", text=text)]

    # Try fast bridge path first
    backend = get_backend()
    if backend is not None:
        result = backend.list_functions(binary_name, project_name, limit)
        if result is not None and result.get("success"):
            funcs = result.get("functions", [])
            total = result.get("total", len(funcs))

            # Cache the result
            cache.set("list_functions", binary_name, project_name, cache_params,
                      {"functions": funcs, "total": total},
                      project_dir=config.get_project_path(project_name))

            text = f"Functions in {binary_name} ({len(funcs)}/{total} shown) [BRIDGE]:\n\n"
            for f in funcs:
                text += f"  {f['address']}: {f['name']} ({f.get('size', 0)} bytes)\n"
            return [types.TextContent(type="text", text=text)]

    # Fall back to subprocess
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

        # Cache the result
        cache.set("list_functions", binary_name, project_name, cache_params,
                  {"functions": funcs, "total": total},
                  project_dir=config.get_project_path(project_name))

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

    # Check cache first
    cache = get_cache()
    cache_params = {"function_name": function_name}
    cached = cache.get("get_function_decompile", binary_name, project_name, cache_params,
                       project_dir=config.get_project_path(project_name))
    if cached is not None:
        text = f"Decompiled {cached['function']} @ {cached['address']} [CACHED]:\n\n"
        text += f"Signature: {cached['signature']}\n\n"
        text += f"```c\n{cached['code']}\n```"
        return [types.TextContent(type="text", text=text)]

    # Try fast bridge path first
    backend = get_backend()
    if backend is not None:
        result = backend.decompile(binary_name, project_name, function_name)
        if result is not None:
            if result.get("success"):
                # Cache the result
                cache.set("get_function_decompile", binary_name, project_name, cache_params,
                          {"function": result['function_name'], "address": result['address'],
                           "signature": result['signature'], "code": result['code']},
                          project_dir=config.get_project_path(project_name))

                text = f"Decompiled {result['function_name']} @ {result['address']} [BRIDGE]:\n\n"
                text += f"Signature: {result['signature']}\n\n"
                text += f"```c\n{result['code']}\n```"
                return [types.TextContent(type="text", text=text)]
            else:
                return [types.TextContent(type="text", text=f"Decompilation failed: {result.get('error', 'Unknown error')}")]

    # Fall back to subprocess
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
        # Cache the result
        cache.set("get_function_decompile", binary_name, project_name, cache_params,
                  {"function": result['function'], "address": result['address'],
                   "signature": result['signature'], "code": result['code']},
                  project_dir=config.get_project_path(project_name))

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

    # Check cache first
    cache = get_cache()
    cache_params = {"min_length": min_length, "limit": limit}
    cached = cache.get("list_strings", binary_name, project_name, cache_params,
                       project_dir=config.get_project_path(project_name))
    if cached is not None:
        strings = cached.get("strings", [])
        text = f"Strings in {binary_name} ({len(strings)} shown) [CACHED]:\n\n"
        for s in strings:
            text += f"  {s['address']}: {s['value']}\n"
        return [types.TextContent(type="text", text=text)]

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

        # Cache the result
        cache.set("list_strings", binary_name, project_name, cache_params,
                  {"strings": strings},
                  project_dir=config.get_project_path(project_name))

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
                "reason": "Calls " + common_hint + "-related APIs"
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
# LaurieWired-compatible Tools + Modification Tools
# ============================================================================

async def handle_list_exports(args: dict) -> Sequence[types.TextContent]:
    """List exported functions and symbols."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    offset = args.get("offset", 0)
    limit = args.get("limit", 100)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {{"success": True, "exports": [], "total": 0}}

try:
    symbol_table = currentProgram.getSymbolTable()
    exports = []
    count = 0

    for symbol in symbol_table.getAllSymbols(True):
        # Check if symbol is exported (external entry point or has GLOBAL scope)
        if symbol.isExternalEntryPoint() or (symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isGlobal()):
            if count >= {offset} and len(exports) < {limit}:
                exports.append({{
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType()),
                    "namespace": str(symbol.getParentNamespace().getName())
                }})
            count += 1

    result["exports"] = exports
    result["total"] = count
except Exception as e:
    result = {{"success": False, "error": str(e)}}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListExports.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListExports.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        exports = result.get("exports", [])
        total = result.get("total", 0)
        text = f"# Exports ({len(exports)} of {total})\n\n"
        for exp in exports:
            text += f"- {exp['name']} @ {exp['address']} [{exp['type']}]\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_list_imports(args: dict) -> Sequence[types.TextContent]:
    """List imported functions and symbols."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    offset = args.get("offset", 0)
    limit = args.get("limit", 100)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {{"success": True, "imports": [], "total": 0}}

try:
    symbol_table = currentProgram.getSymbolTable()
    ext_manager = currentProgram.getExternalManager()
    imports = []
    count = 0

    # Get external symbols (imports)
    for symbol in symbol_table.getExternalSymbols():
        if count >= {offset} and len(imports) < {limit}:
            ext_loc = symbol.getExternalLocation() if hasattr(symbol, 'getExternalLocation') else None
            library = ""
            if ext_loc:
                library = str(ext_loc.getLibraryName()) if ext_loc.getLibraryName() else ""
            imports.append({{
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "library": library,
                "type": str(symbol.getSymbolType())
            }})
        count += 1

    result["imports"] = imports
    result["total"] = count
except Exception as e:
    result = {{"success": False, "error": str(e)}}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListImports.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListImports.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        imports = result.get("imports", [])
        total = result.get("total", 0)
        text = f"# Imports ({len(imports)} of {total})\n\n"
        for imp in imports:
            lib = f" from {imp['library']}" if imp.get('library') else ""
            text += f"- {imp['name']}{lib} @ {imp['address']}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_list_data_items(args: dict) -> Sequence[types.TextContent]:
    """List defined data labels and their values."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    offset = args.get("offset", 0)
    limit = args.get("limit", 100)

    script = f'''# @category MCP
# @runtime Jython
import json

result = {{"success": True, "data_items": [], "total": 0}}

try:
    listing = currentProgram.getListing()
    data_items = []
    count = 0

    for data in listing.getDefinedData(True):
        if count >= {offset} and len(data_items) < {limit}:
            value_repr = ""
            try:
                val = data.getValue()
                if val is not None:
                    value_repr = str(val)[:100]  # Limit value string length
            except:
                pass

            data_items.append({{
                "address": str(data.getAddress()),
                "label": str(data.getLabel()) if data.getLabel() else "",
                "type": str(data.getDataType().getName()),
                "size": data.getLength(),
                "value": value_repr
            }})
        count += 1

    result["data_items"] = data_items
    result["total"] = count
except Exception as e:
    result = {{"success": False, "error": str(e)}}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListDataItems.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListDataItems.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        items = result.get("data_items", [])
        total = result.get("total", 0)
        text = f"# Data Items ({len(items)} of {total})\n\n"
        for item in items:
            label = item['label'] if item['label'] else "(unnamed)"
            value = f" = {item['value']}" if item['value'] else ""
            text += f"- {label} @ {item['address']} : {item['type']} ({item['size']} bytes){value}\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_list_namespaces(args: dict) -> Sequence[types.TextContent]:
    """List all namespaces and classes."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    offset = args.get("offset", 0)
    limit = args.get("limit", 100)

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {{"success": True, "namespaces": [], "total": 0}}

try:
    symbol_table = currentProgram.getSymbolTable()
    namespaces = []
    count = 0
    seen = set()

    # Get all namespaces
    for symbol in symbol_table.getAllSymbols(True):
        ns = symbol.getParentNamespace()
        while ns and not ns.isGlobal():
            ns_name = ns.getName(True)  # Full path
            if ns_name not in seen:
                seen.add(ns_name)
                if count >= {offset} and len(namespaces) < {limit}:
                    ns_type = "Class" if hasattr(ns, 'getSymbol') and ns.getSymbol() and "class" in str(ns.getSymbol().getSymbolType()).lower() else "Namespace"
                    namespaces.append({{
                        "name": ns.getName(),
                        "full_path": ns_name,
                        "type": ns_type,
                        "symbol_count": len(list(symbol_table.getSymbols(ns)))
                    }})
                count += 1
            ns = ns.getParentNamespace()

    result["namespaces"] = namespaces
    result["total"] = count
except Exception as e:
    result = {{"success": False, "error": str(e)}}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("ListNamespaces.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "ListNamespaces.py"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        namespaces = result.get("namespaces", [])
        total = result.get("total", 0)
        text = f"# Namespaces ({len(namespaces)} of {total})\n\n"
        for ns in namespaces:
            text += f"- {ns['full_path']} [{ns['type']}] ({ns['symbol_count']} symbols)\n"
        return [types.TextContent(type="text", text=text)]
    else:
        return [types.TextContent(type="text", text=f"Error: {result.get('error', 'Unknown error')}")]


async def handle_rename_function(args: dict) -> Sequence[types.TextContent]:
    """Rename a function in the binary."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    old_name = args.get("old_name")
    new_name = args.get("new_name")

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType

result = {{"success": False, "message": ""}}

try:
    func = None
    old_name = "{old_name}"
    new_name = "{new_name}"

    # Try to find by name first
    func_manager = currentProgram.getFunctionManager()
    for f in func_manager.getFunctions(True):
        if f.getName() == old_name:
            func = f
            break

    # If not found, try as address
    if func is None and old_name.startswith("0x"):
        addr = currentProgram.getAddressFactory().getAddress(old_name)
        func = func_manager.getFunctionAt(addr)

    if func:
        old_func_name = func.getName()
        func.setName(new_name, SourceType.USER_DEFINED)
        result["success"] = True
        result["message"] = "Renamed '{{}}' to '{{}}'".format(old_func_name, new_name)
        result["address"] = str(func.getEntryPoint())
    else:
        result["message"] = "Function not found: " + old_name
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("RenameFunction.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "RenameFunction.py",
        "-save"  # Save changes
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')} @ {result.get('address', '')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


async def handle_rename_data(args: dict) -> Sequence[types.TextContent]:
    """Rename a data label at a specified address."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    address = args.get("address")
    new_name = args.get("new_name")

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType

result = {{"success": False, "message": ""}}

try:
    addr_str = "{address}"
    new_name = "{new_name}"

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        symbol_table = currentProgram.getSymbolTable()

        # Get existing symbol or create new one
        symbol = symbol_table.getPrimarySymbol(addr)
        if symbol:
            old_name = symbol.getName()
            symbol.setName(new_name, SourceType.USER_DEFINED)
            result["success"] = True
            result["message"] = "Renamed '{{}}' to '{{}}'".format(old_name, new_name)
        else:
            # Create new label
            symbol_table.createLabel(addr, new_name, SourceType.USER_DEFINED)
            result["success"] = True
            result["message"] = "Created label '{{}}' at {{}}".format(new_name, addr_str)

        result["address"] = addr_str
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("RenameData.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "RenameData.py",
        "-save"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


async def handle_rename_variable(args: dict) -> Sequence[types.TextContent]:
    """Rename a local variable within a function."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    function_name = args.get("function_name")
    old_name = args.get("old_name")
    new_name = args.get("new_name")

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

result = {{"success": False, "message": ""}}

try:
    func_name = "{function_name}"
    old_var_name = "{old_name}"
    new_var_name = "{new_name}"

    # Find function
    func = None
    func_manager = currentProgram.getFunctionManager()
    for f in func_manager.getFunctions(True):
        if f.getName() == func_name:
            func = f
            break

    if func is None and func_name.startswith("0x"):
        addr = currentProgram.getAddressFactory().getAddress(func_name)
        func = func_manager.getFunctionAt(addr)

    if func is None:
        result["message"] = "Function not found: " + func_name
    else:
        # Find and rename variable
        found = False
        for var in func.getAllVariables():
            if var.getName() == old_var_name:
                var.setName(new_var_name, SourceType.USER_DEFINED)
                result["success"] = True
                result["message"] = "Renamed variable '{{}}' to '{{}}' in function '{{}}'".format(old_var_name, new_var_name, func.getName())
                found = True
                break

        if not found:
            result["message"] = "Variable '{{}}' not found in function '{{}}'".format(old_var_name, func.getName())
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("RenameVariable.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "RenameVariable.py",
        "-save"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


async def handle_set_comment(args: dict) -> Sequence[types.TextContent]:
    """Set a comment at a specified address."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    address = args.get("address")
    comment = args.get("comment", "").replace('"', '\\"').replace('\n', '\\n')
    comment_type = args.get("comment_type", "EOL")

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.listing import CodeUnit

result = {{"success": False, "message": ""}}

try:
    addr_str = "{address}"
    comment_text = "{comment}"
    comment_type = "{comment_type}"

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        listing = currentProgram.getListing()
        code_unit = listing.getCodeUnitAt(addr)

        if code_unit is None:
            result["message"] = "No code unit at address: " + addr_str
        else:
            # Map comment type
            type_map = {{
                "EOL": CodeUnit.EOL_COMMENT,
                "PRE": CodeUnit.PRE_COMMENT,
                "POST": CodeUnit.POST_COMMENT,
                "PLATE": CodeUnit.PLATE_COMMENT
            }}
            ct = type_map.get(comment_type, CodeUnit.EOL_COMMENT)

            code_unit.setComment(ct, comment_text)
            result["success"] = True
            result["message"] = "Set {{}} comment at {{}}".format(comment_type, addr_str)
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SetComment.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SetComment.py",
        "-save"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


async def handle_set_function_prototype(args: dict) -> Sequence[types.TextContent]:
    """Set a function's prototype/signature."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    function_name = args.get("function_name")
    prototype = args.get("prototype", "").replace('"', '\\"')

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.program.model.symbol import SourceType

result = {{"success": False, "message": ""}}

try:
    func_name = "{function_name}"
    prototype_str = "{prototype}"

    # Find function
    func = None
    func_manager = currentProgram.getFunctionManager()
    for f in func_manager.getFunctions(True):
        if f.getName() == func_name:
            func = f
            break

    if func is None and func_name.startswith("0x"):
        addr = currentProgram.getAddressFactory().getAddress(func_name)
        func = func_manager.getFunctionAt(addr)

    if func is None:
        result["message"] = "Function not found: " + func_name
    else:
        # Parse and apply signature
        dtm = currentProgram.getDataTypeManager()
        parser = FunctionSignatureParser(dtm, None)
        try:
            sig = parser.parse(func.getSignature(), prototype_str)
            cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(), sig, SourceType.USER_DEFINED)
            cmd.applyTo(currentProgram)
            result["success"] = True
            result["message"] = "Applied prototype to function '{{}}': {{}}".format(func.getName(), prototype_str)
        except Exception as parse_error:
            result["message"] = "Failed to parse prototype: " + str(parse_error)
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SetFunctionPrototype.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SetFunctionPrototype.py",
        "-save"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


async def handle_set_local_variable_type(args: dict) -> Sequence[types.TextContent]:
    """Set the type of a local variable within a function."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    function_name = args.get("function_name")
    variable_name = args.get("variable_name")
    new_type = args.get("new_type", "").replace('"', '\\"')

    script = f'''# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType
from ghidra.app.util.cparser.C import CParser

result = {{"success": False, "message": ""}}

try:
    func_name = "{function_name}"
    var_name = "{variable_name}"
    type_str = "{new_type}"

    # Find function
    func = None
    func_manager = currentProgram.getFunctionManager()
    for f in func_manager.getFunctions(True):
        if f.getName() == func_name:
            func = f
            break

    if func is None and func_name.startswith("0x"):
        addr = currentProgram.getAddressFactory().getAddress(func_name)
        func = func_manager.getFunctionAt(addr)

    if func is None:
        result["message"] = "Function not found: " + func_name
    else:
        # Parse the type
        dtm = currentProgram.getDataTypeManager()

        # Try to find existing type first
        data_type = None
        for dt in dtm.getAllDataTypes():
            if dt.getName() == type_str or str(dt) == type_str:
                data_type = dt
                break

        # If not found, try parsing as C type
        if data_type is None:
            try:
                parser = CParser(dtm)
                data_type = parser.parse(type_str + " x;").getDataTypes()[0]
            except:
                # Try built-in types
                from ghidra.program.model.data import IntegerDataType, CharDataType, PointerDataType
                builtin = {{"int": IntegerDataType.dataType, "char": CharDataType.dataType}}
                data_type = builtin.get(type_str.replace("*", "").strip())
                if data_type and "*" in type_str:
                    data_type = PointerDataType(data_type)

        if data_type is None:
            result["message"] = "Could not parse type: " + type_str
        else:
            # Find and retype variable
            found = False
            for var in func.getAllVariables():
                if var.getName() == var_name:
                    var.setDataType(data_type, SourceType.USER_DEFINED)
                    result["success"] = True
                    result["message"] = "Set type of '{{}}' to '{{}}' in function '{{}}'".format(var_name, type_str, func.getName())
                    found = True
                    break

            if not found:
                result["message"] = "Variable '{{}}' not found in function '{{}}'".format(var_name, func.getName())
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("SetLocalVariableType.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "SetLocalVariableType.py",
        "-save"
    ], timeout=config.decompile_timeout)

    result = parse_ghidra_json_output(stdout)
    if result.get("success"):
        return [types.TextContent(type="text", text=f"✓ {result.get('message')}")]
    else:
        return [types.TextContent(type="text", text=f"✗ {result.get('message', 'Unknown error')}")]


# ============================================================================
# Exhaustive Report Generator
# ============================================================================

async def handle_generate_report(args: dict) -> Sequence[types.TextContent]:
    """Generate an exhaustive, ground-truth binary analysis report."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name", config.default_project)
    depth = args.get("depth", "standard")
    output_format = args.get("output_format", "markdown")
    include_decompilation = args.get("include_decompilation")
    max_functions_decompile = args.get("max_functions_decompile")

    # Check cache first
    cache = get_cache()
    cache_params = {
        "depth": depth,
        "output_format": output_format,
        "include_decompilation": include_decompilation,
        "max_functions_decompile": max_functions_decompile
    }
    cached = cache.get("generate_report", binary_name, project_name, cache_params,
                       project_dir=config.get_project_path(project_name))
    if cached is not None:
        cached_text = cached.get("text", "")
        # Add cache indicator
        if output_format == "markdown" and cached_text.startswith("#"):
            cached_text = cached_text.replace("# Binary Analysis Report", "# Binary Analysis Report [CACHED]", 1)
        return [types.TextContent(type="text", text=cached_text)]

    # Set defaults based on depth
    if include_decompilation is None:
        include_decompilation = depth in ("full", "exhaustive")
    if max_functions_decompile is None:
        max_functions_decompile = {"quick": 0, "standard": 5, "full": 20, "exhaustive": 50}.get(depth, 5)

    script = f'''# @category MCP
# @runtime Jython
import json
import re
from datetime import datetime
from collections import defaultdict

# Import Ghidra classes
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface

depth = "{depth}"
include_decompilation = {str(include_decompilation).lower() == "true" or include_decompilation == True}
max_functions_decompile = {max_functions_decompile}

report = {{
    "meta": {{}},
    "binary_info": {{}},
    "memory_layout": [],
    "symbols": {{"exports": [], "imports": [], "namespaces": []}},
    "functions": {{"total": 0, "list": [], "entry_points": [], "by_size": [], "most_referenced": []}},
    "strings": {{"total": 0, "interesting": [], "urls": [], "paths": [], "ips": [], "samples": []}},
    "data_items": [],
    "libraries": [],
    "behavioral": {{"file_io": [], "network": [], "crypto": [], "process": [], "memory": []}},
    "vulnerabilities": [],
    "decompiled_functions": [],
    "call_graph": {{}},
    "ios_analysis": {{}},
    "recommendations": []
}}

try:
    program = currentProgram
    listing = program.getListing()
    func_manager = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    memory = program.getMemory()
    ref_manager = program.getReferenceManager()

    # =========================================================================
    # 1. METADATA
    # =========================================================================
    report["meta"]["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report["meta"]["depth"] = depth
    report["meta"]["analyzer"] = "Kawaiidra MCP"

    # =========================================================================
    # 2. BINARY INFO
    # =========================================================================
    lang = program.getLanguage()
    report["binary_info"] = {{
        "name": program.getName(),
        "path": str(program.getExecutablePath()),
        "format": str(program.getExecutableFormat()),
        "language": str(lang.getLanguageID()),
        "processor": str(lang.getProcessor()),
        "endian": str(lang.isBigEndian() and "big" or "little"),
        "address_size": lang.getLanguageDescription().getSize(),
        "compiler": str(program.getCompiler()) if program.getCompiler() else "unknown",
        "image_base": str(program.getImageBase()),
        "min_address": str(program.getMinAddress()),
        "max_address": str(program.getMaxAddress()),
        "creation_date": str(program.getCreationDate()) if program.getCreationDate() else None,
        "md5": str(program.getExecutableMD5()) if hasattr(program, 'getExecutableMD5') and program.getExecutableMD5() else None,
        "sha256": str(program.getExecutableSHA256()) if hasattr(program, 'getExecutableSHA256') and program.getExecutableSHA256() else None
    }}

    # =========================================================================
    # 3. MEMORY LAYOUT
    # =========================================================================
    for block in memory.getBlocks():
        perms = ""
        if block.isRead(): perms += "R"
        if block.isWrite(): perms += "W"
        if block.isExecute(): perms += "X"
        report["memory_layout"].append({{
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": perms,
            "type": str(block.getType()),
            "initialized": block.isInitialized()
        }})

    # =========================================================================
    # 4. SYMBOLS - EXPORTS
    # =========================================================================
    export_count = 0
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint() or (symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isGlobal()):
            if export_count < 200:  # Limit for report size
                report["symbols"]["exports"].append({{
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType())
                }})
            export_count += 1

    # =========================================================================
    # 5. SYMBOLS - IMPORTS
    # =========================================================================
    import_count = 0
    import_libs = defaultdict(list)
    for symbol in symbol_table.getExternalSymbols():
        try:
            ext_loc = symbol.getExternalLocation() if hasattr(symbol, 'getExternalLocation') else None
            lib = str(ext_loc.getLibraryName()) if ext_loc and ext_loc.getLibraryName() else "unknown"
            import_libs[lib].append(symbol.getName())
            if import_count < 300:
                report["symbols"]["imports"].append({{
                    "name": symbol.getName(),
                    "library": lib,
                    "address": str(symbol.getAddress())
                }})
            import_count += 1
        except:
            pass

    # =========================================================================
    # 6. NAMESPACES
    # =========================================================================
    seen_ns = set()
    ns_count = 0
    for symbol in symbol_table.getAllSymbols(True):
        ns = symbol.getParentNamespace()
        while ns and not ns.isGlobal():
            ns_name = ns.getName(True)
            if ns_name not in seen_ns:
                seen_ns.add(ns_name)
                if ns_count < 100:
                    report["symbols"]["namespaces"].append({{
                        "name": ns.getName(),
                        "full_path": ns_name
                    }})
                ns_count += 1
            ns = ns.getParentNamespace()

    # =========================================================================
    # 7. FUNCTIONS ANALYSIS
    # =========================================================================
    functions_data = []
    func_refs = {{}}  # Track references to each function

    for func in func_manager.getFunctions(True):
        addr = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        # Count incoming references
        ref_count = 0
        for ref in ref_manager.getReferencesTo(addr):
            ref_count += 1
        func_refs[func.getName()] = ref_count

        func_data = {{
            "name": func.getName(),
            "address": str(addr),
            "size": size,
            "param_count": func.getParameterCount(),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "calling_convention": str(func.getCallingConventionName()),
            "ref_count": ref_count
        }}

        if func.isExternal():
            continue

        functions_data.append(func_data)

        if func.getName() in ["main", "_main", "entry", "_start", "WinMain", "DllMain"]:
            report["functions"]["entry_points"].append(func_data)

    report["functions"]["total"] = len(functions_data)
    report["functions"]["list"] = functions_data[:100]  # Top 100

    # Sort by size (largest functions)
    by_size = sorted(functions_data, key=lambda x: x["size"], reverse=True)[:20]
    report["functions"]["by_size"] = by_size

    # Sort by reference count (most called)
    by_refs = sorted(functions_data, key=lambda x: x["ref_count"], reverse=True)[:20]
    report["functions"]["most_referenced"] = by_refs

    # =========================================================================
    # 8. STRINGS ANALYSIS
    # =========================================================================
    strings_data = []
    interesting_patterns = {{
        "urls": re.compile(r'https?://[^\s<>"{{}}|\\\\^`\\[\\]]+', re.I),
        "ips": re.compile(r'\\b(?:\\d{{1,3}}\\.?){{4}}\\b'),
        "paths": re.compile(r'[A-Za-z]:\\\\[^\\s]+|/(?:usr|etc|var|home|tmp|bin|opt)/[^\\s]+'),
        "emails": re.compile(r'[\\w.-]+@[\\w.-]+\\.\\w+'),
        "potential_secrets": re.compile(r'(?:password|passwd|pwd|secret|key|token|api_key|apikey|auth)[\\s]*[=:][\\s]*[^\\s]+', re.I)
    }}

    string_count = 0
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            try:
                val = str(data.getValue())
                if len(val) >= 4:
                    str_entry = {{
                        "address": str(data.getAddress()),
                        "value": val[:200],  # Truncate long strings
                        "length": len(val)
                    }}

                    # Check for interesting patterns
                    for pattern_name, pattern in interesting_patterns.items():
                        if pattern.search(val):
                            if pattern_name == "urls":
                                report["strings"]["urls"].append(val[:200])
                            elif pattern_name == "ips":
                                report["strings"]["ips"].append(val[:50])
                            elif pattern_name == "paths":
                                report["strings"]["paths"].append(val[:200])
                            str_entry["interesting"] = True
                            if len(report["strings"]["interesting"]) < 100:
                                report["strings"]["interesting"].append(str_entry)

                    if string_count < 200:
                        strings_data.append(str_entry)
                    string_count += 1
            except:
                pass

    report["strings"]["total"] = string_count
    report["strings"]["samples"] = strings_data[:100]

    # =========================================================================
    # 9. BEHAVIORAL ANALYSIS (for standard+ depth)
    # =========================================================================
    if depth in ["standard", "full", "exhaustive"]:
        behavioral_patterns = {{
            "file_io": ["fopen", "fread", "fwrite", "fclose", "open", "read", "write", "close",
                       "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "CopyFile"],
            "network": ["socket", "connect", "send", "recv", "bind", "listen", "accept",
                       "WSAStartup", "gethostbyname", "inet_addr", "getaddrinfo"],
            "crypto": ["crypt", "encrypt", "decrypt", "hash", "md5", "sha1", "sha256", "aes",
                      "EVP_", "SSL_", "CRYPTO_", "BCrypt"],
            "process": ["fork", "exec", "system", "popen", "CreateProcess", "ShellExecute",
                       "WinExec", "spawn", "posix_spawn"],
            "memory": ["malloc", "calloc", "realloc", "free", "mmap", "VirtualAlloc",
                      "HeapAlloc", "HeapFree"]
        }}

        for category, patterns in behavioral_patterns.items():
            for func in func_manager.getFunctions(True):
                func_name = func.getName().lower()
                for pattern in patterns:
                    if pattern.lower() in func_name:
                        report["behavioral"][category].append({{
                            "function": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "pattern": pattern
                        }})
                        break

    # =========================================================================
    # 10. LIBRARY DETECTION
    # =========================================================================
    lib_signatures = {{
        "OpenSSL": ["SSL_", "EVP_", "CRYPTO_", "BIO_", "X509_"],
        "zlib": ["inflate", "deflate", "compress", "uncompress", "gzopen"],
        "libcurl": ["curl_easy_", "curl_multi_", "CURLOPT_"],
        "SQLite": ["sqlite3_open", "sqlite3_exec", "sqlite3_prepare"],
        "Qt": ["Q_OBJECT", "QWidget", "QString", "QApplication"],
        "Boost": ["boost::", "_ZN5boost"],
        "Windows API": ["kernel32", "ntdll", "user32", "advapi32"],
        "CRT": ["printf", "scanf", "malloc", "free", "strcpy", "strlen"]
    }}

    detected_libs = defaultdict(list)
    for lib_name, signatures in lib_signatures.items():
        for sig in signatures:
            for symbol in symbol_table.getAllSymbols(True):
                if sig.lower() in symbol.getName().lower():
                    detected_libs[lib_name].append(symbol.getName())
                    if len(detected_libs[lib_name]) >= 3:
                        break
            if len(detected_libs[lib_name]) >= 3:
                break

    for lib_name, matches in detected_libs.items():
        report["libraries"].append({{
            "name": lib_name,
            "confidence": "high" if len(matches) >= 3 else "medium",
            "evidence": matches[:5]
        }})

    # =========================================================================
    # 11. VULNERABILITY DETECTION
    # =========================================================================
    vuln_patterns = {{
        "buffer_overflow": {{
            "functions": ["strcpy", "strcat", "sprintf", "gets", "scanf"],
            "severity": "high",
            "cwe": "CWE-120"
        }},
        "format_string": {{
            "functions": ["printf", "sprintf", "fprintf", "syslog"],
            "severity": "high",
            "cwe": "CWE-134"
        }},
        "command_injection": {{
            "functions": ["system", "popen", "exec", "ShellExecute", "WinExec"],
            "severity": "critical",
            "cwe": "CWE-78"
        }},
        "memory_corruption": {{
            "functions": ["memcpy", "memmove", "memset"],
            "severity": "medium",
            "cwe": "CWE-119"
        }},
        "use_after_free": {{
            "functions": ["free", "delete", "HeapFree"],
            "severity": "high",
            "cwe": "CWE-416"
        }}
    }}

    for vuln_type, vuln_info in vuln_patterns.items():
        for func in func_manager.getFunctions(True):
            func_name = func.getName().lower()
            for dangerous_func in vuln_info["functions"]:
                if dangerous_func.lower() == func_name or func_name.endswith("_" + dangerous_func.lower()):
                    # Count callers to assess risk
                    caller_count = 0
                    for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
                        caller_count += 1

                    report["vulnerabilities"].append({{
                        "type": vuln_type,
                        "function": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "severity": vuln_info["severity"],
                        "cwe": vuln_info["cwe"],
                        "caller_count": caller_count,
                        "description": "Usage of potentially dangerous function"
                    }})
                    break

    # =========================================================================
    # 12. DECOMPILATION (for full/exhaustive depth)
    # =========================================================================
    if include_decompilation and max_functions_decompile > 0:
        decomp = DecompInterface()
        decomp.openProgram(program)

        # Prioritize: entry points, most referenced, largest
        priority_funcs = []
        priority_funcs.extend([f["name"] for f in report["functions"]["entry_points"]])
        priority_funcs.extend([f["name"] for f in report["functions"]["most_referenced"][:10]])
        priority_funcs.extend([f["name"] for f in report["functions"]["by_size"][:10]])

        # Remove duplicates while preserving order
        seen = set()
        unique_priority = []
        for f in priority_funcs:
            if f not in seen:
                seen.add(f)
                unique_priority.append(f)

        decompiled_count = 0
        for func_name in unique_priority[:max_functions_decompile]:
            func = None
            for f in func_manager.getFunctions(True):
                if f.getName() == func_name:
                    func = f
                    break

            if func and not func.isExternal():
                try:
                    results = decomp.decompileFunction(func, 60, None)
                    if results and results.decompileCompleted():
                        decomp_func = results.getDecompiledFunction()
                        if decomp_func:
                            code = decomp_func.getC()
                            if code:
                                report["decompiled_functions"].append({{
                                    "name": func_name,
                                    "address": str(func.getEntryPoint()),
                                    "code": code[:5000]  # Limit size
                                }})
                                decompiled_count += 1
                except:
                    pass

        decomp.dispose()

    # =========================================================================
    # 13. iOS/macOS SPECIFIC ANALYSIS (for exhaustive depth)
    # =========================================================================
    if depth == "exhaustive":
        arch = str(lang.getProcessor()).lower()
        if "aarch64" in arch or "arm" in arch:
            ios_markers = {{
                "entitlements": ["SecTask", "entitlement", "amfi", "AppleMobileFileIntegrity"],
                "sandbox": ["sandbox_check", "sandbox_init", "sandbox_extension"],
                "mach_ports": ["mach_port", "mach_msg", "task_for_pid", "thread_create"],
                "kpp_ktrr": ["kpp", "ktrr", "ppl_", "amcc", "__TEXT_EXEC"]
            }}

            for category, markers in ios_markers.items():
                for marker in markers:
                    for symbol in symbol_table.getAllSymbols(True):
                        if marker.lower() in symbol.getName().lower():
                            if category not in report["ios_analysis"]:
                                report["ios_analysis"][category] = []
                            report["ios_analysis"][category].append({{
                                "symbol": symbol.getName(),
                                "address": str(symbol.getAddress())
                            }})

    # =========================================================================
    # 14. RECOMMENDATIONS
    # =========================================================================
    # Suggest renames for auto-generated function names
    for func_data in report["functions"]["most_referenced"][:10]:
        if func_data["name"].startswith("FUN_") or func_data["name"].startswith("sub_"):
            report["recommendations"].append({{
                "type": "rename_suggestion",
                "target": func_data["name"],
                "address": func_data["address"],
                "reason": "High-traffic function with auto-generated name should be analyzed and renamed"
            }})

    # Flag functions that need investigation
    for vuln in report["vulnerabilities"]:
        if vuln["severity"] in ["critical", "high"] and vuln["caller_count"] > 0:
            report["recommendations"].append({{
                "type": "security_review",
                "target": vuln["function"],
                "address": vuln["address"],
                "reason": "Dangerous function with " + str(vuln["caller_count"]) + " callers - verify safe usage"
            }})

    result = {{"success": True, "report": report}}
except Exception as e:
    import traceback
    result = {{"success": False, "error": str(e), "traceback": traceback.format_exc()}}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
'''

    write_ghidra_script("GenerateReport.py", script)

    project_path = config.get_project_path(project_name)
    stdout, stderr, code = run_ghidra_headless([
        str(project_path),
        project_name,
        "-process", str(binary_name),
        "-noanalysis",
        "-scriptPath", str(config.scripts_dir),
        "-postScript", "GenerateReport.py"
    ], timeout=config.analysis_timeout * 2)  # Double timeout for exhaustive reports

    result = parse_ghidra_json_output(stdout)
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        tb = result.get("traceback", "")
        return [types.TextContent(type="text", text=f"Report generation failed: {error_msg}\n{tb}")]

    report = result.get("report", {})

    if output_format == "json":
        output_text = json.dumps(report, indent=2)
        # Cache the result
        cache.set("generate_report", binary_name, project_name, cache_params,
                  {"text": output_text},
                  project_dir=config.get_project_path(project_name))
        return [types.TextContent(type="text", text=output_text)]

    # Generate Markdown report
    md = generate_markdown_report(report)

    # Cache the result
    cache.set("generate_report", binary_name, project_name, cache_params,
              {"text": md},
              project_dir=config.get_project_path(project_name))

    return [types.TextContent(type="text", text=md)]


def generate_markdown_report(report: dict) -> str:
    """Convert report data to formatted markdown."""
    md = []

    # Header
    binary_info = report.get("binary_info", {})
    md.append(f"# Binary Analysis Report: {binary_info.get('name', 'Unknown')}")
    md.append(f"\n*Generated: {report.get('meta', {}).get('generated_at', 'N/A')} | Depth: {report.get('meta', {}).get('depth', 'N/A')} | Analyzer: Kawaiidra MCP*\n")

    # Executive Summary
    md.append("## Executive Summary\n")
    func_count = report.get("functions", {}).get("total", 0)
    string_count = report.get("strings", {}).get("total", 0)
    vuln_count = len(report.get("vulnerabilities", []))
    critical_vulns = len([v for v in report.get("vulnerabilities", []) if v.get("severity") == "critical"])
    high_vulns = len([v for v in report.get("vulnerabilities", []) if v.get("severity") == "high"])

    md.append(f"| Metric | Value |")
    md.append(f"|--------|-------|")
    md.append(f"| **Format** | {binary_info.get('format', 'N/A')} |")
    md.append(f"| **Architecture** | {binary_info.get('processor', 'N/A')} ({binary_info.get('endian', 'N/A')} endian) |")
    md.append(f"| **Functions** | {func_count} |")
    md.append(f"| **Strings** | {string_count} |")
    md.append(f"| **Vulnerabilities** | {vuln_count} ({critical_vulns} critical, {high_vulns} high) |")
    md.append(f"| **Libraries Detected** | {len(report.get('libraries', []))} |")
    md.append("")

    # Risk Assessment
    risk_score = "LOW"
    if critical_vulns > 0:
        risk_score = "CRITICAL"
    elif high_vulns > 2:
        risk_score = "HIGH"
    elif high_vulns > 0 or vuln_count > 5:
        risk_score = "MEDIUM"
    md.append(f"**Risk Assessment: {risk_score}**\n")

    # Binary Info
    md.append("## Binary Information\n")
    md.append("```")
    md.append(f"Name:        {binary_info.get('name', 'N/A')}")
    md.append(f"Path:        {binary_info.get('path', 'N/A')}")
    md.append(f"Format:      {binary_info.get('format', 'N/A')}")
    md.append(f"Processor:   {binary_info.get('processor', 'N/A')}")
    md.append(f"Endianness:  {binary_info.get('endian', 'N/A')}")
    md.append(f"Address Size: {binary_info.get('address_size', 'N/A')} bit")
    md.append(f"Compiler:    {binary_info.get('compiler', 'N/A')}")
    md.append(f"Image Base:  {binary_info.get('image_base', 'N/A')}")
    if binary_info.get('md5'):
        md.append(f"MD5:         {binary_info.get('md5')}")
    if binary_info.get('sha256'):
        md.append(f"SHA256:      {binary_info.get('sha256')}")
    md.append("```\n")

    # Memory Layout
    md.append("## Memory Layout\n")
    md.append("| Section | Start | End | Size | Permissions |")
    md.append("|---------|-------|-----|------|-------------|")
    for section in report.get("memory_layout", [])[:20]:
        md.append(f"| {section.get('name', 'N/A')} | {section.get('start', 'N/A')} | {section.get('end', 'N/A')} | {section.get('size', 0):,} | {section.get('permissions', 'N/A')} |")
    md.append("")

    # Libraries
    if report.get("libraries"):
        md.append("## Detected Libraries\n")
        for lib in report.get("libraries", []):
            confidence_emoji = "✅" if lib.get("confidence") == "high" else "⚠️"
            md.append(f"- {confidence_emoji} **{lib.get('name')}** ({lib.get('confidence')} confidence)")
            md.append(f"  - Evidence: {', '.join(lib.get('evidence', [])[:3])}")
        md.append("")

    # Vulnerabilities
    if report.get("vulnerabilities"):
        md.append("## Security Vulnerabilities\n")
        md.append("| Severity | Type | Function | Address | CWE | Callers |")
        md.append("|----------|------|----------|---------|-----|---------|")
        for vuln in sorted(report.get("vulnerabilities", []), key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "low"), 4))[:30]:
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln.get("severity", "low"), "⚪")
            md.append(f"| {sev_emoji} {vuln.get('severity', 'N/A').upper()} | {vuln.get('type', 'N/A')} | `{vuln.get('function', 'N/A')}` | {vuln.get('address', 'N/A')} | {vuln.get('cwe', 'N/A')} | {vuln.get('caller_count', 0)} |")
        md.append("")

    # Functions
    md.append("## Function Analysis\n")
    md.append(f"**Total Functions:** {report.get('functions', {}).get('total', 0)}\n")

    if report.get("functions", {}).get("entry_points"):
        md.append("### Entry Points")
        for ep in report.get("functions", {}).get("entry_points", []):
            md.append(f"- `{ep.get('name')}` @ {ep.get('address')} ({ep.get('size', 0)} bytes)")
        md.append("")

    if report.get("functions", {}).get("most_referenced"):
        md.append("### Most Referenced Functions")
        md.append("| Function | Address | References | Size |")
        md.append("|----------|---------|------------|------|")
        for func in report.get("functions", {}).get("most_referenced", [])[:15]:
            md.append(f"| `{func.get('name')}` | {func.get('address')} | {func.get('ref_count', 0)} | {func.get('size', 0)} |")
        md.append("")

    if report.get("functions", {}).get("by_size"):
        md.append("### Largest Functions")
        md.append("| Function | Address | Size (bytes) |")
        md.append("|----------|---------|--------------|")
        for func in report.get("functions", {}).get("by_size", [])[:10]:
            md.append(f"| `{func.get('name')}` | {func.get('address')} | {func.get('size', 0):,} |")
        md.append("")

    # Strings
    md.append("## String Analysis\n")
    md.append(f"**Total Strings:** {report.get('strings', {}).get('total', 0)}\n")

    if report.get("strings", {}).get("urls"):
        md.append("### URLs Found")
        for url in report.get("strings", {}).get("urls", [])[:10]:
            md.append(f"- `{url}`")
        md.append("")

    if report.get("strings", {}).get("paths"):
        md.append("### File Paths")
        for path in report.get("strings", {}).get("paths", [])[:10]:
            md.append(f"- `{path}`")
        md.append("")

    if report.get("strings", {}).get("interesting"):
        md.append("### Interesting Strings")
        for s in report.get("strings", {}).get("interesting", [])[:15]:
            md.append(f"- @ {s.get('address')}: `{s.get('value', '')[:80]}{'...' if len(s.get('value', '')) > 80 else ''}`")
        md.append("")

    # Behavioral Analysis
    behavioral = report.get("behavioral", {})
    if any(behavioral.get(k) for k in behavioral):
        md.append("## Behavioral Analysis\n")
        for category, items in behavioral.items():
            if items:
                md.append(f"### {category.replace('_', ' ').title()} Operations")
                for item in items[:10]:
                    md.append(f"- `{item.get('function')}` @ {item.get('address')} (pattern: {item.get('pattern')})")
                md.append("")

    # Imports/Exports
    md.append("## Symbol Information\n")
    md.append(f"- **Exports:** {len(report.get('symbols', {}).get('exports', []))}")
    md.append(f"- **Imports:** {len(report.get('symbols', {}).get('imports', []))}")
    md.append(f"- **Namespaces:** {len(report.get('symbols', {}).get('namespaces', []))}")
    md.append("")

    # iOS Analysis
    ios = report.get("ios_analysis", {})
    if ios:
        md.append("## iOS/macOS Specific Analysis\n")
        for category, items in ios.items():
            if items:
                md.append(f"### {category.replace('_', ' ').title()}")
                for item in items[:10]:
                    md.append(f"- `{item.get('symbol')}` @ {item.get('address')}")
                md.append("")

    # Decompiled Functions
    if report.get("decompiled_functions"):
        md.append("## Decompiled Functions\n")
        for func in report.get("decompiled_functions", []):
            md.append(f"### {func.get('name')} @ {func.get('address')}")
            md.append("```c")
            md.append(func.get("code", "// Decompilation failed")[:3000])
            md.append("```\n")

    # Recommendations
    if report.get("recommendations"):
        md.append("## Recommendations\n")
        for rec in report.get("recommendations", [])[:20]:
            rec_type = rec.get("type", "").replace("_", " ").title()
            md.append(f"- **[{rec_type}]** `{rec.get('target')}` @ {rec.get('address')}")
            md.append(f"  - {rec.get('reason')}")
        md.append("")

    # Footer
    md.append("---")
    md.append("*Report generated by Kawaiidra MCP - Binary Analysis Made Adorable*")

    return "\n".join(md)


# ============================================================================
# Cache Management Handlers
# ============================================================================

async def handle_cache_stats(args: dict) -> Sequence[types.TextContent]:
    """Get cache statistics."""
    stats = get_cache_stats()

    output = [
        "# Kawaiidra Cache Statistics\n",
        f"**Status:** {'Enabled' if stats['enabled'] else 'Disabled'}",
        f"**Location:** `{stats['cache_dir']}`\n",
        "## Usage",
        f"- **Entries:** {stats['entry_count']}",
        f"- **Size:** {stats['total_size_mb']} MB / {stats['max_size_mb']} MB max\n",
        "## Performance",
        f"- **Hits:** {stats['hits']}",
        f"- **Misses:** {stats['misses']}",
        f"- **Hit Rate:** {stats['hit_rate_percent']}%\n",
        "## Maintenance",
        f"- **Invalidations:** {stats['invalidations']}",
        f"- **Evictions:** {stats['evictions']}",
    ]

    return [types.TextContent(type="text", text="\n".join(output))]


async def handle_cache_clear(args: dict) -> Sequence[types.TextContent]:
    """Clear cache entries."""
    binary_name = args.get("binary_name")
    project_name = args.get("project_name")

    cleared = clear_cache(binary_name=binary_name, project_name=project_name)

    if binary_name or project_name:
        scope = []
        if binary_name:
            scope.append(f"binary=`{binary_name}`")
        if project_name:
            scope.append(f"project=`{project_name}`")
        scope_str = ", ".join(scope)
        msg = f"Cleared {cleared} cache entries for {scope_str}"
    else:
        msg = f"Cleared {cleared} cache entries (all)"

    return [types.TextContent(type="text", text=msg)]


# ============================================================================
# Bridge Status Handler
# ============================================================================

def handle_bridge_status(args: dict) -> Sequence[types.TextContent]:
    """Get JPype bridge status."""
    backend = get_backend()

    output = ["# Kawaiidra Bridge Status\n"]

    if backend is None:
        output.extend([
            "**Mode:** Subprocess (fallback)",
            "**Reason:** Bridge backend not available",
            "",
            "The subprocess mode uses Ghidra's analyzeHeadless command for each operation.",
            "This involves ~5-15 seconds of JVM startup overhead per tool call.",
            "",
            "To enable the fast bridge mode, install JPype:",
            "```",
            "pip install JPype1",
            "```",
            "",
            "Requirements:",
            "- JPype1 >= 1.5.0",
            "- Java JDK 17+ installed",
        ])
    else:
        status = backend.get_status()
        output.extend([
            f"**Mode:** {status['mode']}",
            f"**Bridge Enabled:** {status['bridge_enabled']}",
            f"**Bridge Started:** {status['bridge_started']}",
            f"**JPype Available:** {status['jpype_available']}",
        ])

        if status.get('jpype_error'):
            output.append(f"**JPype Error:** {status['jpype_error']}")

        if status.get('cached_programs') is not None:
            output.append(f"**Cached Programs:** {status['cached_programs']}")

        output.append("")

        if status['bridge_started']:
            output.extend([
                "## Performance",
                "The bridge is active! Operations run ~100-1000x faster than subprocess mode:",
                "- **First call per binary:** ~2-5 seconds (program load)",
                "- **Subsequent calls:** ~1-50 milliseconds",
                "",
                "Programs stay loaded in memory for instant access.",
            ])
        else:
            output.extend([
                "## Note",
                "Bridge is enabled but not yet started. It will start automatically",
                "on the first tool call that requires Ghidra analysis.",
            ])

    return [types.TextContent(type="text", text="\n".join(output))]


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
