#!/usr/bin/env python3
"""
Ghidra MCP Server - General-purpose binary analysis via Model Context Protocol.

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
server = Server("ghidra")


def log(message: str) -> None:
    """Log message to file."""
    try:
        log_file = config.log_dir / "ghidra_mcp.log"
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

    log(f"Starting Ghidra MCP Server")
    log(f"Ghidra home: {config.ghidra_home}")
    log(f"Project dir: {config.project_dir}")

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="ghidra",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


if __name__ == "__main__":
    asyncio.run(main())
