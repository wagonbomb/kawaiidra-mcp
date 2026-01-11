# Kawaiidra MCP

> A Ghidra MCP Server for Claude Code - Binary Analysis Made Adorable

[![Ghidra](https://img.shields.io/badge/Ghidra-MCP-red)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-Server-blue)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Keywords:** `ghidra` `mcp` `ghidra-mcp` `model-context-protocol` `binary-analysis` `reverse-engineering` `decompiler` `disassembler` `claude` `claude-code`

A general-purpose **Ghidra MCP server** that brings the power of Ghidra's headless analyzer and decompiler to Claude Code and other MCP-compatible AI assistants.

## Features

- **Analyze any binary**: PE (Windows), ELF (Linux), Mach-O (macOS), and raw firmware
- **Decompile functions**: Get C code from compiled binaries
- **Disassembly**: View assembly listings
- **Cross-references**: Find function callers and callees
- **String analysis**: Search and list strings in binaries
- **Export results**: Save analysis to JSON for further processing
- **Multi-project support**: Organize analyses into separate Ghidra projects

## Requirements

- **Python 3.10+**
- **Ghidra 11.0+** (tested with 11.x and 12.0)
- **MCP Python package**: `pip install mcp`

## Quick Start

### 1. Install Dependencies

```bash
cd kawaiidra-mcp
pip install -r requirements.txt
```

### 2. Set Ghidra Installation Path

```bash
# Windows
set GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.0_PUBLIC

# Linux/macOS
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0_PUBLIC
```

### 3. Use with Claude Code

Open the `kawaiidra-mcp` folder in Claude Code. The MCP server will automatically load from `.mcp.json`.

Or add to your Claude Code config:

```json
{
  "mcpServers": {
    "ghidra": {
      "type": "stdio",
      "command": "python",
      "args": ["/path/to/kawaiidra-mcp/run_server.py"],
      "env": {
        "GHIDRA_INSTALL_DIR": "/path/to/ghidra"
      }
    }
  }
}
```

### 4. Analyze a Binary

1. Place your binary in the `binaries/` folder, or use an absolute path
2. Use the `analyze_binary` tool to import and analyze
3. Use other tools to explore the analysis

## Available Tools

| Tool | Description |
|------|-------------|
| `analyze_binary` | Import and analyze a binary file |
| `list_analyzed_binaries` | List binaries in current project |
| `list_functions` | List all functions in a binary |
| `find_functions` | Search functions by name pattern |
| `get_function_decompile` | Decompile function to C code |
| `get_function_disassembly` | Get assembly listing |
| `get_function_xrefs` | Get cross-references to/from function |
| `search_strings` | Search strings by pattern |
| `list_strings` | List all defined strings |
| `get_binary_info` | Get binary metadata (arch, format, etc.) |
| `get_memory_map` | Get memory segments/sections |
| `export_analysis` | Export analysis to JSON file |

## Tool Examples

### Analyze a Windows Executable

```
analyze_binary
  file_path: "C:\path\to\target.exe"
```

### Analyze Raw Firmware

```
analyze_binary
  file_path: "firmware.bin"
  processor: "ARM:LE:32:v7"
  base_address: "0x08000000"
```

### Decompile a Function

```
get_function_decompile
  binary_name: "target.exe"
  function_name: "main"
```

### Find Functions by Pattern

```
find_functions
  pattern: "crypt"
  binary_name: "target.exe"
```

### Get Cross-References

```
get_function_xrefs
  binary_name: "target.exe"
  function_name: "main"
  direction: "from"
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation | (required) |
| `GHIDRA_MCP_PROJECT_DIR` | Where Ghidra projects are stored | `./projects` |
| `GHIDRA_MCP_BINARIES_DIR` | Where input binaries are stored | `./binaries` |
| `GHIDRA_MCP_EXPORTS_DIR` | Where exports are written | `./exports` |
| `GHIDRA_MCP_LOG_DIR` | Where logs are written | `./logs` |
| `GHIDRA_MCP_TIMEOUT` | Analysis timeout in seconds | `300` |
| `GHIDRA_MCP_DECOMPILE_TIMEOUT` | Decompile timeout in seconds | `180` |
| `GHIDRA_MCP_MAX_MEMORY` | JVM max memory | `4G` |

## Directory Structure

```
kawaiidra-mcp/
├── .mcp.json           # MCP server configuration
├── README.md           # This file
├── requirements.txt    # Python dependencies
├── run_server.py       # Server entry point
├── src/
│   └── ghidra_mcp/
│       ├── server.py   # MCP server implementation
│       ├── config.py   # Configuration management
│       └── scripts/    # Ghidra headless scripts
├── projects/           # Ghidra project storage (gitignored)
├── binaries/           # Input binaries (gitignored)
├── exports/            # Exported analysis (gitignored)
└── logs/               # Runtime logs (gitignored)
```

## Supported Binary Formats

| Format | Extensions | Auto-detected |
|--------|------------|---------------|
| PE (Windows) | .exe, .dll, .sys | Yes |
| ELF (Linux) | .so, .o, (none) | Yes |
| Mach-O (macOS) | .dylib, (none) | Yes |
| Raw Binary | .bin, .fw | No (specify processor) |

## Common Processor IDs

For raw binaries, specify the processor manually:

| Architecture | Processor ID |
|--------------|--------------|
| x86 32-bit | `x86:LE:32:default` |
| x86 64-bit (AMD64) | `x86:LE:64:default` |
| ARM 32-bit | `ARM:LE:32:v7` |
| ARM 64-bit (AArch64) | `AARCH64:LE:64:default` |
| MIPS 32-bit BE | `MIPS:BE:32:default` |
| MIPS 32-bit LE | `MIPS:LE:32:default` |
| PowerPC 32-bit | `PowerPC:BE:32:default` |
| RISC-V 32-bit | `RISCV:LE:32:default` |

## Troubleshooting

### "Ghidra not found"

Ensure `GHIDRA_INSTALL_DIR` points to a valid Ghidra installation with `support/analyzeHeadless` script.

### "MCP SDK not installed"

```bash
pip install mcp
```

### Analysis Times Out

Increase timeout with environment variable:
```bash
# Windows
set GHIDRA_MCP_TIMEOUT=600

# Linux/macOS
export GHIDRA_MCP_TIMEOUT=600
```

### Large Binary Memory Issues

Increase JVM memory:
```bash
set GHIDRA_MCP_MAX_MEMORY=8G
```

### Function Not Found

- Ensure the binary has been analyzed first with `analyze_binary`
- Try using the function's address instead of name (e.g., `0x401000`)
- Check if the function is in a different binary in the project

## Why "Kawaiidra"?

Because reverse engineering should be fun! This is a cute wrapper around serious tools.

*Kawaii* (Japanese: cute) + *Ghidra* = **Kawaiidra**

## License

MIT License

## See Also

- [Ghidra](https://ghidra-sre.org/) - NSA's reverse engineering framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Claude Code](https://claude.ai/code) - AI coding assistant
