# Kawaiidra MCP

> A Ghidra MCP Server for Claude Code - Binary Analysis Made Adorable

[![Ghidra](https://img.shields.io/badge/Ghidra-MCP-red)](https://ghidra-sre.org/)
[![MCP](https://img.shields.io/badge/Model%20Context%20Protocol-Server-blue)](https://modelcontextprotocol.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Keywords:** `ghidra` `mcp` `ghidra-mcp` `model-context-protocol` `binary-analysis` `reverse-engineering` `decompiler` `disassembler` `claude` `claude-code`

A general-purpose **Ghidra MCP server** that brings the power of Ghidra's headless analyzer and decompiler to Claude Code and other MCP-compatible AI assistants.

## Features

### Core Features
- **Analyze any binary**: PE (Windows), ELF (Linux), Mach-O (macOS), and raw firmware
- **Decompile functions**: Get C code from compiled binaries
- **Disassembly**: View assembly listings
- **Cross-references**: Find function callers and callees
- **String analysis**: Search and list strings in binaries
- **Export results**: Save analysis to JSON for further processing
- **Multi-project support**: Organize analyses into separate Ghidra projects

### Advanced Analysis (LLM-Optimized)
- **Call graphs**: Extract hierarchical function relationships
- **Library detection**: Identify OpenSSL, zlib, Qt, Windows API, and more
- **Semantic search**: Find code by behavior (file I/O, network, crypto, memory ops)
- **Context extraction**: Get functions with all dependencies for complete understanding
- **Data structures**: Extract struct/class definitions and enums
- **Control flow graphs**: Analyze function logic with basic blocks
- **Vulnerability detection**: Pattern-based security analysis with CWE mapping
- **Function similarity**: Find code reuse based on structural fingerprints
- **Smart naming**: Suggest better symbol names based on usage patterns

### iOS Security Research Tools
- **KPP/KTRR detection**: Identify kernel patch protection mechanisms
- **Mach trap analysis**: Analyze syscall tables and trap handlers
- **PAC gadget finder**: Locate pointer authentication gadgets for ARM64e
- **Sandbox analysis**: Examine sandbox operations and policy checks
- **IOKit class finder**: Map IOKit class hierarchies and user clients
- **Entitlement checks**: Detect entitlement validation code paths
- **Kernel symbols**: Find and analyze XNU kernel symbols
- **Mach port analysis**: Analyze IPC and port operations

## Performance

Kawaiidra supports two execution modes:

| Mode | Speed | Setup |
|------|-------|-------|
| **JPype Bridge** (default) | ~1-50ms per call | Requires Java JDK 17+ |
| Subprocess (fallback) | ~5-15s per call | Works out of the box |

The JPype bridge keeps a JVM running in-process, eliminating the ~5-15 second startup overhead of spawning `analyzeHeadless` for each operation. **This is 100-1000x faster for sequential operations.**

```
┌────────────────────────────────────────────────────┐
│  10 function decompilations:                       │
│                                                    │
│  Subprocess mode:  ~2-3 minutes                    │
│  JPype Bridge:     ~0.5 seconds                    │
└────────────────────────────────────────────────────┘
```

## Requirements

- **Python 3.10+**
- **Ghidra 11.0+** (tested with 11.x and 12.0, fully compatible with Ghidra 12.0)
- **MCP Python package**: `pip install mcp`

### For Maximum Performance (Recommended)
- **Java JDK 17+** (for JPype bridge)
- **JPype1**: `pip install JPype1`

## Quick Start

### 1. Install Ghidra

**Option A: Homebrew (macOS/Linux) - Recommended**
```bash
# macOS
brew install ghidra

# Linux (Homebrew)
brew install ghidra
```

**Option B: Manual Installation**
Download Ghidra from [ghidra-sre.org](https://ghidra-sre.org/) and extract it.

### 2. Install Dependencies

```bash
cd kawaiidra-mcp
pip install -r requirements.txt
```

### 2b. Enable Fast Mode (Recommended)

For 100-1000x faster operations, install JPype and ensure Java is available:

```bash
# Install JPype
pip install JPype1

# Verify Java JDK 17+ is installed
java -version
```

**Installing Java if needed:**
```bash
# macOS
brew install openjdk@17

# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# Windows (winget)
winget install EclipseAdoptium.Temurin.17.JDK
```

The bridge auto-enables when both JPype and Java are available. Use the `bridge_status` tool to verify.

### 3. Configure Ghidra Path (Optional)

The server auto-detects Ghidra installations in common locations. If auto-detection fails or you want to use a specific version, set `GHIDRA_INSTALL_DIR`:

**Homebrew installations (usually auto-detected):**
```bash
# macOS (Apple Silicon)
export GHIDRA_INSTALL_DIR=/opt/homebrew

# macOS (Intel)
export GHIDRA_INSTALL_DIR=/usr/local

# Linux
export GHIDRA_INSTALL_DIR=/home/linuxbrew/.linuxbrew
```

**Manual installations:**
```bash
# Windows
set GHIDRA_INSTALL_DIR=C:\ghidra_11.2_PUBLIC

# Linux/macOS
export GHIDRA_INSTALL_DIR=/opt/ghidra
export GHIDRA_INSTALL_DIR=/Applications/ghidra_11.2_PUBLIC
```

### 4. Use with Claude Code

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

### 5. Analyze a Binary

1. Place your binary in the `binaries/` folder, or use an absolute path
2. Use the `analyze_binary` tool to import and analyze
3. Use other tools to explore the analysis

## Available Tools

### Core Analysis Tools

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
| `cache_stats` | View cache hit rate and performance statistics |
| `cache_clear` | Clear cached results |
| `bridge_status` | Check if fast JPype bridge mode is active |
| `generate_report` | Generate comprehensive binary analysis report |
| `list_exports` | List exported functions and symbols |
| `list_imports` | List imported functions from external libraries |
| `list_data_items` | List defined data labels and values |
| `list_namespaces` | List all namespaces and classes |
| `rename_function` | Rename a function in the analysis |
| `rename_data` | Rename a data label at an address |
| `rename_variable` | Rename a local variable within a function |
| `set_comment` | Add comments at specific addresses |
| `set_function_prototype` | Set a function's signature |
| `set_local_variable_type` | Set the type of a local variable |

### Advanced Analysis Tools (LLM-Optimized)

| Tool | Description |
|------|-------------|
| `get_call_graph` | Extract call hierarchy showing function relationships |
| `detect_libraries` | Identify standard libraries, frameworks, and third-party code |
| `semantic_code_search` | Search for code by behavior (file I/O, network, crypto, etc.) |
| `get_function_with_context` | Get function with all dependencies for complete LLM understanding |
| `get_data_structures` | Extract struct/class definitions and data types |
| `get_control_flow_graph` | Extract CFG with basic blocks for logic flow analysis |
| `detect_vulnerabilities` | Detect security vulnerabilities using pattern analysis |
| `find_similar_functions` | Find functions similar to a reference based on structure |
| `get_annotated_disassembly` | Get richly annotated disassembly with xrefs and comments |
| `suggest_symbol_names` | Suggest better variable/function names based on usage |

### iOS Security Research Tools

| Tool | Description |
|------|-------------|
| `detect_kpp_ktrr` | Detect KPP, KTRR, PPL, and AMFI kernel protections |
| `analyze_mach_traps` | Analyze Mach trap table and syscall handlers |
| `find_pac_gadgets` | Find PAC signing/authentication gadgets for ARM64e |
| `analyze_sandbox_ops` | Analyze sandbox operations and policy enforcement |
| `find_iokit_classes` | Find IOKit classes, vtables, and user clients |
| `detect_entitlement_checks` | Detect entitlement validation and AMFI checks |
| `find_kernel_symbols` | Find kernel symbols with pattern matching |
| `analyze_mach_ports` | Analyze Mach port operations and IPC patterns |

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

### Get Call Graph

```
get_call_graph
  binary_name: "target.exe"
  function_name: "main"
  depth: 3
  direction: "callees"
```

### Detect Libraries

```
detect_libraries
  binary_name: "target.exe"
  detailed: true
```

### Search for Crypto Code

```
semantic_code_search
  binary_name: "target.exe"
  pattern: "crypto"
```

### Get Function with Full Context

```
get_function_with_context
  binary_name: "target.exe"
  function_name: "process_data"
  include_callees: true
  include_data_types: true
```

### Detect Vulnerabilities

```
detect_vulnerabilities
  binary_name: "target.exe"
  severity: "high"
```

### Get Control Flow Graph

```
get_control_flow_graph
  binary_name: "target.exe"
  function_name: "main"
  include_instructions: true
```

### Find Similar Functions

```
find_similar_functions
  binary_name: "target.exe"
  function_name: "encrypt_block"
  threshold: 0.7
```

### Generate Comprehensive Report

```
generate_report
  binary_name: "target.exe"
  depth: "full"
```

Depth options: `quick` (metadata only), `standard` (+ functions/strings), `full` (+ decompilation), `exhaustive` (everything)

### Detect Kernel Protections (iOS)

```
detect_kpp_ktrr
  binary_name: "kernelcache"
```

### Analyze Mach Traps (iOS/macOS)

```
analyze_mach_traps
  binary_name: "kernelcache"
  include_handlers: true
```

### Find PAC Gadgets (ARM64e)

```
find_pac_gadgets
  binary_name: "kernelcache"
  gadget_type: "signing"
  max_results: 50
```

### Find IOKit Classes

```
find_iokit_classes
  binary_name: "IOKit.kext"
  include_vtables: true
  include_user_clients: true
```

### Detect Entitlement Checks

```
detect_entitlement_checks
  binary_name: "amfid"
  include_context: true
```

### Find Kernel Symbols

```
find_kernel_symbols
  binary_name: "kernelcache"
  pattern: "proc_"
  symbol_type: "function"
```

### Analyze Mach Ports

```
analyze_mach_ports
  binary_name: "launchd"
  include_dangerous: true
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GHIDRA_INSTALL_DIR` | Path to Ghidra installation | Auto-detected |
| `KAWAIIDRA_PROJECT_DIR` | Where Ghidra projects are stored | `./projects` |
| `KAWAIIDRA_BINARIES_DIR` | Where input binaries are stored | `./binaries` |
| `KAWAIIDRA_EXPORTS_DIR` | Where exports are written | `./exports` |
| `KAWAIIDRA_LOG_DIR` | Where logs are written | `./logs` |
| `KAWAIIDRA_TIMEOUT` | Analysis timeout in seconds | `300` |
| `KAWAIIDRA_DECOMPILE_TIMEOUT` | Decompile timeout in seconds | `180` |
| `KAWAIIDRA_MAX_MEMORY` | JVM max memory | `4G` |

### Cache Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `KAWAIIDRA_CACHE_ENABLED` | Enable result caching | `true` |
| `KAWAIIDRA_CACHE_DIR` | Cache storage location | `~/.kawaiidra/cache` |
| `KAWAIIDRA_CACHE_MAX_SIZE_MB` | Maximum cache size | `500` |

### JPype Bridge Settings (Performance)

| Variable | Description | Default |
|----------|-------------|---------|
| `KAWAIIDRA_USE_BRIDGE` | Enable fast JPype bridge | `true` |
| `KAWAIIDRA_BRIDGE_CACHE_PROGRAMS` | Keep programs loaded in memory | `true` |
| `KAWAIIDRA_BRIDGE_MAX_PROGRAMS` | Max programs to cache | `5` |

## Testing

Kawaiidra includes a comprehensive test suite with 166 tests covering all major modules:

```bash
# Run all tests
uv run pytest tests/ -v

# Run specific test file
uv run pytest tests/test_cache.py -v
```

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `test_cache.py` | 57 | Cache operations, TTL, LRU eviction |
| `test_index_parsing.py` | 30 | Ghidra index parsing, regex patterns |
| `test_config.py` | 26 | Configuration, env vars, path detection |
| `test_mcp_tools.py` | 22 | Tool definitions, schemas, utilities |
| `test_mcp_handlers.py` | 22 | MCP handler integration |
| `test_bridge.py` | 17 | Bridge availability, backend operations |

## Directory Structure

```
kawaiidra-mcp/
├── .mcp.json           # MCP server configuration
├── README.md           # This file
├── requirements.txt    # Python dependencies
├── run_server.py       # Server entry point
├── src/
│   └── kawaiidra_mcp/
│       ├── server.py   # MCP server implementation
│       ├── config.py   # Configuration management
│       ├── cache.py    # Result caching system
│       ├── bridge/     # JPype bridge for fast execution
│       │   ├── __init__.py
│       │   ├── jpype_bridge.py  # JVM lifecycle & Ghidra API
│       │   └── backend.py       # High-level backend abstraction
│       └── scripts/    # Ghidra headless scripts (fallback)
├── tests/              # Unit test suite (166 tests)
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
set KAWAIIDRA_TIMEOUT=600

# Linux/macOS
export KAWAIIDRA_TIMEOUT=600
```

### Large Binary Memory Issues

Increase JVM memory:
```bash
set KAWAIIDRA_MAX_MEMORY=8G
```

### Function Not Found

- Ensure the binary has been analyzed first with `analyze_binary`
- Try using the function's address instead of name (e.g., `0x401000`)
- Check if the function is in a different binary in the project

### JPype Bridge Not Starting

Check bridge status:
```
bridge_status
```

If bridge shows as unavailable:

1. **Install JPype:**
   ```bash
   pip install JPype1
   ```

2. **Install Java JDK 17+:**
   ```bash
   # macOS
   brew install openjdk@17

   # Ubuntu/Debian
   sudo apt install openjdk-17-jdk
   ```

3. **Verify Java is in PATH:**
   ```bash
   java -version
   ```

4. **Check JAVA_HOME (if needed):**
   ```bash
   export JAVA_HOME=/path/to/jdk
   ```

The server automatically falls back to subprocess mode if JPype is unavailable.

### Bridge Mode Slower Than Expected

- First call per binary takes 2-5s (program loading)
- Subsequent calls should be ~1-50ms
- Use `bridge_status` to verify bridge is active
- Check `KAWAIIDRA_BRIDGE_CACHE_PROGRAMS=true` is set

## Why "Kawaiidra"?

Because reverse engineering should be fun! This is a cute wrapper around serious tools.

*Kawaii* (Japanese: cute) + *Ghidra* = **Kawaiidra**

## License

MIT License

## See Also

- [Ghidra](https://ghidra-sre.org/) - NSA's reverse engineering framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Claude Code](https://claude.ai/code) - AI coding assistant
