# Ghidra Installation Guide for Kawaiidra MCP

This guide covers different ways to install Ghidra for use with Kawaiidra MCP.

## Installation Methods

### Method 1: Homebrew (Recommended for macOS/Linux)

**Advantages:**
- Automatic updates via `brew upgrade`
- No manual extraction or path setup needed
- Auto-detected by Kawaiidra MCP

**macOS:**
```bash
brew install ghidra
```

**Linux (requires Homebrew for Linux):**
```bash
brew install ghidra
```

**Verification:**
```bash
# Check installation
which ghidraRun
# Should show: /opt/homebrew/bin/ghidraRun (Apple Silicon)
#          or: /usr/local/bin/ghidraRun (Intel Mac)

# Check version
ghidra --version
```

### Method 2: Manual Installation

**Download:**
1. Visit [https://ghidra-sre.org/](https://ghidra-sre.org/)
2. Download the latest release (e.g., `ghidra_11.2_PUBLIC_20241105.zip`)
3. Extract to your preferred location

**Recommended locations:**
- **Windows:** `C:\ghidra_11.2_PUBLIC`
- **Linux:** `/opt/ghidra` or `~/ghidra`
- **macOS:** `/Applications/ghidra_11.2_PUBLIC` or `~/ghidra`

**Set environment variable:**
```bash
# Windows (Command Prompt)
set GHIDRA_INSTALL_DIR=C:\ghidra_11.2_PUBLIC

# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR="C:\ghidra_11.2_PUBLIC"

# Linux/macOS
export GHIDRA_INSTALL_DIR=/opt/ghidra
```

## Auto-Detection

Kawaiidra MCP automatically detects Ghidra in these locations:

### macOS
- `/opt/homebrew` (Apple Silicon Homebrew)
- `/usr/local` (Intel Homebrew)
- `/Applications/ghidra_11.2_PUBLIC`
- `/Applications/ghidra_11.1_PUBLIC`
- `/Applications/ghidra_11.0_PUBLIC`
- `/Applications/ghidra`

### Linux
- `/home/linuxbrew/.linuxbrew` (Homebrew)
- `/opt/ghidra`
- `~/ghidra`
- `/usr/local/ghidra`

### Windows
- `C:\ghidra`
- `C:\ghidra_11.2_PUBLIC`
- `C:\ghidra_11.1_PUBLIC`
- `C:\ghidra_11.0_PUBLIC`
- `%USERPROFILE%\ghidra`

## Supported Installation Structures

Kawaiidra MCP supports multiple Ghidra installation structures:

### Traditional (Manual Installation)
```
ghidra_11.2_PUBLIC/
├── support/
│   ├── analyzeHeadless         # Unix script
│   └── analyzeHeadless.bat     # Windows batch file
├── Ghidra/
└── ...
```

### Homebrew (macOS/Linux)
```
/opt/homebrew/
├── Cellar/
│   └── ghidra/
│       └── 11.2/
│           └── libexec/
│               └── support/
│                   └── analyzeHeadless
└── bin/
    └── ghidraRun               # Symlink
```

## Version Support

Kawaiidra MCP supports:
- **Ghidra 11.x** (11.0, 11.1, 11.2)
- **Ghidra 12.x** (if available)

Multiple versions can coexist. Set `GHIDRA_INSTALL_DIR` to choose which version to use.

## Troubleshooting

### "Ghidra not found"

**Check if Ghidra is installed:**
```bash
# Homebrew installation
which ghidraRun

# Manual installation - verify the path exists
ls /opt/ghidra/support/analyzeHeadless  # Linux/macOS
dir C:\ghidra\support\analyzeHeadless.bat  # Windows
```

**Set GHIDRA_INSTALL_DIR explicitly:**
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

### Multiple Ghidra Versions

If you have multiple versions installed, set `GHIDRA_INSTALL_DIR` to the specific version you want to use:

```bash
# Use Ghidra 11.2
export GHIDRA_INSTALL_DIR=/Applications/ghidra_11.2_PUBLIC

# Or use Homebrew version
export GHIDRA_INSTALL_DIR=/opt/homebrew
```

### Homebrew Installation Not Detected

If Homebrew Ghidra is installed but not detected:

```bash
# Find where Homebrew installed Ghidra
brew --prefix ghidra

# Set it explicitly
export GHIDRA_INSTALL_DIR=$(brew --prefix)
```

## Verifying Installation

Test that Kawaiidra MCP can find Ghidra:

```bash
cd kawaiidra-mcp
python -c "from src.kawaiidra_mcp.config import config; print(f'Found: {config.analyze_headless}')"
```

Expected output:
```
Found: /opt/homebrew/Cellar/ghidra/11.2/libexec/support/analyzeHeadless
```

Or:
```
Found: /Applications/ghidra_11.2_PUBLIC/support/analyzeHeadless
```
