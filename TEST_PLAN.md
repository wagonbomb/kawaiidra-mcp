# Kawaiidra MCP - Comprehensive Test Plan

This document provides a validated testing methodology for Kawaiidra MCP, covering all 55 tools across multiple binary formats and platforms.

---

## Test Binary Sources

All test binaries used in this plan are from **open-source projects with permissive licenses** or are self-compiled test programs. This ensures reproducibility and legal compliance.

### Recommended Test Binaries

| Binary | Source | License | Format | Use Case |
|--------|--------|---------|--------|----------|
| `putty.exe` | putty.org | MIT | PE x86/x64 | Windows core testing |
| `busybox` | busybox.net | GPL-2.0 | ELF | Linux/Embedded testing |
| `libcrypto.so` | openssl.org | Apache-2.0 | ELF | Crypto detection testing |
| `curl` | curl.se | MIT | Various | Network/API testing |

### Obtaining Test Binaries

#### Windows PE (putty.exe) - Recommended
```bash
# Download from official PuTTY site
# https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
# Direct link: https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe
```

#### Alternative: Self-compiled Windows PE (hello_x86.exe)
```c
// hello.c - Compile with: cl /Fe:hello_x86.exe hello.c
#include <stdio.h>
#include <string.h>

// Hardcoded test strings for string analysis
const char* API_KEY = "sk-test-1234567890abcdef";
const char* API_URL = "https://api.example.com/v1/data";

int encrypt_data(char* data, int len) {
    // Simple XOR for vulnerability detection testing
    for (int i = 0; i < len; i++) {
        data[i] ^= 0x42;
    }
    return len;
}

int process_input(char* buffer) {
    char local[64];
    strcpy(local, buffer);  // Unsafe - for vuln detection
    return strlen(local);
}

int main(int argc, char** argv) {
    printf("Hello, Kawaiidra!\n");
    printf("API: %s\n", API_URL);

    if (argc > 1) {
        process_input(argv[1]);
    }

    return 0;
}
```

#### Linux ELF (hello_x64.elf)
```bash
# Compile on Linux:
gcc -o hello_x64.elf hello.c -m64

# Cross-compile on Windows with MinGW:
x86_64-linux-gnu-gcc -o hello_x64.elf hello.c
```

#### Android ARM (test_jni.so)
```c
// test_jni.c - Android JNI test library
#include <jni.h>
#include <string.h>

// JNI method pattern for detection
JNIEXPORT jstring JNICALL
Java_com_example_test_MainActivity_stringFromJNI(JNIEnv *env, jobject thiz) {
    return (*env)->NewStringUTF(env, "Hello from C!");
}

// JNI_OnLoad for detection
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    return JNI_VERSION_1_6;
}
```

### Obtaining Pre-built Binaries

#### Option 1: BusyBox (Recommended for Android/ARM testing)
```bash
# Download from busybox.net
wget https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox

# Or for ARM:
wget https://busybox.net/downloads/binaries/1.35.0-arm-linux-musleabi/busybox
```

#### Option 2: Curl (Good for API/network testing)
```bash
# Available from curl.se/download.html
# Pre-built binaries for all platforms
```

#### Option 3: OpenSSL (For crypto testing)
```bash
# libcrypto.so contains all crypto constants
# Available from openssl.org or system packages
```

---

## Test Environment Requirements

### Windows (Primary Testing)
- Windows 10/11
- Python 3.10+
- Ghidra 11.x or 12.x installed
- Java JDK 17+ (for JPype bridge performance)
- Visual Studio Build Tools (for compiling test binaries)

### macOS (iOS/macOS Tools)
- macOS 12+ (Monterey or later)
- Xcode Command Line Tools
- Ghidra 11.x or 12.x
- For iOS testing: Extracted kernelcache from public IPSW

### Linux
- Ubuntu 20.04+ or equivalent
- GCC for compiling test binaries
- Ghidra 11.x or 12.x

---

## Test Execution Phases

### Phase 1: Core Analysis Tools (17 Tests)

These tests validate the fundamental Ghidra integration.

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| CORE-001 | `analyze_binary` | Import test binary | Analysis completes, functions detected |
| CORE-002 | `list_analyzed_binaries` | List project contents | Shows imported binary |
| CORE-003 | `list_functions` | Enumerate functions | Returns function list with addresses |
| CORE-004 | `find_functions` | Search by pattern | Matches functions containing pattern |
| CORE-005 | `get_function_decompile` | Decompile function | Returns C pseudocode |
| CORE-006 | `get_function_disassembly` | Get assembly | Returns disassembly listing |
| CORE-007 | `get_function_xrefs` | Cross-references | Shows callers/callees |
| CORE-008 | `list_strings` | List all strings | Returns defined strings |
| CORE-009 | `search_strings` | Search strings | Matches pattern in strings |
| CORE-010 | `get_binary_info` | Binary metadata | Format, arch, compiler info |
| CORE-011 | `get_memory_map` | Memory segments | Shows .text, .data, etc. |
| CORE-012 | `list_imports` | Imported functions | External dependencies |
| CORE-013 | `list_exports` | Exported functions | Public symbols |
| CORE-014 | `list_data_items` | Data definitions | Labeled data |
| CORE-015 | `list_namespaces` | Namespaces/classes | Organizational structure |
| CORE-016 | `export_analysis` | Export to JSON | Creates valid JSON file |
| CORE-017 | `generate_report` | Full report | Comprehensive analysis |

### Phase 2: Modification Tools (6 Tests)

These tests validate analysis annotation capabilities.

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| MOD-001 | `rename_function` | Rename function | Name persists in project |
| MOD-002 | `rename_data` | Rename data label | Label updated |
| MOD-003 | `rename_variable` | Rename local var | Variable renamed in decompilation |
| MOD-004 | `set_comment` | Add comment | Comment appears at address |
| MOD-005 | `set_function_prototype` | Set signature | Signature updated |
| MOD-006 | `set_local_variable_type` | Set variable type | Type reflected in decompilation |

### Phase 3: Advanced LLM Tools (10 Tests)

These tests validate the LLM-optimized analysis features.

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| ADV-001 | `get_call_graph` | Call hierarchy | Tree of function calls |
| ADV-002 | `detect_libraries` | Library detection | Identifies linked libraries |
| ADV-003 | `semantic_code_search` | Behavior search | Finds code by pattern type |
| ADV-004 | `get_function_with_context` | Full context | Function + dependencies |
| ADV-005 | `get_data_structures` | Type definitions | Struct/class layouts |
| ADV-006 | `get_control_flow_graph` | CFG analysis | Basic blocks + edges |
| ADV-007 | `detect_vulnerabilities` | Security scan | CWE-mapped findings |
| ADV-008 | `find_similar_functions` | Code similarity | Similar function list |
| ADV-009 | `get_annotated_disassembly` | Rich disasm | Xrefs + comments inline |
| ADV-010 | `suggest_symbol_names` | Name suggestions | Context-based names |

### Phase 4: Android/Mobile Tools (5 Tests)

Use ARM ELF binaries (busybox or compiled JNI library).

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| AND-001 | `find_crypto_constants` | Crypto detection | AES/CRC constants found |
| AND-002 | `analyze_jni_methods` | JNI analysis | Java_* and JNI_OnLoad |
| AND-003 | `extract_api_endpoints` | API extraction | URLs/hostnames found |
| AND-004 | `find_hardcoded_secrets` | Secret detection | Keys/tokens identified |
| AND-005 | `compare_binaries` | Binary diff | Function differences |

### Phase 5: iOS Security Tools (8 Tests)

**Note:** These require macOS with iOS binaries (kernelcache, system binaries).

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| IOS-001 | `detect_kpp_ktrr` | Kernel protection | KPP/KTRR markers |
| IOS-002 | `analyze_mach_traps` | Syscall table | Trap handlers |
| IOS-003 | `find_pac_gadgets` | PAC gadgets | ARM64e gadgets |
| IOS-004 | `analyze_sandbox_ops` | Sandbox analysis | Policy checks |
| IOS-005 | `find_iokit_classes` | IOKit analysis | Class hierarchy |
| IOS-006 | `detect_entitlement_checks` | Entitlements | Validation code |
| IOS-007 | `find_kernel_symbols` | Kernel symbols | Symbol matches |
| IOS-008 | `analyze_mach_ports` | IPC analysis | Port operations |

### Phase 6: GUI/Context Tools (6 Tests)

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| GUI-001 | `gui_status` | Status check | Mode and connection info |
| GUI-002 | `set_current_address` | Set address | Context updated |
| GUI-003 | `get_current_address` | Get address | Returns set address |
| GUI-004 | `set_current_function` | Set function | Context updated |
| GUI-005 | `get_current_function` | Get function | Returns set function |
| GUI-006 | `get_current_selection` | Get selection | GUI mode message |

### Phase 7: System Tools (3 Tests)

| Test ID | Tool | Description | Expected Result |
|---------|------|-------------|-----------------|
| SYS-001 | `cache_stats` | Cache metrics | Hits/misses/size |
| SYS-002 | `cache_clear` | Clear cache | Entries removed |
| SYS-003 | `bridge_status` | Bridge check | Mode and status |

---

## Quick Start Test Commands

### 1. Setup Environment
```bash
# Set Ghidra path
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Verify installation
python -c "from kawaiidra_mcp.config import config; print(config)"
```

### 2. Prepare Test Binary
```bash
# Place in binaries folder
mkdir -p binaries
cp /path/to/test_binary binaries/

# Or download BusyBox
wget -O binaries/busybox https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
```

### 3. Run Tests
```bash
# Run automated test suite
python run_comprehensive_tests.py

# Run specific phase
python run_comprehensive_tests.py --phase 1

# Include iOS tests (macOS only)
python run_comprehensive_tests.py --ios
```

---

## Success Criteria

### Individual Test Pass Criteria
1. Tool executes without Python exception
2. Returns valid `TextContent` response
3. Response contains expected data format
4. No "Error" prefix in response (unless testing error handling)

### Phase Pass Criteria
- Phase 1 (Core): 100% pass rate required
- Phase 2 (Mod): 100% pass rate required
- Phase 3 (Advanced): ≥90% pass rate
- Phase 4 (Android): ≥80% pass rate (some features binary-dependent)
- Phase 5 (iOS): ≥80% pass rate on macOS (0% expected on Windows)
- Phase 6 (GUI): 100% pass rate
- Phase 7 (System): 100% pass rate

### Overall Pass Criteria
- Windows: Phases 1-4, 6-7 at ≥95% pass rate
- macOS: All phases at ≥90% pass rate

---

## Platform-Specific Notes

### Windows Testing
- All phases except iOS (Phase 5) fully supported
- iOS tools will execute but return limited/empty results
- Use `.exe` and Windows-compiled binaries

### macOS Testing
- Full support for all phases including iOS
- Can analyze Mach-O binaries natively
- For iOS kernelcache: Extract from IPSW using `img4tool`

### Linux Testing
- Phases 1-4, 6-7 fully supported
- ELF binaries work natively
- Cross-compile Windows PE for testing if needed

---

## Troubleshooting

### "Binary not found"
```bash
# Verify binary exists
ls -la binaries/

# Use absolute path
analyze_binary file_path="/full/path/to/binary"
```

### "Analysis timeout"
```bash
# Increase timeout
export KAWAIIDRA_TIMEOUT=600
```

### "No functions found"
- Binary may be stripped - expected behavior
- Try using `list_functions` with higher limit
- Check `get_binary_info` for format confirmation

### "Bridge not available"
```bash
# Install JPype
pip install JPype1

# Verify Java
java -version  # Requires JDK 17+
```

---

## Test Report Format

After running tests, generate a report:

```
================================================================================
KAWAIIDRA MCP TEST REPORT
Date: 2025-01-11
Platform: Windows 11 / Python 3.11 / Ghidra 11.2
================================================================================

Phase 1 - Core Tools:       17/17 PASS (100%)
Phase 2 - Modification:      6/6  PASS (100%)
Phase 3 - Advanced LLM:     10/10 PASS (100%)
Phase 4 - Android/Mobile:    5/5  PASS (100%)
Phase 5 - iOS Security:      0/8  SKIP (Windows - No iOS binaries)
Phase 6 - GUI/Context:       6/6  PASS (100%)
Phase 7 - System:            3/3  PASS (100%)

--------------------------------------------------------------------------------
TOTAL: 47/47 PASS (100%) - iOS tests skipped on Windows
================================================================================
```

---

## Contributing Test Cases

To add new test cases:

1. Add test definition to appropriate phase in this document
2. Update `run_comprehensive_tests.py` with new test
3. Provide sample binary or generation instructions
4. Document expected output format

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-11 | Initial test plan with 55 tools |
