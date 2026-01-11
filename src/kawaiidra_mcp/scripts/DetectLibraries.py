# @category MCP
# @runtime Jython
import json
import re

# Library detection patterns
LIBRARY_PATTERNS = {
    "OpenSSL": {
        "functions": ["SSL_", "EVP_", "CRYPTO_", "BIO_", "PEM_", "X509_", "RSA_", "AES_"],
        "strings": ["OpenSSL", "libssl", "libcrypto"]
    },
    "zlib": {
        "functions": ["inflate", "deflate", "compress", "uncompress", "gzip"],
        "strings": ["zlib", "1.2."]
    },
    "libcurl": {
        "functions": ["curl_", "CURL"],
        "strings": ["libcurl", "curl/"]
    },
    "Qt": {
        "functions": ["Q", "_ZN"],  # Qt classes start with Q, mangled names
        "strings": ["Qt", "QObject", "QWidget"]
    },
    "Boost": {
        "functions": ["boost_", "_ZN5boost"],
        "strings": ["boost::", "Boost"]
    },
    "libc/msvcrt": {
        "functions": ["printf", "malloc", "free", "strcpy", "strlen", "fopen", "fclose"],
        "strings": []
    },
    "Windows API": {
        "functions": ["CreateFile", "ReadFile", "WriteFile", "GetProcAddress", "LoadLibrary",
                     "VirtualAlloc", "CreateProcess", "RegOpenKey", "WSA"],
        "strings": ["kernel32", "ntdll", "user32", "advapi32", "ws2_32"]
    },
    "pthread": {
        "functions": ["pthread_"],
        "strings": ["libpthread"]
    },
    "SQLite": {
        "functions": ["sqlite3_"],
        "strings": ["sqlite", "SQLite"]
    },
    "libpng": {
        "functions": ["png_"],
        "strings": ["libpng", "PNG"]
    },
    "libjpeg": {
        "functions": ["jpeg_"],
        "strings": ["libjpeg", "JPEG"]
    }
}

detected = {}
detailed_flag = false

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
    matches = {"functions": [], "strings": [], "imports": []}

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
        detected[lib_name] = {
            "confidence": confidence,
            "match_count": total,
            "matches": matches if detailed_flag else None
        }

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "libraries": detected, "total_functions": len(all_funcs), "total_imports": len(imports)}))
print("=== MCP_RESULT_END ===")
