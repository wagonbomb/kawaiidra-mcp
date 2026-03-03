# @category MCP
# @runtime Jython
import json

LIBRARY_PATTERNS = {
    "OpenSSL": {
        "functions": ["SSL_", "EVP_", "CRYPTO_", "BIO_", "PEM_", "X509_", "RSA_", "AES_"],
        "strings": ["OpenSSL", "libssl", "libcrypto"]
    },
    "zlib": {
        "functions": ["inflate", "deflate", "compress", "uncompress", "crc32"],
        "strings": ["zlib", "1.2."]
    },
    "libcurl": {
        "functions": ["curl_", "CURL"],
        "strings": ["libcurl", "curl/"]
    },
    "Qt": {
        "functions": ["_ZN"],
        "strings": ["QObject", "QWidget"]
    },
    "Boost": {
        "functions": ["boost_", "_ZN5boost"],
        "strings": ["boost::"]
    },
    "CRT": {
        "functions": ["printf", "malloc", "free", "strcpy", "strlen", "fopen"],
        "strings": []
    },
    "Windows API": {
        "functions": ["CreateFile", "ReadFile", "WriteFile", "GetProcAddress", "LoadLibrary",
                     "VirtualAlloc", "CreateProcess", "WSA"],
        "strings": ["kernel32", "ntdll", "user32", "advapi32", "ws2_32"]
    },
    "ENet": {
        "functions": ["enet_"],
        "strings": []
    },
    "SDL": {
        "functions": ["SDL_"],
        "strings": []
    },
    "SDL_mixer": {
        "functions": ["Mix_"],
        "strings": []
    },
    "SDL_image": {
        "functions": ["IMG_"],
        "strings": []
    },
    "OpenGL": {
        "functions": ["glCreateShader", "glCompileShader", "glBindTexture", "glDrawArrays"],
        "strings": []
    },
    "Tiger Hash": {
        "functions": ["tiger"],
        "strings": ["Tiger - A Fast New Hash"]
    }
}

detected = {}

fm = currentProgram.getFunctionManager()
all_funcs = []
for func in fm.getFunctions(True):
    try:
        all_funcs.append(func.getName())
    except:
        pass

all_strings = []
listing = currentProgram.getListing()
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        try:
            val = data.getValue()
            if val:
                s = str(val).encode("ascii", "ignore").decode("ascii")
                if s:
                    all_strings.append(s)
        except:
            pass

imports = []
sym_table = currentProgram.getSymbolTable()
for sym in sym_table.getExternalSymbols():
    try:
        imports.append(sym.getName())
    except:
        pass

for lib_name, patterns in LIBRARY_PATTERNS.items():
    matches = {"functions": [], "strings": [], "imports": []}

    for func_name in all_funcs:
        if len(matches["functions"]) >= 20:
            break
        for pattern in patterns["functions"]:
            if pattern in func_name:
                if func_name not in matches["functions"]:
                    matches["functions"].append(func_name)
                break

    for string in all_strings[:5000]:
        if len(matches["strings"]) >= 10:
            break
        for pattern in patterns["strings"]:
            if pattern.lower() in string.lower():
                if string not in matches["strings"]:
                    matches["strings"].append(string[:100])
                break

    for imp in imports:
        if len(matches["imports"]) >= 20:
            break
        for pattern in patterns["functions"]:
            if pattern in imp:
                if imp not in matches["imports"]:
                    matches["imports"].append(imp)
                break

    total = len(matches["functions"]) + len(matches["strings"]) + len(matches["imports"])
    if total > 0:
        confidence = "high" if total > 5 else "medium" if total > 2 else "low"
        detected[lib_name] = {
            "confidence": confidence,
            "match_count": total,
            "sample_functions": matches["functions"][:5],
            "sample_strings": matches["strings"][:5],
            "sample_imports": matches["imports"][:5]
        }

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "libraries": detected, "total_functions": len(all_funcs), "total_imports": len(imports), "total_strings": len(all_strings)}))
print("=== MCP_RESULT_END ===")
