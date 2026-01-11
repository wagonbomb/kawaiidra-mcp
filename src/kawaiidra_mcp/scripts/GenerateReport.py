# @category MCP
# @runtime Jython
import json
import re
from datetime import datetime
from collections import defaultdict

# Import Ghidra classes
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface

depth = "quick"
include_decompilation = False
max_functions_decompile = 0

report = {
    "meta": {},
    "binary_info": {},
    "memory_layout": [],
    "symbols": {"exports": [], "imports": [], "namespaces": []},
    "functions": {"total": 0, "list": [], "entry_points": [], "by_size": [], "most_referenced": []},
    "strings": {"total": 0, "interesting": [], "urls": [], "paths": [], "ips": [], "samples": []},
    "data_items": [],
    "libraries": [],
    "behavioral": {"file_io": [], "network": [], "crypto": [], "process": [], "memory": []},
    "vulnerabilities": [],
    "decompiled_functions": [],
    "call_graph": {},
    "ios_analysis": {},
    "recommendations": []
}

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
    report["binary_info"] = {
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
    }

    # =========================================================================
    # 3. MEMORY LAYOUT
    # =========================================================================
    for block in memory.getBlocks():
        perms = ""
        if block.isRead(): perms += "R"
        if block.isWrite(): perms += "W"
        if block.isExecute(): perms += "X"
        report["memory_layout"].append({
            "name": block.getName(),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": block.getSize(),
            "permissions": perms,
            "type": str(block.getType()),
            "initialized": block.isInitialized()
        })

    # =========================================================================
    # 4. SYMBOLS - EXPORTS
    # =========================================================================
    export_count = 0
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint() or (symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isGlobal()):
            if export_count < 200:  # Limit for report size
                report["symbols"]["exports"].append({
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType())
                })
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
                report["symbols"]["imports"].append({
                    "name": symbol.getName(),
                    "library": lib,
                    "address": str(symbol.getAddress())
                })
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
                    report["symbols"]["namespaces"].append({
                        "name": ns.getName(),
                        "full_path": ns_name
                    })
                ns_count += 1
            ns = ns.getParentNamespace()

    # =========================================================================
    # 7. FUNCTIONS ANALYSIS
    # =========================================================================
    functions_data = []
    func_refs = {}  # Track references to each function

    for func in func_manager.getFunctions(True):
        addr = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses() if body else 0

        # Count incoming references
        ref_count = 0
        for ref in ref_manager.getReferencesTo(addr):
            ref_count += 1
        func_refs[func.getName()] = ref_count

        func_data = {
            "name": func.getName(),
            "address": str(addr),
            "size": size,
            "param_count": func.getParameterCount(),
            "is_thunk": func.isThunk(),
            "is_external": func.isExternal(),
            "calling_convention": str(func.getCallingConventionName()),
            "ref_count": ref_count
        }

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
    interesting_patterns = {
        "urls": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.I),
        "ips": re.compile(r'\b(?:\d{1,3}\.?){4}\b'),
        "paths": re.compile(r'[A-Za-z]:\\[^\s]+|/(?:usr|etc|var|home|tmp|bin|opt)/[^\s]+'),
        "emails": re.compile(r'[\w.-]+@[\w.-]+\.\w+'),
        "potential_secrets": re.compile(r'(?:password|passwd|pwd|secret|key|token|api_key|apikey|auth)[\s]*[=:][\s]*[^\s]+', re.I)
    }

    string_count = 0
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            try:
                val = str(data.getValue())
                if len(val) >= 4:
                    str_entry = {
                        "address": str(data.getAddress()),
                        "value": val[:200],  # Truncate long strings
                        "length": len(val)
                    }

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
        behavioral_patterns = {
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
        }

        for category, patterns in behavioral_patterns.items():
            for func in func_manager.getFunctions(True):
                func_name = func.getName().lower()
                for pattern in patterns:
                    if pattern.lower() in func_name:
                        report["behavioral"][category].append({
                            "function": func.getName(),
                            "address": str(func.getEntryPoint()),
                            "pattern": pattern
                        })
                        break

    # =========================================================================
    # 10. LIBRARY DETECTION
    # =========================================================================
    lib_signatures = {
        "OpenSSL": ["SSL_", "EVP_", "CRYPTO_", "BIO_", "X509_"],
        "zlib": ["inflate", "deflate", "compress", "uncompress", "gzopen"],
        "libcurl": ["curl_easy_", "curl_multi_", "CURLOPT_"],
        "SQLite": ["sqlite3_open", "sqlite3_exec", "sqlite3_prepare"],
        "Qt": ["Q_OBJECT", "QWidget", "QString", "QApplication"],
        "Boost": ["boost::", "_ZN5boost"],
        "Windows API": ["kernel32", "ntdll", "user32", "advapi32"],
        "CRT": ["printf", "scanf", "malloc", "free", "strcpy", "strlen"]
    }

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
        report["libraries"].append({
            "name": lib_name,
            "confidence": "high" if len(matches) >= 3 else "medium",
            "evidence": matches[:5]
        })

    # =========================================================================
    # 11. VULNERABILITY DETECTION
    # =========================================================================
    vuln_patterns = {
        "buffer_overflow": {
            "functions": ["strcpy", "strcat", "sprintf", "gets", "scanf"],
            "severity": "high",
            "cwe": "CWE-120"
        },
        "format_string": {
            "functions": ["printf", "sprintf", "fprintf", "syslog"],
            "severity": "high",
            "cwe": "CWE-134"
        },
        "command_injection": {
            "functions": ["system", "popen", "exec", "ShellExecute", "WinExec"],
            "severity": "critical",
            "cwe": "CWE-78"
        },
        "memory_corruption": {
            "functions": ["memcpy", "memmove", "memset"],
            "severity": "medium",
            "cwe": "CWE-119"
        },
        "use_after_free": {
            "functions": ["free", "delete", "HeapFree"],
            "severity": "high",
            "cwe": "CWE-416"
        }
    }

    for vuln_type, vuln_info in vuln_patterns.items():
        for func in func_manager.getFunctions(True):
            func_name = func.getName().lower()
            for dangerous_func in vuln_info["functions"]:
                if dangerous_func.lower() == func_name or func_name.endswith("_" + dangerous_func.lower()):
                    # Count callers to assess risk
                    caller_count = 0
                    for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
                        caller_count += 1

                    report["vulnerabilities"].append({
                        "type": vuln_type,
                        "function": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "severity": vuln_info["severity"],
                        "cwe": vuln_info["cwe"],
                        "caller_count": caller_count,
                        "description": "Usage of potentially dangerous function"
                    })
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
                                report["decompiled_functions"].append({
                                    "name": func_name,
                                    "address": str(func.getEntryPoint()),
                                    "code": code[:5000]  # Limit size
                                })
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
            ios_markers = {
                "entitlements": ["SecTask", "entitlement", "amfi", "AppleMobileFileIntegrity"],
                "sandbox": ["sandbox_check", "sandbox_init", "sandbox_extension"],
                "mach_ports": ["mach_port", "mach_msg", "task_for_pid", "thread_create"],
                "kpp_ktrr": ["kpp", "ktrr", "ppl_", "amcc", "__TEXT_EXEC"]
            }

            for category, markers in ios_markers.items():
                for marker in markers:
                    for symbol in symbol_table.getAllSymbols(True):
                        if marker.lower() in symbol.getName().lower():
                            if category not in report["ios_analysis"]:
                                report["ios_analysis"][category] = []
                            report["ios_analysis"][category].append({
                                "symbol": symbol.getName(),
                                "address": str(symbol.getAddress())
                            })

    # =========================================================================
    # 14. RECOMMENDATIONS
    # =========================================================================
    # Suggest renames for auto-generated function names
    for func_data in report["functions"]["most_referenced"][:10]:
        if func_data["name"].startswith("FUN_") or func_data["name"].startswith("sub_"):
            report["recommendations"].append({
                "type": "rename_suggestion",
                "target": func_data["name"],
                "address": func_data["address"],
                "reason": "High-traffic function with auto-generated name should be analyzed and renamed"
            })

    # Flag functions that need investigation
    for vuln in report["vulnerabilities"]:
        if vuln["severity"] in ["critical", "high"] and vuln["caller_count"] > 0:
            report["recommendations"].append({
                "type": "security_review",
                "target": vuln["function"],
                "address": vuln["address"],
                "reason": "Dangerous function with " + str(vuln["caller_count"]) + " callers - verify safe usage"
            })

    result = {"success": True, "report": report}
except Exception as e:
    import traceback
    result = {"success": False, "error": str(e), "traceback": traceback.format_exc()}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
