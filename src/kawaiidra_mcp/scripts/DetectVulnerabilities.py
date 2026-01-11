# @category MCP
# @runtime Jython
import json

# Vulnerability patterns
VULN_PATTERNS = {
    "buffer_overflow": {
        "severity": "high",
        "cwe": "CWE-120",
        "functions": ["strcpy", "strcat", "gets", "sprintf", "scanf", "vsprintf",
                     "lstrcpy", "lstrcpyA", "lstrcpyW", "StrCpy"],
        "description": "Unbounded string copy - potential buffer overflow"
    },
    "format_string": {
        "severity": "high",
        "cwe": "CWE-134",
        "functions": ["printf", "fprintf", "sprintf", "snprintf", "vprintf",
                     "syslog", "wprintf"],
        "description": "Potential format string vulnerability"
    },
    "command_injection": {
        "severity": "critical",
        "cwe": "CWE-78",
        "functions": ["system", "popen", "exec", "execl", "execle", "execlp",
                     "execv", "execve", "execvp", "ShellExecute", "WinExec",
                     "CreateProcess"],
        "description": "Command execution - potential command injection"
    },
    "path_traversal": {
        "severity": "high",
        "cwe": "CWE-22",
        "functions": ["fopen", "open", "CreateFile", "DeleteFile", "CopyFile",
                     "MoveFile", "LoadLibrary"],
        "description": "File operation - check for path traversal"
    },
    "memory_corruption": {
        "severity": "high",
        "cwe": "CWE-119",
        "functions": ["memcpy", "memmove", "memset", "bcopy", "CopyMemory"],
        "description": "Memory operation - verify bounds checking"
    },
    "integer_overflow": {
        "severity": "medium",
        "cwe": "CWE-190",
        "functions": ["malloc", "calloc", "realloc", "alloca", "HeapAlloc",
                     "VirtualAlloc", "LocalAlloc", "GlobalAlloc"],
        "description": "Memory allocation - check for integer overflow in size"
    },
    "use_after_free": {
        "severity": "critical",
        "cwe": "CWE-416",
        "functions": ["free", "delete", "HeapFree", "VirtualFree", "LocalFree",
                     "GlobalFree"],
        "description": "Memory deallocation - potential use-after-free"
    },
    "race_condition": {
        "severity": "medium",
        "cwe": "CWE-362",
        "functions": ["CreateThread", "pthread_create", "fork", "_beginthread",
                     "_beginthreadex"],
        "description": "Thread creation - check for race conditions"
    },
    "crypto_weak": {
        "severity": "medium",
        "cwe": "CWE-327",
        "functions": ["MD5", "SHA1", "DES", "RC4", "rand", "srand", "random"],
        "description": "Potentially weak cryptographic algorithm"
    }
}

severity_filter = "medium"
function_filter = "None" if "None" else None
severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "all": 0}

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
                                vulnerabilities.append({
                                    "type": vuln_type,
                                    "severity": vuln_info["severity"],
                                    "cwe": vuln_info["cwe"],
                                    "function": func.getName(),
                                    "function_address": str(func.getEntryPoint()),
                                    "call_address": str(addr),
                                    "target": target_name,
                                    "description": vuln_info["description"]
                                })
                                break

# Sort by severity
vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "vulnerabilities": vulnerabilities[:100], "functions_scanned": len(funcs)}))
print("=== MCP_RESULT_END ===")
