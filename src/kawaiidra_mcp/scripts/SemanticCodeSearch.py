# @category MCP
# @runtime Jython
import json

search_terms = ["CreateProcess", "OpenProcess", "TerminateProcess", "GetCurrentProcess", "fork", "exec", "system", "popen", "WinExec", "ShellExecute", "CreateThread", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory"]
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
            func_matches.append({"type": "name_match", "term": term})

    # Check calls from this function
    for addr in func.getBody().getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target_func = getFunctionAt(ref.getToAddress())
                if target_func:
                    target_name = target_func.getName().lower()
                    for term in search_terms:
                        if term.lower() in target_name:
                            func_matches.append({
                                "type": "calls",
                                "target": target_func.getName(),
                                "address": str(ref.getFromAddress())
                            })

    if func_matches:
        matches.append({
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "matches": func_matches[:10]  # Limit matches per function
        })

    if len(matches) >= 100:  # Limit total results
        break

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "pattern": "process", "results": matches}))
print("=== MCP_RESULT_END ===")
