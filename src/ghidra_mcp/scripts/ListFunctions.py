# @category MCP
# @runtime Jython
import json

results = []
fm = currentProgram.getFunctionManager()
count = 0
limit = 50

for func in fm.getFunctions(True):
    if count >= limit:
        break
    results.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses()
    })
    count += 1

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "functions": results, "total": fm.getFunctionCount()}))
print("=== MCP_RESULT_END ===")
