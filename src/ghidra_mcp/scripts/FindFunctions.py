# @category MCP
# @runtime Jython
import json

pattern = "sdl".lower()
results = []
fm = currentProgram.getFunctionManager()

for func in fm.getFunctions(True):
    if pattern in func.getName().lower():
        results.append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "matches": results}))
print("=== MCP_RESULT_END ===")
