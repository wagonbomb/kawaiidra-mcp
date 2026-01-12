# @category MCP
# @runtime Jython
import json

pattern = "aes".lower()
results = []
data_mgr = currentProgram.getListing()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val and pattern in str(val).lower():
            results.append({
                "address": str(data.getAddress()),
                "value": str(val)[:200]
            })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "matches": results[:100]}))
print("=== MCP_RESULT_END ===")
