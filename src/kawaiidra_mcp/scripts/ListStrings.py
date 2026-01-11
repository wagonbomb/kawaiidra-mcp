# @category MCP
# @runtime Jython
import json

min_len = 4
limit = 20
results = []
data_mgr = currentProgram.getListing()
count = 0

for data in data_mgr.getDefinedData(True):
    if count >= limit:
        break
    if data.hasStringValue():
        val = data.getValue()
        if val and len(str(val)) >= min_len:
            results.append({
                "address": str(data.getAddress()),
                "value": str(val)[:200],
                "length": len(str(val))
            })
            count += 1

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "strings": results}))
print("=== MCP_RESULT_END ===")
