# @category MCP
# @runtime Jython
import json

def _safe_str(val):
    try:
        return str(val)
    except UnicodeEncodeError:
        try:
            return val.encode("ascii", "ignore")
        except:
            return ""

pattern = "version".lower()
results = []
data_mgr = currentProgram.getListing()

for data in data_mgr.getDefinedData(True):
    if data.hasStringValue():
        try:
            val = data.getValue()
            s = _safe_str(val)
            if s and pattern in s.lower():
                results.append({
                    "address": str(data.getAddress()),
                    "value": s[:200]
                })
        except:
            pass

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "matches": results[:100]}))
print("=== MCP_RESULT_END ===")
