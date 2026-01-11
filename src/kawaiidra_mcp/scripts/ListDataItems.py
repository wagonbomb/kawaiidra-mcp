# @category MCP
# @runtime Jython
import json

result = {"success": True, "data_items": [], "total": 0}

try:
    listing = currentProgram.getListing()
    data_items = []
    count = 0

    for data in listing.getDefinedData(True):
        if count >= 0 and len(data_items) < 10:
            value_repr = ""
            try:
                val = data.getValue()
                if val is not None:
                    value_repr = str(val)[:100]  # Limit value string length
            except:
                pass

            data_items.append({
                "address": str(data.getAddress()),
                "label": str(data.getLabel()) if data.getLabel() else "",
                "type": str(data.getDataType().getName()),
                "size": data.getLength(),
                "value": value_repr
            })
        count += 1

    result["data_items"] = data_items
    result["total"] = count
except Exception as e:
    result = {"success": False, "error": str(e)}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
