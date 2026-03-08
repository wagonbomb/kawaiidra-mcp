# @category MCP
# @runtime Jython
import json

result = {"success": False, "message": ""}

try:
    addr_str = "0x140001000"
    category = "MCP_Test"
    comment = 'Test bookmark from MCP'

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        bm_mgr = currentProgram.getBookmarkManager()
        bm_mgr.setBookmark(addr, "Note", category, comment)
        result["success"] = True
        result["message"] = "Set bookmark at {} [{}]: {}".format(addr_str, category, comment)
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
