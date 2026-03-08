# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType

result = {"success": False, "message": ""}

try:
    addr_str = "0x140001000"
    label_name = "mcp_test_label"

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        symbol_table = currentProgram.getSymbolTable()
        symbol = symbol_table.createLabel(addr, label_name, SourceType.USER_DEFINED)
        if symbol:
            result["success"] = True
            result["message"] = "Created label '{}' at {}".format(label_name, addr_str)
        else:
            result["message"] = "Failed to create label at " + addr_str
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
