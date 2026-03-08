# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SourceType

def _safe_str(val):
    try:
        return str(val)
    except UnicodeEncodeError:
        try:
            return val.encode("ascii", "ignore")
        except:
            return ""

result = {"success": False, "message": ""}

try:
    addr_str = "0x140001000"
    old_name = "None"
    new_name = "mcp_renamed_label"

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        symbol_table = currentProgram.getSymbolTable()
        symbols = list(symbol_table.getSymbols(addr))
        renamed = False
        for sym in symbols:
            if _safe_str(sym.getName()) == old_name:
                sym.setName(new_name, SourceType.USER_DEFINED)
                renamed = True
                result["success"] = True
                result["message"] = "Renamed '{}' to '{}' at {}".format(old_name, new_name, addr_str)
                break
        if not renamed:
            result["message"] = "Label '{}' not found at {}".format(old_name, addr_str)
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
