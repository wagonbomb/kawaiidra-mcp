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

result = {"success": False, "message": ""}

try:
    addr_str = "0x140001000"
    label_name = 'mcp_renamed_label'

    addr = currentProgram.getAddressFactory().getAddress(addr_str)
    if addr is None:
        result["message"] = "Invalid address: " + addr_str
    else:
        symbol_table = currentProgram.getSymbolTable()
        if label_name:
            # Delete specific named label at address
            symbols = list(symbol_table.getSymbols(addr))
            deleted = False
            for sym in symbols:
                if _safe_str(sym.getName()) == label_name:
                    sym.delete()
                    deleted = True
                    result["success"] = True
                    result["message"] = "Deleted label '{}' at {}".format(label_name, addr_str)
                    break
            if not deleted:
                result["message"] = "Label '{}' not found at {}".format(label_name, addr_str)
        else:
            # Delete primary symbol at address
            sym = symbol_table.getPrimarySymbol(addr)
            if sym:
                sym_name = _safe_str(sym.getName())
                sym.delete()
                result["success"] = True
                result["message"] = "Deleted label '{}' at {}".format(sym_name, addr_str)
            else:
                result["message"] = "No label found at " + addr_str
except Exception as e:
    result["message"] = str(e)

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
