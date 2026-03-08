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

addr_str = "0x140001000"
limit = 100

addr = currentProgram.getAddressFactory().getAddress(addr_str)
if addr is None:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Invalid address: " + addr_str}))
    print("=== MCP_RESULT_END ===")
else:
    ref_mgr = currentProgram.getReferenceManager()
    refs = []
    for ref in ref_mgr.getReferencesTo(addr):
        if len(refs) >= limit:
            break
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        refs.append({
            "from_address": str(from_addr),
            "from_function": _safe_str(func.getName()) if func else None,
            "type": _safe_str(ref.getReferenceType()),
            "is_call": ref.getReferenceType().isCall(),
            "is_data": ref.getReferenceType().isData()
        })

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": True, "address": addr_str, "count": len(refs), "references": refs}))
    print("=== MCP_RESULT_END ===")
