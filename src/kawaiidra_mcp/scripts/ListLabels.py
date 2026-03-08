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

filter_str = json.loads('"mcp_test"').lower()
start_str = json.loads('""')
end_str = json.loads('""')
limit = 20

symbol_table = currentProgram.getSymbolTable()
af = currentProgram.getAddressFactory()

start_addr = af.getAddress(start_str) if start_str else None
end_addr = af.getAddress(end_str) if end_str else None

results = []
for sym in symbol_table.getAllSymbols(True):
    if len(results) >= limit:
        break

    name = _safe_str(sym.getName())
    addr = sym.getAddress()

    # Apply filters
    if filter_str and filter_str not in name.lower():
        continue
    if start_addr and addr.compareTo(start_addr) < 0:
        continue
    if end_addr and addr.compareTo(end_addr) > 0:
        continue

    results.append({
        "name": name,
        "address": str(addr),
        "type": _safe_str(sym.getSymbolType()),
        "source": _safe_str(sym.getSource()),
        "namespace": _safe_str(sym.getParentNamespace().getName())
    })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "count": len(results), "labels": results}))
print("=== MCP_RESULT_END ===")
