# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {"success": True, "namespaces": [], "total": 0}

try:
    symbol_table = currentProgram.getSymbolTable()
    namespaces = []
    count = 0
    seen = set()

    # Get all namespaces
    for symbol in symbol_table.getAllSymbols(True):
        ns = symbol.getParentNamespace()
        while ns and not ns.isGlobal():
            ns_name = ns.getName(True)  # Full path
            if ns_name not in seen:
                seen.add(ns_name)
                if count >= 0 and len(namespaces) < 10:
                    ns_type = "Class" if hasattr(ns, 'getSymbol') and ns.getSymbol() and "class" in str(ns.getSymbol().getSymbolType()).lower() else "Namespace"
                    namespaces.append({
                        "name": ns.getName(),
                        "full_path": ns_name,
                        "type": ns_type,
                        "symbol_count": len(list(symbol_table.getSymbols(ns)))
                    })
                count += 1
            ns = ns.getParentNamespace()

    result["namespaces"] = namespaces
    result["total"] = count
except Exception as e:
    result = {"success": False, "error": str(e)}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
