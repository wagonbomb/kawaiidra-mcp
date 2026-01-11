# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {"success": True, "exports": [], "total": 0}

try:
    symbol_table = currentProgram.getSymbolTable()
    exports = []
    count = 0

    for symbol in symbol_table.getAllSymbols(True):
        # Check if symbol is exported (external entry point or has GLOBAL scope)
        if symbol.isExternalEntryPoint() or (symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isGlobal()):
            if count >= 0 and len(exports) < 10:
                exports.append({
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "type": str(symbol.getSymbolType()),
                    "namespace": str(symbol.getParentNamespace().getName())
                })
            count += 1

    result["exports"] = exports
    result["total"] = count
except Exception as e:
    result = {"success": False, "error": str(e)}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
