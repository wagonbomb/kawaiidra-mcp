# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import SymbolType

result = {"success": True, "imports": [], "total": 0}

try:
    symbol_table = currentProgram.getSymbolTable()
    ext_manager = currentProgram.getExternalManager()
    imports = []
    count = 0

    # Get external symbols (imports)
    for symbol in symbol_table.getExternalSymbols():
        if count >= 0 and len(imports) < 10:
            ext_loc = symbol.getExternalLocation() if hasattr(symbol, 'getExternalLocation') else None
            library = ""
            if ext_loc:
                library = str(ext_loc.getLibraryName()) if ext_loc.getLibraryName() else ""
            imports.append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "library": library,
                "type": str(symbol.getSymbolType())
            })
        count += 1

    result["imports"] = imports
    result["total"] = count
except Exception as e:
    result = {"success": False, "error": str(e)}

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
