# @category MCP
# @runtime Jython
import json

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()

# Collect functions
functions = []
for func in fm.getFunctions(True):
    functions.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "signature": str(func.getSignature())
    })

# Collect strings
strings = []
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            strings.append({
                "address": str(data.getAddress()),
                "value": str(val)[:500]
            })

# Collect imports/exports
imports = []
exports = []
sym_table = prog.getSymbolTable()
for sym in sym_table.getAllSymbols(True):
    if sym.isExternal():
        imports.append({
            "name": sym.getName(),
            "address": str(sym.getAddress())
        })
    elif sym.getSymbolType().toString() == "Function" and sym.isGlobal():
        exports.append({
            "name": sym.getName(),
            "address": str(sym.getAddress())
        })

result = {
    "binary": prog.getName(),
    "functions": functions,
    "strings": strings[:500],
    "imports": imports,
    "exports": exports[:100]
}

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "data": result}))
print("=== MCP_RESULT_END ===")
