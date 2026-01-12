# @category MCP
# @runtime Jython
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def find_function(name):
    # Try by name
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]

    # Try as address
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr)
        if not func:
            func = getFunctionContaining(addr)
        return func
    except:
        return None

func = find_function("entry")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: entry"}))
    print("=== MCP_RESULT_END ===")
else:
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    results = decompiler.decompileFunction(func, 60, ConsoleTaskMonitor())

    if results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        print("=== MCP_RESULT_JSON ===")
        print(json.dumps({
            "success": True,
            "function": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "code": code
        }))
        print("=== MCP_RESULT_END ===")
    else:
        print("=== MCP_RESULT_JSON ===")
        print(json.dumps({"success": False, "error": results.getErrorMessage()}))
        print("=== MCP_RESULT_END ===")
