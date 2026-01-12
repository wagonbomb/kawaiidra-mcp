# @category MCP
# @runtime Jython
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import json

def find_function(name):
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

def decompile_func(func, decompiler):
    if not func:
        return None
    results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
    if results.decompileCompleted():
        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "code": results.getDecompiledFunction().getC()
        }
    return None

func = find_function("entry")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: entry"}))
    print("=== MCP_RESULT_END ===")
else:
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = {"success": True}

    # Decompile main function
    main_decomp = decompile_func(func, decompiler)
    if main_decomp:
        result["function"] = main_decomp

    # Get callees
    if true:
        callees = []
        ref_mgr = currentProgram.getReferenceManager()
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.getReferenceType().isCall():
                    target = getFunctionAt(ref.getToAddress())
                    if target and not target.isThunk() and len(callees) < 10:
                        decomp = decompile_func(target, decompiler)
                        if decomp:
                            callees.append(decomp)
        result["callees"] = callees

    # Get callers
    if false:
        callers = []
        ref_mgr = currentProgram.getReferenceManager()
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            if ref.getReferenceType().isCall():
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and len(callers) < 5:
                    decomp = decompile_func(caller, decompiler)
                    if decomp:
                        callers.append(decomp)
        result["callers"] = callers

    # Get referenced strings
    strings = []
    listing = currentProgram.getListing()
    for addr in func.getBody().getAddresses(True):
        refs = currentProgram.getReferenceManager().getReferencesFrom(addr)
        for ref in refs:
            data = listing.getDataAt(ref.getToAddress())
            if data and data.hasStringValue():
                val = data.getValue()
                if val:
                    strings.append({"address": str(data.getAddress()), "value": str(val)[:200]})
    result["strings"] = strings[:20]

    # Get data types (if enabled)
    if true:
        types_used = []
        # Get parameter types
        for param in func.getParameters():
            dt = param.getDataType()
            types_used.append({"name": dt.getName(), "size": dt.getLength(), "source": "parameter"})
        # Get return type
        rt = func.getReturnType()
        if rt:
            types_used.append({"name": rt.getName(), "size": rt.getLength(), "source": "return"})
        result["data_types"] = types_used[:20]

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
