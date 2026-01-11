# @category MCP
# @runtime Jython
import json
from ghidra.program.model.symbol import RefType

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

func = find_function("0x14022C760")
direction = "to"

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: 0x14022C760"}))
    print("=== MCP_RESULT_END ===")
else:
    refs_to = []
    refs_from = []
    ref_mgr = currentProgram.getReferenceManager()

    # References TO this function
    if direction in ["to", "both"]:
        for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
            caller = getFunctionContaining(ref.getFromAddress())
            refs_to.append({
                "from_addr": str(ref.getFromAddress()),
                "from_func": caller.getName() if caller else "unknown",
                "type": str(ref.getReferenceType())
            })

    # References FROM this function
    if direction in ["from", "both"]:
        for addr in func.getBody().getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(addr):
                if ref.isMemoryReference():
                    target_func = getFunctionAt(ref.getToAddress())
                    if target_func:
                        refs_from.append({
                            "to_addr": str(ref.getToAddress()),
                            "to_func": target_func.getName(),
                            "type": str(ref.getReferenceType())
                        })

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({
        "success": True,
        "function": func.getName(),
        "refs_to": refs_to[:50],
        "refs_from": refs_from[:50]
    }))
    print("=== MCP_RESULT_END ===")
