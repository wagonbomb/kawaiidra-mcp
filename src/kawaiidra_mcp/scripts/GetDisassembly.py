# @category MCP
# @runtime Jython
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

func = find_function("ISWATER")

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: ISWATER"}))
    print("=== MCP_RESULT_END ===")
else:
    listing = currentProgram.getListing()
    body = func.getBody()
    instructions = []

    inst = listing.getInstructionAt(body.getMinAddress())
    while inst and body.contains(inst.getAddress()):
        instructions.append({
            "address": str(inst.getAddress()),
            "mnemonic": inst.getMnemonicString(),
            "operands": str(inst)
        })
        inst = inst.getNext()

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "instructions": instructions
    }))
    print("=== MCP_RESULT_END ===")
