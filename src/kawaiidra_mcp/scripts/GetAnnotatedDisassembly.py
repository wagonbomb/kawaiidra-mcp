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

func = find_function("entry")
include_comments = true
include_xrefs = true

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: entry"}))
    print("=== MCP_RESULT_END ===")
else:
    listing = currentProgram.getListing()
    ref_mgr = currentProgram.getReferenceManager()
    body = func.getBody()

    instructions = []
    inst = listing.getInstructionAt(body.getMinAddress())

    while inst and body.contains(inst.getAddress()):
        addr = inst.getAddress()

        inst_info = {
            "address": str(addr),
            "bytes": " ".join(["%02x" % (b & 0xff) for b in inst.getBytes()]),
            "mnemonic": inst.getMnemonicString(),
            "operands": str(inst),
            "label": None,
            "comments": [],
            "xrefs_to": [],
            "xrefs_from": []
        }

        # Get labels/symbols
        sym = getSymbolAt(addr)
        if sym:
            inst_info["label"] = sym.getName()

        # Get comments
        if include_comments:
            eol_comment = listing.getComment(0, addr)  # EOL_COMMENT
            pre_comment = listing.getComment(1, addr)  # PRE_COMMENT
            post_comment = listing.getComment(2, addr)  # POST_COMMENT
            plate_comment = listing.getComment(3, addr)  # PLATE_COMMENT

            if eol_comment:
                inst_info["comments"].append({"type": "eol", "text": eol_comment})
            if pre_comment:
                inst_info["comments"].append({"type": "pre", "text": pre_comment})
            if post_comment:
                inst_info["comments"].append({"type": "post", "text": post_comment})

        # Get cross-references
        if include_xrefs:
            # References TO this address
            for ref in ref_mgr.getReferencesTo(addr):
                from_func = getFunctionContaining(ref.getFromAddress())
                inst_info["xrefs_to"].append({
                    "from": str(ref.getFromAddress()),
                    "from_func": from_func.getName() if from_func else None,
                    "type": str(ref.getReferenceType())
                })

            # References FROM this address
            for ref in ref_mgr.getReferencesFrom(addr):
                target_func = getFunctionAt(ref.getToAddress())
                # Check if it's a string reference
                data = listing.getDataAt(ref.getToAddress())
                string_val = None
                if data and data.hasStringValue():
                    val = data.getValue()
                    if val:
                        string_val = str(val)[:50]

                inst_info["xrefs_from"].append({
                    "to": str(ref.getToAddress()),
                    "to_func": target_func.getName() if target_func else None,
                    "to_string": string_val,
                    "type": str(ref.getReferenceType())
                })

        instructions.append(inst_info)
        inst = inst.getNext()

        if len(instructions) >= 500:  # Limit
            break

    result = {
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "instruction_count": len(instructions),
        "instructions": instructions
    }

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
