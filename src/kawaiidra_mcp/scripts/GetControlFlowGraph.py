# @category MCP
# @runtime Jython
import json
from ghidra.program.model.block import BasicBlockModel

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
include_insts = true

if not func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: entry"}))
    print("=== MCP_RESULT_END ===")
else:
    bbm = BasicBlockModel(currentProgram)
    blocks = []
    edges = []
    block_map = {}

    # Get all basic blocks in function
    block_iter = bbm.getCodeBlocksContaining(func.getBody(), monitor)
    while block_iter.hasNext():
        block = block_iter.next()
        block_id = str(block.getFirstStartAddress())
        block_map[block_id] = len(blocks)

        block_info = {
            "id": block_id,
            "start": str(block.getFirstStartAddress()),
            "end": str(block.getMaxAddress()),
            "size": block.getNumAddresses()
        }

        # Get instructions if requested
        if include_insts:
            insts = []
            listing = currentProgram.getListing()
            inst = listing.getInstructionAt(block.getFirstStartAddress())
            while inst and block.contains(inst.getAddress()):
                insts.append({
                    "address": str(inst.getAddress()),
                    "mnemonic": inst.getMnemonicString(),
                    "operands": str(inst)
                })
                inst = inst.getNext()
                if len(insts) >= 50:  # Limit instructions per block
                    break
            block_info["instructions"] = insts

        blocks.append(block_info)

        # Get outgoing edges
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            dest_addr = str(dest.getDestinationAddress())
            flow_type = str(dest.getFlowType())
            edges.append({
                "from": block_id,
                "to": dest_addr,
                "type": flow_type
            })

        if len(blocks) >= 200:  # Limit total blocks
            break

    result = {
        "success": True,
        "function": func.getName(),
        "address": str(func.getEntryPoint()),
        "block_count": len(blocks),
        "edge_count": len(edges),
        "blocks": blocks,
        "edges": edges
    }

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
