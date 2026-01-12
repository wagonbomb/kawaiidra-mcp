# @category MCP
# @runtime Jython
import json
from collections import Counter

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

def get_function_fingerprint(func):
    """Create a fingerprint of the function for comparison."""
    if not func:
        return None

    listing = currentProgram.getListing()
    body = func.getBody()

    # Collect mnemonics
    mnemonics = []
    inst = listing.getInstructionAt(body.getMinAddress())
    while inst and body.contains(inst.getAddress()):
        mnemonics.append(inst.getMnemonicString())
        inst = inst.getNext()

    # Count mnemonic frequencies
    mnem_counts = Counter(mnemonics)

    # Get reference counts
    ref_mgr = currentProgram.getReferenceManager()
    call_count = 0
    data_ref_count = 0
    for addr in body.getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                call_count += 1
            elif ref.getReferenceType().isData():
                data_ref_count += 1

    return {
        "size": body.getNumAddresses(),
        "instruction_count": len(mnemonics),
        "mnemonic_counts": dict(mnem_counts),
        "call_count": call_count,
        "data_ref_count": data_ref_count,
        "param_count": func.getParameterCount()
    }

def compare_fingerprints(fp1, fp2):
    """Compare two fingerprints and return similarity score."""
    if not fp1 or not fp2:
        return 0.0

    # Size similarity
    size_sim = 1.0 - abs(fp1["size"] - fp2["size"]) / max(fp1["size"], fp2["size"], 1)

    # Instruction count similarity
    inst_sim = 1.0 - abs(fp1["instruction_count"] - fp2["instruction_count"]) / max(fp1["instruction_count"], fp2["instruction_count"], 1)

    # Mnemonic distribution similarity (Jaccard)
    m1 = set(fp1["mnemonic_counts"].keys())
    m2 = set(fp2["mnemonic_counts"].keys())
    mnem_sim = len(m1 & m2) / max(len(m1 | m2), 1)

    # Call count similarity
    call_sim = 1.0 - abs(fp1["call_count"] - fp2["call_count"]) / max(fp1["call_count"], fp2["call_count"], 1)

    # Parameter count similarity
    param_sim = 1.0 if fp1["param_count"] == fp2["param_count"] else 0.5

    # Weighted average
    return (size_sim * 0.2 + inst_sim * 0.2 + mnem_sim * 0.3 + call_sim * 0.2 + param_sim * 0.1)

ref_func = find_function("entry")
threshold = 0.7

if not ref_func:
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps({"success": False, "error": "Function not found: entry"}))
    print("=== MCP_RESULT_END ===")
else:
    ref_fp = get_function_fingerprint(ref_func)
    similar = []

    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        if func.getEntryPoint() == ref_func.getEntryPoint():
            continue

        fp = get_function_fingerprint(func)
        sim = compare_fingerprints(ref_fp, fp)

        if sim >= threshold:
            similar.append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "similarity": round(sim, 3),
                "size": fp["size"] if fp else 0,
                "instruction_count": fp["instruction_count"] if fp else 0
            })

    # Sort by similarity
    similar.sort(key=lambda x: x["similarity"], reverse=True)

    result = {
        "success": True,
        "reference": {
            "name": ref_func.getName(),
            "address": str(ref_func.getEntryPoint()),
            "fingerprint": ref_fp
        },
        "similar_functions": similar[:50],
        "threshold": threshold
    }

    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(result))
    print("=== MCP_RESULT_END ===")
