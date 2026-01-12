# @category MCP
# @runtime Jython
import json

gadget_type = "all"

# PAC instruction patterns (ARM64e)
PAC_SIGNING = ["pacia", "pacib", "pacda", "pacdb", "paciza", "pacizb", "pacdza", "pacdzb", "pacga"]
PAC_AUTH = ["autia", "autib", "autda", "autdb", "autiza", "autizb", "autdza", "autdzb"]
PAC_COMBINED = ["blraa", "blrab", "braa", "brab", "retaa", "retab", "eretaa", "eretab"]

results = {
    "signing_gadgets": [],
    "auth_gadgets": [],
    "bypass_candidates": [],
    "pac_instructions_found": 0
}

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()

# Scan all instructions
for func in fm.getFunctions(True):
    body = func.getBody()
    inst = listing.getInstructionAt(body.getMinAddress())

    while inst and body.contains(inst.getAddress()):
        mnemonic = inst.getMnemonicString().lower()

        # Check for PAC signing instructions
        if gadget_type in ["signing", "all"]:
            for pac_inst in PAC_SIGNING:
                if pac_inst in mnemonic:
                    results["signing_gadgets"].append({
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    })
                    results["pac_instructions_found"] += 1

        # Check for PAC auth instructions
        if gadget_type in ["auth", "all"]:
            for pac_inst in PAC_AUTH:
                if pac_inst in mnemonic:
                    results["auth_gadgets"].append({
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    })
                    results["pac_instructions_found"] += 1

        # Check for combined PAC+branch (potential bypass gadgets)
        if gadget_type in ["bypass", "all"]:
            for pac_inst in PAC_COMBINED:
                if pac_inst in mnemonic:
                    results["bypass_candidates"].append({
                        "address": str(inst.getAddress()),
                        "instruction": str(inst),
                        "function": func.getName(),
                        "mnemonic": mnemonic
                    })
                    results["pac_instructions_found"] += 1

        inst = inst.getNext()

    # Limit results
    if len(results["signing_gadgets"]) + len(results["auth_gadgets"]) + len(results["bypass_candidates"]) > 500:
        break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
