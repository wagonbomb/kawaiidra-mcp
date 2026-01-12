# @category MCP
# @runtime Jython
import json

# KPP/KTRR detection patterns
KPP_INDICATORS = {
    "functions": [
        "kpp_", "monitor_", "rorgn_", "lockdown_",
        "ml_static_mfree", "pmap_protect", "kernel_memory_allocate",
        "PPL", "ppl_", "gxf_", "AMFI", "AppleMobileFileIntegrity"
    ],
    "strings": [
        "KTRR", "KPP", "Kernel Patch Protection", "text_readonly",
        "rorgn_begin", "rorgn_end", "__TEXT_EXEC", "__PPLTEXT",
        "Kernel text locked", "amfi_", "cs_enforcement",
        "APRR", "PPL violation", "code signature"
    ],
    "segments": ["__PPLTEXT", "__PPLDATA", "__TEXT_EXEC", "__KLD"]
}

detailed_flag = true

results = {
    "kpp_detected": False,
    "ktrr_detected": False,
    "ppl_detected": False,
    "amfi_detected": False,
    "indicators": [],
    "protection_functions": [],
    "protection_strings": [],
    "protected_segments": []
}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
mem = currentProgram.getMemory()

# Check for protection-related functions
for func in fm.getFunctions(True):
    func_name = func.getName().lower()
    for indicator in KPP_INDICATORS["functions"]:
        if indicator.lower() in func_name:
            results["protection_functions"].append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "indicator": indicator
            })
            if "kpp" in indicator.lower():
                results["kpp_detected"] = True
            if "ppl" in indicator.lower():
                results["ppl_detected"] = True
            if "amfi" in indicator.lower():
                results["amfi_detected"] = True

# Check for protection-related strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)
            for indicator in KPP_INDICATORS["strings"]:
                if indicator.lower() in str_val.lower():
                    results["protection_strings"].append({
                        "address": str(data.getAddress()),
                        "value": str_val[:100],
                        "indicator": indicator
                    })
                    if "ktrr" in indicator.lower():
                        results["ktrr_detected"] = True
                    if "kpp" in indicator.lower():
                        results["kpp_detected"] = True
                    if "ppl" in indicator.lower():
                        results["ppl_detected"] = True
                    if "amfi" in indicator.lower():
                        results["amfi_detected"] = True

# Check memory segments
for block in mem.getBlocks():
    block_name = block.getName()
    for seg in KPP_INDICATORS["segments"]:
        if seg in block_name:
            results["protected_segments"].append({
                "name": block_name,
                "start": str(block.getStart()),
                "size": block.getSize(),
                "permissions": (
                    ("r" if block.isRead() else "-") +
                    ("w" if block.isWrite() else "-") +
                    ("x" if block.isExecute() else "-")
                )
            })

# Build summary
results["summary"] = []
if results["kpp_detected"]:
    results["summary"].append("KPP (Kernel Patch Protection) detected")
if results["ktrr_detected"]:
    results["summary"].append("KTRR (Kernel Text Read-only Region) detected")
if results["ppl_detected"]:
    results["summary"].append("PPL (Page Protection Layer) detected")
if results["amfi_detected"]:
    results["summary"].append("AMFI (Apple Mobile File Integrity) detected")

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
