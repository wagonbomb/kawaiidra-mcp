# @category MCP
# @runtime Jython
import json

operation_filter = None

# Known sandbox operations
SANDBOX_OPS = [
    "file-read-data", "file-write-data", "file-read-metadata",
    "file-write-create", "file-write-unlink", "file-read-xattr",
    "process-fork", "process-exec", "signal",
    "mach-lookup", "mach-register", "mach-task-name",
    "network-outbound", "network-inbound", "network-bind",
    "ipc-posix-shm", "ipc-posix-sem", "sysctl-read", "sysctl-write",
    "iokit-open", "iokit-get-properties", "iokit-set-properties",
    "system-socket", "system-sysctl", "nvram-get", "nvram-set"
]

# Sandbox-related functions
SANDBOX_FUNCS = [
    "sandbox_check", "sandbox_init", "sandbox_free_error",
    "sandbox_apply", "sandbox_extension", "sandbox_container",
    "sb_evaluate", "mac_sandbox", "mpo_", "cred_check"
]

results = {
    "sandbox_functions": [],
    "sandbox_ops_strings": [],
    "policy_checks": [],
    "mach_lookups": []
}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

# Find sandbox-related functions
for func in fm.getFunctions(True):
    func_name = func.getName().lower()
    for sb_func in SANDBOX_FUNCS:
        if sb_func.lower() in func_name:
            results["sandbox_functions"].append({
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses()
            })
            break

# Find sandbox operation strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)

            # Check if it's a sandbox operation
            for op in SANDBOX_OPS:
                if op in str_val.lower():
                    if operation_filter is None or operation_filter.lower() in str_val.lower():
                        # Find references to this string
                        refs = list(ref_mgr.getReferencesTo(data.getAddress()))
                        ref_funcs = []
                        for ref in refs[:5]:
                            func = getFunctionContaining(ref.getFromAddress())
                            if func:
                                ref_funcs.append(func.getName())

                        results["sandbox_ops_strings"].append({
                            "operation": str_val[:100],
                            "address": str(data.getAddress()),
                            "referenced_by": ref_funcs
                        })
                    break

            # Check for mach-lookup operations
            if "mach-lookup" in str_val.lower() or str_val.startswith("com.apple."):
                results["mach_lookups"].append({
                    "service": str_val[:100],
                    "address": str(data.getAddress())
                })

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
