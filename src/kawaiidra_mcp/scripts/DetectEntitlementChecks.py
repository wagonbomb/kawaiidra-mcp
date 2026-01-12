# @category MCP
# @runtime Jython
import json

ent_filter = None

# Common iOS/macOS entitlements
KNOWN_ENTITLEMENTS = [
    "com.apple.private.security.container-required",
    "com.apple.private.skip-library-validation",
    "com.apple.private.amfi.can-load-cdhash",
    "platform-application",
    "get-task-allow",
    "task_for_pid-allow",
    "com.apple.system-task-ports",
    "com.apple.private.kernel.jit",
    "com.apple.private.kernel.override-cpufeatures",
    "com.apple.rootless.install",
    "com.apple.rootless.storage",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation"
]

# Entitlement check functions
ENT_CHECK_FUNCS = [
    "IOTaskHasEntitlement", "amfi_check_dyld_policy_self",
    "csblob_get_entitlements", "cs_entitlement_check",
    "sandbox_check_by_audit_token", "SecTaskCopyValueForEntitlement",
    "xpc_connection_get_entitlement_value", "proc_has_entitlement"
]

results = {
    "entitlement_strings": [],
    "check_functions": [],
    "check_sites": []
}

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
ref_mgr = currentProgram.getReferenceManager()

# Find entitlement strings
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        val = data.getValue()
        if val:
            str_val = str(val)

            is_entitlement = False
            if str_val.startswith("com.apple."):
                is_entitlement = True
            elif any(ent in str_val for ent in KNOWN_ENTITLEMENTS):
                is_entitlement = True

            if is_entitlement:
                if ent_filter is None or ent_filter.lower() in str_val.lower():
                    refs = list(ref_mgr.getReferencesTo(data.getAddress()))
                    ref_funcs = []
                    for ref in refs[:5]:
                        func = getFunctionContaining(ref.getFromAddress())
                        if func:
                            ref_funcs.append({
                                "name": func.getName(),
                                "address": str(ref.getFromAddress())
                            })

                    results["entitlement_strings"].append({
                        "entitlement": str_val[:150],
                        "address": str(data.getAddress()),
                        "checked_in": ref_funcs
                    })

# Find entitlement check functions
for func in fm.getFunctions(True):
    func_name = func.getName()
    for check_func in ENT_CHECK_FUNCS:
        if check_func.lower() in func_name.lower():
            # Find callers
            callers = []
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller:
                    callers.append(caller.getName())

            results["check_functions"].append({
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "called_by": list(set(callers))[:10]
            })
            break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
