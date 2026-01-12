# @category MCP
# @runtime Jython
import json

port_type_filter = "all"

# Mach port functions by category
PORT_FUNCTIONS = {
    "task": [
        "task_get_special_port", "task_set_special_port",
        "mach_port_allocate", "mach_port_insert_right",
        "task_suspend", "task_resume", "task_threads",
        "task_for_pid", "pid_for_task"
    ],
    "thread": [
        "thread_create", "thread_terminate", "thread_suspend",
        "thread_get_state", "thread_set_state", "thread_create_running"
    ],
    "host": [
        "host_get_special_port", "host_set_special_port",
        "host_processor_info", "host_info", "host_priv_port"
    ],
    "general": [
        "mach_msg", "mach_msg_overwrite", "mach_port_deallocate",
        "mach_port_mod_refs", "mach_port_destroy", "ipc_port",
        "convert_port_to_task", "convert_task_to_port"
    ]
}

results = {
    "port_operations": [],
    "ipc_patterns": [],
    "dangerous_operations": []
}

fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()

# Build list of functions to search for
search_funcs = []
if port_type_filter == "all":
    for funcs in PORT_FUNCTIONS.values():
        search_funcs.extend(funcs)
else:
    search_funcs = PORT_FUNCTIONS.get(port_type_filter, [])
    search_funcs.extend(PORT_FUNCTIONS.get("general", []))

# Dangerous operations (security-sensitive)
DANGEROUS_OPS = ["task_for_pid", "convert_port_to_task", "thread_create_running",
                 "mach_port_insert_right", "host_priv_port"]

# Find port-related functions
for func in fm.getFunctions(True):
    func_name = func.getName()

    for search_func in search_funcs:
        if search_func.lower() in func_name.lower():
            # Get callers
            callers = []
            for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
                caller = getFunctionContaining(ref.getFromAddress())
                if caller and caller.getName() != func_name:
                    callers.append(caller.getName())

            entry = {
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "called_by": list(set(callers))[:10],
                "category": next((cat for cat, funcs in PORT_FUNCTIONS.items() if search_func in funcs), "general")
            }

            # Check if dangerous
            if any(danger in func_name.lower() for danger in [d.lower() for d in DANGEROUS_OPS]):
                results["dangerous_operations"].append(entry)
            else:
                results["port_operations"].append(entry)

            break

# Find mach_msg patterns (IPC)
for func in fm.getFunctions(True):
    func_name = func.getName()
    if "mach_msg" in func_name.lower() or "mig_" in func_name.lower():
        results["ipc_patterns"].append({
            "name": func_name,
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses()
        })

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
