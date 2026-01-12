# @category MCP
# @runtime Jython
import json

trap_number = None

# Known Mach trap names
MACH_TRAPS = {
    -10: "kern_invalid",
    -26: "mach_reply_port",
    -27: "thread_self_trap",
    -28: "task_self_trap",
    -29: "host_self_trap",
    -31: "mach_msg_trap",
    -32: "mach_msg_overwrite_trap",
    -33: "semaphore_signal_trap",
    -34: "semaphore_signal_all_trap",
    -36: "semaphore_wait_trap",
    -41: "task_for_pid",
    -45: "pid_for_task",
    -48: "macx_swapon",
    -49: "macx_swapoff",
    -51: "macx_triggers",
    -59: "swtch_pri",
    -60: "swtch",
    -61: "thread_switch",
    -89: "mach_timebase_info_trap",
    -90: "mach_wait_until_trap",
    -91: "mk_timer_create_trap",
    -92: "mk_timer_destroy_trap",
    -93: "mk_timer_arm_trap",
    -94: "mk_timer_cancel_trap"
}

results = {
    "trap_table_found": False,
    "traps": [],
    "syscall_handlers": []
}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()

# Search for mach trap table
for sym in sym_table.getAllSymbols(True):
    sym_name = sym.getName()
    if "mach_trap_table" in sym_name.lower() or "mach_trap" in sym_name.lower():
        results["trap_table_found"] = True
        results["traps"].append({
            "symbol": sym_name,
            "address": str(sym.getAddress())
        })

# Search for known trap handler functions
for func in fm.getFunctions(True):
    func_name = func.getName()

    # Check against known trap names
    for trap_num, trap_name in MACH_TRAPS.items():
        if trap_name in func_name or func_name.startswith("_" + trap_name):
            if trap_number is None or trap_num == trap_number:
                results["syscall_handlers"].append({
                    "trap_number": trap_num,
                    "name": func_name,
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses()
                })

    # Also check for generic mach_msg patterns
    if any(x in func_name.lower() for x in ["mach_msg", "mach_port", "ipc_", "mig_"]):
        if trap_number is None:
            results["syscall_handlers"].append({
                "trap_number": "N/A",
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses()
            })

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
