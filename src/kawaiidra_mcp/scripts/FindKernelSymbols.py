# @category MCP
# @runtime Jython
import json

pattern_filter = None
symbol_type = "all"

# Important kernel symbols for research
IMPORTANT_SYMBOLS = [
    "kernel_map", "kernel_task", "kernproc", "realhost",
    "zone_array", "kalloc", "kfree", "ipc_port_alloc",
    "task_zone", "thread_zone", "ipc_space_kernel",
    "IORegistryEntry::getProperty", "copyin", "copyout",
    "current_task", "current_thread", "proc_find"
]

results = {
    "functions": [],
    "data_symbols": [],
    "important_symbols": [],
    "total_count": 0
}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()

# Find functions
if symbol_type in ["functions", "all"]:
    for func in fm.getFunctions(True):
        func_name = func.getName()
        include = False

        if pattern_filter:
            if pattern_filter in func_name.lower():
                include = True
        else:
            include = True

        if include:
            is_important = any(imp.lower() in func_name.lower() for imp in IMPORTANT_SYMBOLS)

            entry = {
                "name": func_name,
                "address": str(func.getEntryPoint()),
                "size": func.getBody().getNumAddresses(),
                "important": is_important
            }

            if is_important:
                results["important_symbols"].append(entry)
            else:
                results["functions"].append(entry)

            results["total_count"] += 1

            if results["total_count"] >= 500:
                break

# Find data symbols
if symbol_type in ["data", "all"] and results["total_count"] < 500:
    for sym in sym_table.getAllSymbols(True):
        if sym.getSymbolType().toString() == "Label":
            sym_name = sym.getName()
            include = False

            if pattern_filter:
                if pattern_filter in sym_name.lower():
                    include = True
            else:
                # Only include if it matches important patterns
                include = any(imp.lower() in sym_name.lower() for imp in IMPORTANT_SYMBOLS)

            if include:
                is_important = any(imp.lower() in sym_name.lower() for imp in IMPORTANT_SYMBOLS)

                entry = {
                    "name": sym_name,
                    "address": str(sym.getAddress()),
                    "important": is_important
                }

                if is_important:
                    results["important_symbols"].append(entry)
                else:
                    results["data_symbols"].append(entry)

                results["total_count"] += 1

                if results["total_count"] >= 500:
                    break

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
