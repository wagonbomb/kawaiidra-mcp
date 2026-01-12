# @category MCP
# @runtime Jython
import json

def find_function(name):
    if not name:
        return None
    funcs = getGlobalFunctions(name)
    if funcs:
        return funcs[0]
    try:
        addr = toAddr(name)
        func = getFunctionAt(addr) or getFunctionContaining(addr)
        return func
    except:
        return None

def get_callees(func, visited, current_depth, max_depth):
    if current_depth >= max_depth or func is None:
        return None

    func_addr = str(func.getEntryPoint())
    if func_addr in visited:
        return {"name": func.getName(), "address": func_addr, "circular": True}

    visited.add(func_addr)
    callees = []

    ref_mgr = currentProgram.getReferenceManager()
    for addr in func.getBody().getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(addr):
            if ref.getReferenceType().isCall():
                target_func = getFunctionAt(ref.getToAddress())
                if target_func and not target_func.isThunk():
                    child = get_callees(target_func, visited.copy(), current_depth + 1, max_depth)
                    if child:
                        callees.append(child)

    return {
        "name": func.getName(),
        "address": func_addr,
        "callees": callees[:20]  # Limit children
    }

def get_callers(func, visited, current_depth, max_depth):
    if current_depth >= max_depth or func is None:
        return None

    func_addr = str(func.getEntryPoint())
    if func_addr in visited:
        return {"name": func.getName(), "address": func_addr, "circular": True}

    visited.add(func_addr)
    callers = []

    ref_mgr = currentProgram.getReferenceManager()
    for ref in ref_mgr.getReferencesTo(func.getEntryPoint()):
        if ref.getReferenceType().isCall():
            caller_func = getFunctionContaining(ref.getFromAddress())
            if caller_func:
                parent = get_callers(caller_func, visited.copy(), current_depth + 1, max_depth)
                if parent:
                    callers.append(parent)

    return {
        "name": func.getName(),
        "address": func_addr,
        "callers": callers[:20]
    }

root_func_name = "entry" if "entry" else None
max_depth = 3
direction = "both"

result = {"success": True}

if root_func_name:
    root_func = find_function(root_func_name)
    if not root_func:
        result = {"success": False, "error": "Function not found: entry"}
    else:
        if direction in ["callees", "both"]:
            result["callees"] = get_callees(root_func, set(), 0, max_depth)
        if direction in ["callers", "both"]:
            result["callers"] = get_callers(root_func, set(), 0, max_depth)
        result["root"] = {"name": root_func.getName(), "address": str(root_func.getEntryPoint())}
else:
    # Get top-level call graph overview
    fm = currentProgram.getFunctionManager()
    functions = []
    for func in fm.getFunctions(True):
        if len(functions) >= 50:
            break
        ref_mgr = currentProgram.getReferenceManager()
        caller_count = len(list(ref_mgr.getReferencesTo(func.getEntryPoint())))
        functions.append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "caller_count": caller_count
        })
    result["overview"] = functions

print("=== MCP_RESULT_JSON ===")
print(json.dumps(result))
print("=== MCP_RESULT_END ===")
