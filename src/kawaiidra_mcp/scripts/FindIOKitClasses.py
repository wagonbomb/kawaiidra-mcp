# @category MCP
# @runtime Jython
import json

class_filter = None
include_vtable = true

# Known IOKit base classes
IOKIT_BASE_CLASSES = [
    "IOService", "IOUserClient", "IORegistryEntry", "IOCommand",
    "IOEventSource", "IOMemoryDescriptor", "IOBufferMemoryDescriptor",
    "IODMACommand", "IOWorkLoop", "IOInterruptEventSource"
]

results = {
    "iokit_classes": [],
    "user_clients": [],
    "vtables": []
}

fm = currentProgram.getFunctionManager()
sym_table = currentProgram.getSymbolTable()
listing = currentProgram.getListing()

# Find IOKit class symbols (usually in __DATA.__const or similar)
for sym in sym_table.getAllSymbols(True):
    sym_name = sym.getName()

    # Look for metaclass or vtable symbols
    if "::MetaClass" in sym_name or "_METACLASS_" in sym_name or "ZTV" in sym_name:
        class_detected = None

        # Extract class name from symbol
        for base in IOKIT_BASE_CLASSES:
            if base in sym_name:
                class_detected = base
                break

        if class_detected or class_filter:
            if class_filter is None or class_filter.lower() in sym_name.lower():
                results["iokit_classes"].append({
                    "symbol": sym_name,
                    "address": str(sym.getAddress()),
                    "base_class": class_detected
                })

                # Check for UserClient (security-sensitive)
                if "UserClient" in sym_name:
                    results["user_clients"].append({
                        "name": sym_name,
                        "address": str(sym.getAddress())
                    })

# Find external/dispatch methods (common attack surface)
for func in fm.getFunctions(True):
    func_name = func.getName()
    if any(x in func_name for x in ["externalMethod", "getTargetAndMethodForIndex",
                                    "clientClose", "clientMemoryForType",
                                    "registerNotificationPort"]):
        if class_filter is None or class_filter.lower() in func_name.lower():
            results["iokit_classes"].append({
                "symbol": func_name,
                "address": str(func.getEntryPoint()),
                "type": "dispatch_method"
            })

# Look for vtables if requested
if include_vtable:
    for sym in sym_table.getAllSymbols(True):
        if "vtable" in sym.getName().lower() or sym.getName().startswith("_ZTV"):
            if class_filter is None or class_filter.lower() in sym.getName().lower():
                results["vtables"].append({
                    "symbol": sym.getName(),
                    "address": str(sym.getAddress())
                })

results["success"] = True

print("=== MCP_RESULT_JSON ===")
print(json.dumps(results))
print("=== MCP_RESULT_END ===")
