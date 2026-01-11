# @category MCP
# @runtime Jython
import json
from ghidra.program.model.data import Structure, Union, Enum

structure_filter = "None" if "None" else None
include_usage = false

dtm = currentProgram.getDataTypeManager()
structures = []

# Get all data types
for dt in dtm.getAllDataTypes():
    if isinstance(dt, (Structure, Union)):
        if structure_filter and structure_filter.lower() not in dt.getName().lower():
            continue

        components = []
        for i in range(dt.getNumComponents()):
            comp = dt.getComponent(i)
            if comp:
                components.append({
                    "offset": comp.getOffset(),
                    "name": comp.getFieldName() or f"field_{comp.getOffset():x}",
                    "type": str(comp.getDataType().getName()),
                    "size": comp.getLength()
                })

        struct_info = {
            "name": dt.getName(),
            "category": str(dt.getCategoryPath()),
            "size": dt.getLength(),
            "type": "struct" if isinstance(dt, Structure) else "union",
            "components": components
        }

        structures.append(struct_info)

        if len(structures) >= 100:
            break

# Get enums as well
enums = []
for dt in dtm.getAllDataTypes():
    if isinstance(dt, Enum):
        if structure_filter and structure_filter.lower() not in dt.getName().lower():
            continue
        values = []
        for name in dt.getNames():
            values.append({"name": name, "value": dt.getValue(name)})
        enums.append({
            "name": dt.getName(),
            "size": dt.getLength(),
            "values": values[:50]
        })
        if len(enums) >= 50:
            break

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "structures": structures, "enums": enums}))
print("=== MCP_RESULT_END ===")
