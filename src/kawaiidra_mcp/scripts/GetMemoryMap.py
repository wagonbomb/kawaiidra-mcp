# @category MCP
# @runtime Jython
import json

mem = currentProgram.getMemory()
blocks = []

for block in mem.getBlocks():
    blocks.append({
        "name": block.getName(),
        "start": str(block.getStart()),
        "end": str(block.getEnd()),
        "size": block.getSize(),
        "permissions": (
            ("r" if block.isRead() else "-") +
            ("w" if block.isWrite() else "-") +
            ("x" if block.isExecute() else "-")
        ),
        "type": str(block.getType()),
        "initialized": block.isInitialized()
    })

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "blocks": blocks}))
print("=== MCP_RESULT_END ===")
