# @category MCP
# @runtime Jython
import json

prog = currentProgram
lang = prog.getLanguage()
compiler = prog.getCompilerSpec()
mem = prog.getMemory()
fm = prog.getFunctionManager()

info = {
    "name": prog.getName(),
    "path": prog.getExecutablePath(),
    "format": prog.getExecutableFormat(),
    "processor": str(lang.getProcessor()),
    "language": str(lang.getLanguageID()),
    "endian": str(lang.isBigEndian() and "big" or "little"),
    "pointer_size": lang.getDefaultSpace().getPointerSize(),
    "compiler": str(compiler.getCompilerSpecID()),
    "image_base": str(prog.getImageBase()),
    "min_address": str(mem.getMinAddress()),
    "max_address": str(mem.getMaxAddress()),
    "memory_size": mem.getSize(),
    "function_count": fm.getFunctionCount(),
    "creation_date": str(prog.getCreationDate())
}

print("=== MCP_RESULT_JSON ===")
print(json.dumps({"success": True, "info": info}))
print("=== MCP_RESULT_END ===")
