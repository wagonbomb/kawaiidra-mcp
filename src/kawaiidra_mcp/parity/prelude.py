"""Jython 2.7 helper code prepended to every parity tool script.

Keep this Python 2.7 compatible: no f-strings, no type hints.
"""

_COMMON = r'''
import json
import base64
import sys
import traceback
from java.lang import Throwable

def _s(val):
    """Unicode-safe string conversion."""
    if val is None:
        return None
    try:
        return unicode(val)
    except (Exception, Throwable):
        try:
            return str(val)
        except (Exception, Throwable):
            return repr(val)

def _hex(v):
    try:
        return "0x%x" % v
    except (Exception, Throwable):
        return _s(v)

def page(items, offset=None, limit=None, default_limit=100):
    offset = int(offset or 0)
    limit = int(limit if limit is not None else default_limit)
    total = len(items)
    return {"items": items[offset:offset + limit], "total": total,
            "offset": offset, "limit": limit,
            "has_more": offset + limit < total}

def arg(name, default=None):
    v = ARGS.get(name)
    if v is None or v == "":
        return default
    return v

def arg_bool(name, default=False):
    v = ARGS.get(name)
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return _s(v).lower() in ("1", "true", "yes", "on")

def arg_list(name):
    """Accept a JSON list or a comma-separated string."""
    v = ARGS.get(name)
    if v is None or v == "":
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    v = _s(v).strip()
    if v.startswith("["):
        return json.loads(v)
    return [x.strip() for x in v.split(",") if x.strip()]

def arg_json(name, default=None):
    v = ARGS.get(name)
    if v is None or v == "":
        return default
    if isinstance(v, basestring):
        return json.loads(v)
    return v

class Fail(Exception):
    pass

def _mcp_emit(fn):
    try:
        res = fn()
        if res is None:
            res = {"success": True}
    except Fail as e:
        res = {"error": _s(e.args[0]) if e.args else "failed"}
    except Exception as e:
        res = {"error": _s(e), "traceback": traceback.format_exc()[-2000:]}
    except Throwable as e:
        res = {"error": _s(e.toString())}
    print("=== MCP_RESULT_JSON ===")
    print(json.dumps(res, default=_s))
    print("=== MCP_RESULT_END ===")
'''

PROGRAM_HELPERS = r'''
from ghidra.program.model.symbol import SourceType, SymbolType, RefType
from ghidra.program.model.listing import CodeUnit, Function
from ghidra.program.model.data import (DataTypeConflictHandler, CategoryPath,
                                       Structure, Union, Enum, TypeDef, Pointer, Array,
                                       FunctionDefinition)
from ghidra.util.task import TaskMonitor
from ghidra.app.decompiler import DecompInterface, DecompileOptions

MONITOR = TaskMonitor.DUMMY

def prog():
    return currentProgram

def addr(s, program=None):
    p = program or currentProgram
    if s is None:
        raise Fail("address is required")
    if not isinstance(s, basestring):
        s = "0x%x" % s
    s = _s(s).strip()
    a = None
    try:
        a = p.getAddressFactory().getAddress(s)
        if a is None and not s.lower().startswith("0x"):
            a = p.getAddressFactory().getAddress("0x" + s)
    except (Exception, Throwable):
        a = None
    if a is None:
        # Accept a symbol / function name wherever an address is expected
        for sym in p.getSymbolTable().getSymbols(s):
            if not sym.isExternal():
                return sym.getAddress()
        raise Fail("Invalid address or unknown symbol: " + s)
    return a

def try_addr(s, program=None):
    try:
        return addr(s, program)
    except (Exception, Throwable):
        return None

def find_func(spec=None, program=None, required=True):
    """Find a function by name, entry address or contained address.

    With spec None, reads the common function/address/name/function_name/
    function_address arguments.
    """
    p = program or currentProgram
    fm = p.getFunctionManager()
    if spec is None:
        for k in ("function", "function_name", "name", "function_address", "address"):
            if ARGS.get(k):
                spec = ARGS.get(k)
                break
    if spec is None:
        if required:
            raise Fail("function (name or address) is required")
        return None
    spec = _s(spec).strip()
    a = try_addr(spec, p) if (spec.lower().startswith("0x") or all(c in "0123456789abcdefABCDEF:" for c in spec)) else None
    if a is not None:
        f = fm.getFunctionAt(a) or fm.getFunctionContaining(a)
        if f is not None:
            return f
    for f in fm.getFunctions(True):
        if f.getName() == spec or f.getName(True) == spec:
            return f
    st = p.getSymbolTable()
    for sym in st.getSymbols(spec):
        f = fm.getFunctionAt(sym.getAddress())
        if f is not None:
            return f
    for f in fm.getExternalFunctions():
        if f.getName() == spec:
            return f
    if required:
        raise Fail("Function not found: " + spec)
    return None

def func_info(f):
    return {"name": _s(f.getName()), "address": _s(f.getEntryPoint()),
            "signature": _s(f.getSignature().getPrototypeString()),
            "size": f.getBody().getNumAddresses()}

class tx(object):
    """with tx("desc"): ... commits on success, rolls back on exception."""
    def __init__(self, desc, program=None):
        self.p = program or currentProgram
        self.desc = desc
    def __enter__(self):
        self.id = self.p.startTransaction(self.desc)
        return self
    def __exit__(self, et, ev, tb):
        self.p.endTransaction(self.id, et is None)
        return False

def dtm(program=None):
    return (program or currentProgram).getDataTypeManager()

def find_dt(name, program=None, required=True):
    """Resolve a data type: path, simple name, builtin or C syntax (int *, char[8])."""
    m = dtm(program)
    name = _s(name).strip()
    if name.startswith("/"):
        dt = m.getDataType(name)
        if dt is not None:
            return dt
    from java.util import ArrayList
    found = ArrayList()
    m.findDataTypes(name, found)
    if found.size() > 0:
        best = None
        for dt in found:
            if best is None or dt.getLength() > best.getLength():
                best = dt
        return best
    try:
        from ghidra.util.data import DataTypeParser
        from ghidra.util.data.DataTypeParser import AllowedDataTypes
        from ghidra.app.services import DataTypeManagerService
        parser = DataTypeParser(m, m, None, AllowedDataTypes.ALL)
        dt = parser.parse(name)
        if dt is not None:
            return dt
    except (Exception, Throwable) as e:
        last = e
    from ghidra.program.model.data import BuiltInDataTypeManager
    bm = BuiltInDataTypeManager.getDataTypeManager()
    found = ArrayList()
    bm.findDataTypes(name, found)
    if found.size() > 0:
        return found.get(0)
    if required:
        raise Fail("Data type not found: " + name)
    return None

def find_dt_exact(name, program=None):
    """Find a user data type by path or exact name (no parsing)."""
    m = dtm(program)
    name = _s(name)
    if name.startswith("/"):
        return m.getDataType(name)
    for dt in m.getAllDataTypes():
        if dt.getName() == name or dt.getPathName() == name:
            return dt
    return None

def dt_info(dt):
    kind = "other"
    if isinstance(dt, Structure): kind = "struct"
    elif isinstance(dt, Union): kind = "union"
    elif isinstance(dt, Enum): kind = "enum"
    elif isinstance(dt, TypeDef): kind = "typedef"
    elif isinstance(dt, Pointer): kind = "pointer"
    elif isinstance(dt, Array): kind = "array"
    elif isinstance(dt, FunctionDefinition): kind = "function_definition"
    return {"name": _s(dt.getName()), "path": _s(dt.getPathName()),
            "category": _s(dt.getCategoryPath().getPath()),
            "kind": kind, "size": dt.getLength()}

_DECOMP = [None]
def decompiler(program=None):
    p = program or currentProgram
    if _DECOMP[0] is None or _DECOMP[0][0] is not p:
        d = DecompInterface()
        d.setOptions(DecompileOptions())
        d.openProgram(p)
        _DECOMP[0] = (p, d)
    return _DECOMP[0][1]

def decompile(f, timeout=60, program=None):
    res = decompiler(program).decompileFunction(f, timeout, MONITOR)
    if res is None or not res.decompileCompleted():
        raise Fail("Decompilation failed: " + (_s(res.getErrorMessage()) if res else "unknown"))
    return res

def is_default_name(name):
    name = _s(name)
    for pre in ("FUN_", "LAB_", "DAT_", "SUB_", "thunk_FUN_", "PTR_", "UNK_", "s_", "u_",
                "switchD", "caseD", "BYTE_", "WORD_", "DWORD_", "QWORD_", "Ordinal_"):
        if name.startswith(pre):
            return True
    return False

def comment_types():
    return {"plate": CodeUnit.PLATE_COMMENT, "pre": CodeUnit.PRE_COMMENT,
            "eol": CodeUnit.EOL_COMMENT, "post": CodeUnit.POST_COMMENT,
            "repeatable": CodeUnit.REPEATABLE_COMMENT}

def get_comments(a, program=None):
    lst = (program or currentProgram).getListing()
    out = {}
    for k, v in comment_types().items():
        out[k] = _s(lst.getComment(v, a))
    return out
'''

PROGRAM_PRELUDE = _COMMON + PROGRAM_HELPERS

PROJECT_PRELUDE = _COMMON + r'''
import os
from ghidra.framework import Application, HeadlessGhidraApplicationConfiguration
from ghidra import GhidraApplicationLayout
if not Application.isInitialized():
    Application.initializeApplication(GhidraApplicationLayout(),
                                      HeadlessGhidraApplicationConfiguration())
from ghidra.base.project import GhidraProject
from ghidra.framework.model import ProjectLocator
from ghidra.util.task import TaskMonitor
MONITOR = TaskMonitor.DUMMY

_OPEN = {}

def project_dir(name=None):
    name = name or ARGS.get("project_name")
    return os.path.join(ARGS["_projects_dir"], name)

def open_project(name=None, create=False):
    """Open (or create) a kawaiidra project: projects/<name>/<name>.gpr."""
    name = name or ARGS.get("project_name")
    if name in _OPEN:
        return _OPEN[name]
    pdir = project_dir(name)
    gpr = os.path.join(pdir, name + ".gpr")
    if not os.path.exists(gpr):
        if not create:
            raise Fail("Project not found: " + name)
        if not os.path.isdir(pdir):
            os.makedirs(pdir)
        gp = GhidraProject.createProject(pdir, name, False)
    else:
        gp = GhidraProject.openProject(pdir, name, True)
    _OPEN[name] = gp
    return gp

def close_all():
    for gp in _OPEN.values():
        try:
            gp.close()
        except (Exception, Throwable):
            pass
    _OPEN.clear()

def split_path(path):
    path = _s(path)
    if not path.startswith("/"):
        path = "/" + path
    folder, _, name = path.rpartition("/")
    return (folder or "/"), name

def find_domain_file(gp, name_or_path):
    root = gp.getProjectData().getRootFolder()
    pd = gp.getProjectData()
    if _s(name_or_path).startswith("/"):
        f = pd.getFile(name_or_path)
        if f is not None:
            return f
    stack = [root]
    while stack:
        fo = stack.pop()
        for df in fo.getFiles():
            if df.getName() == name_or_path or df.getPathname() == name_or_path:
                return df
        stack.extend(list(fo.getFolders()))
    raise Fail("File not found in project: " + _s(name_or_path))

def open_program(gp, name_or_path, read_only=True):
    df = find_domain_file(gp, name_or_path)
    folder = df.getParent().getPathname()
    prog = gp.openProgram(folder, df.getName(), read_only)
    return prog

def walk_files(gp):
    out = []
    stack = [gp.getProjectData().getRootFolder()]
    while stack:
        fo = stack.pop()
        for df in fo.getFiles():
            out.append(df)
        stack.extend(list(fo.getFolders()))
    return out

_orig_emit = _mcp_emit
def _mcp_emit(fn):
    try:
        _orig_emit(fn)
    finally:
        close_all()
'''

PROJECT_PRELUDE += r'''
def use_program(p):
    global currentProgram
    currentProgram = p
    return p
'''

# Program helpers are also useful in project mode once a program is opened.
PROJECT_PRELUDE += PROGRAM_HELPERS.replace(
    "def prog():\n    return currentProgram",
    "currentProgram = None\ndef prog():\n    return currentProgram")
