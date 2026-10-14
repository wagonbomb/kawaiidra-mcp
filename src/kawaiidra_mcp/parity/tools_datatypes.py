"""Phase 10 — Advanced data type tools."""

from __future__ import annotations

from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
FIELDS = {"type": "array", "description": 'Fields: [{"name":"dwId","type":"uint","offset":0,"comment":""}] (offset optional)',
          "items": {"type": "object"}}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


# Shared Jython for building structures from a fields list.
_STRUCT_BUILD = '''
from ghidra.program.model.data import StructureDataType, UnionDataType
def _cat(path):
    return CategoryPath(path) if path else CategoryPath.ROOT
def build_struct(name, fields, size, category):
    st = StructureDataType(_cat(category), name, int(size or 0), dtm())
    for fd in fields:
        dt = find_dt(fd["type"])
        if fd.get("offset") is not None:
            off = int(fd["offset"])
            if off + dt.getLength() > st.getLength():
                st.growStructure(off + dt.getLength() - st.getLength())
            st.replaceAtOffset(off, dt, dt.getLength(), fd.get("name"), fd.get("comment"))
        else:
            st.add(dt, dt.getLength(), fd.get("name"), fd.get("comment"))
    if size and st.getLength() < int(size):
        st.growStructure(int(size) - st.getLength())
    return st
def layout(st):
    out = []
    for c in st.getDefinedComponents():
        out.append({"offset": c.getOffset(), "name": _s(c.getFieldName()),
                    "type": _s(c.getDataType().getName()), "size": c.getLength()})
    return out
'''

register(
    JTool(
        name="create_union",
        description="Create a union data type from a fields list.",
        properties={"name": _p("Union name"), "fields": FIELDS, "category": _p("Category path (default /)")},
        required=["name", "fields"],
        mode="write",
        helpers=_STRUCT_BUILD,
        body='''
        un = UnionDataType(_cat(arg("category")), arg("name"), dtm())
        for fd in arg_json("fields", []):
            dt = find_dt(fd["type"])
            un.add(dt, dt.getLength(), fd.get("name"), fd.get("comment"))
        with tx("Create union"):
            res = dtm().addDataType(un, DataTypeConflictHandler.REPLACE_HANDLER)
        r = dt_info(res)
        r["members"] = [{"name": _s(c.getFieldName()), "type": _s(c.getDataType().getName()),
                         "size": c.getLength()} for c in res.getComponents()]
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="create_function_signature",
        description="Create a function-definition (function pointer target) data type, from parts or a C prototype string.",
        properties={"name": _p("Type name"), "return_type": _p("Return type (default void)"),
                    "parameters": {"type": "array", "items": {"type": "object"},
                                   "description": 'Parameters: [{"name":"a","type":"int"}]'},
                    "prototype": _p("Alternatively a full C prototype: 'int cb(void *ctx, int n)'"),
                    "calling_convention": _p("Calling convention name"),
                    "category": _p("Category path")},
        required=["name"],
        mode="write",
        body='''
        from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl
        from ghidra.app.util.parser import FunctionSignatureParser
        cat = CategoryPath(arg("category")) if arg("category") else CategoryPath.ROOT
        if arg("prototype"):
            sig = FunctionSignatureParser(dtm(), None).parse(None, arg("prototype"))
            fd = FunctionDefinitionDataType(cat, arg("name"), sig, dtm())
        else:
            fd = FunctionDefinitionDataType(cat, arg("name"), dtm())
            fd.setReturnType(find_dt(arg("return_type", "void")))
            params = []
            for i, pdef in enumerate(arg_json("parameters", [])):
                params.append(ParameterDefinitionImpl(pdef.get("name") or ("param_%d" % (i + 1)),
                                                      find_dt(pdef["type"]), pdef.get("comment")))
            fd.setArguments(params)
        fd.setName(arg("name"))
        if arg("calling_convention"):
            fd.setCallingConvention(arg("calling_convention"))
        with tx("Create function signature"):
            res = dtm().addDataType(fd, DataTypeConflictHandler.REPLACE_HANDLER)
        r = dt_info(res)
        r["prototype"] = _s(res.getPrototypeString())
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="create_derived_type",
        description="Create a type built on another: a typedef alias, an array (length elements) or a pointer. Replaces an existing same-named type.",
        properties={"kind": _p("Derived kind", enum=["typedef", "array", "pointer"]),
                    "base_type": _p("Base data type"), "name": _p("Name (typedef required; optional for array/pointer)"),
                    "length": _p("Array element count", I), "category": _p("Category path")},
        required=["kind", "base_type"],
        mode="write",
        body='''
        from ghidra.program.model.data import TypedefDataType, ArrayDataType, PointerDataType
        base = find_dt(arg("base_type"))
        kind = arg("kind")
        cat = CategoryPath(arg("category")) if arg("category") else CategoryPath.ROOT
        if kind == "typedef":
            if not arg("name"):
                raise Fail("name is required for typedef")
            nd = TypedefDataType(cat, arg("name"), base, dtm())
        elif kind == "array":
            n = int(arg("length", 0))
            if n <= 0:
                raise Fail("length must be > 0 for array")
            nd = ArrayDataType(base, n, base.getLength(), dtm())
        elif kind == "pointer":
            nd = PointerDataType(base, dtm())
        else:
            raise Fail("kind must be typedef, array or pointer")
        with tx("Create derived type"):
            res = dtm().addDataType(nd, DataTypeConflictHandler.REPLACE_HANDLER)
            if kind != "typedef" and arg("name"):
                from ghidra.program.model.data import TypedefDataType as TD
                res = dtm().addDataType(TD(cat, arg("name"), res, dtm()), DataTypeConflictHandler.REPLACE_HANDLER)
        r = dt_info(res)
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="clone_data_type",
        description="Copy a data type under a new name (same category unless category is given).",
        properties={"source_type": _p("Type to copy"), "new_name": _p("Name for the copy"),
                    "category": _p("Category for the copy")},
        required=["source_type", "new_name"],
        mode="write",
        body='''
        src = find_dt_exact(arg("source_type")) or find_dt(arg("source_type"))
        if find_dt_exact(arg("new_name")) is not None:
            raise Fail("Type already exists: " + arg("new_name"))
        cp = src.copy(dtm())
        cp.setName(arg("new_name"))
        if arg("category"):
            cp.setCategoryPath(CategoryPath(arg("category")))
        with tx("Clone data type"):
            res = dtm().addDataType(cp, DataTypeConflictHandler.DEFAULT_HANDLER)
        r = dt_info(res)
        r["cloned_from"] = _s(src.getPathName())
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="create_data_type_category",
        description="Create a data type category (folder), including missing parents.",
        properties={"category_path": _p("Category path, e.g. /net/packets")},
        required=["category_path"],
        mode="write",
        body='''
        cp = CategoryPath(arg("category_path"))
        with tx("Create category"):
            cat = dtm().createCategory(cp)
        return {"success": True, "category": _s(cat.getCategoryPathName())}
        ''',
    ),
    JTool(
        name="move_data_type_to_category",
        description="Move a data type into another category (created if needed).",
        properties={"type_name": _p("Type to move"), "category_path": _p("Destination category")},
        required=["type_name", "category_path"],
        mode="write",
        body='''
        dt = find_dt_exact(arg("type_name"))
        if dt is None:
            raise Fail("Type not found: " + arg("type_name"))
        old = _s(dt.getPathName())
        with tx("Move data type"):
            cat = dtm().createCategory(CategoryPath(arg("category_path")))
            cat.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER)
        return {"success": True, "old_path": old, "new_path": _s(dt.getPathName())}
        ''',
    ),
    JTool(
        name="rename_data_type",
        description="Rename a struct/union/enum/typedef in place, preserving every existing application of it.",
        properties={"old_name": _p("Current name or path"), "new_name": _p("New name")},
        required=["old_name", "new_name"],
        mode="write",
        body='''
        dt = find_dt_exact(arg("old_name"))
        if dt is None:
            raise Fail("Type not found: " + arg("old_name"))
        old = _s(dt.getPathName())
        with tx("Rename data type"):
            dt.setName(arg("new_name"))
        return {"success": True, "old_path": old, "new_path": _s(dt.getPathName())}
        ''',
    ),
    JTool(
        name="resize_struct",
        description="Grow or shrink a structure to new_size bytes. Fields that still fit are preserved; growth pads with undefined bytes. Refuses to clip defined fields unless force=true.",
        properties={"name": _p("Structure name"), "new_size": _p("New total size in bytes", I),
                    "force": _p("Allow clipping defined fields (default false)", B)},
        required=["name", "new_size"],
        mode="write",
        helpers=_STRUCT_BUILD,
        body='''
        st = find_dt_exact(arg("name"))
        if st is None or not isinstance(st, Structure):
            raise Fail("Structure not found: " + arg("name"))
        new = int(arg("new_size"))
        old = st.getLength()
        clipped = [c for c in st.getDefinedComponents() if c.getOffset() + c.getLength() > new]
        if clipped and not arg_bool("force"):
            raise Fail("Shrink would clip fields: " + ", ".join(_s(c.getFieldName()) or ("@%d" % c.getOffset()) for c in clipped))
        with tx("Resize struct"):
            if new > old:
                st.growStructure(new - old)
            elif new < old:
                for c in sorted(st.getComponents(), key=lambda c: -c.getOrdinal()):
                    if c.getOffset() >= new:
                        st.delete(c.getOrdinal())
                    elif c.getOffset() + c.getLength() > new:
                        st.clearComponent(c.getOrdinal())
                while st.getLength() > new and st.getNumComponents() > 0:
                    st.delete(st.getNumComponents() - 1)
                if st.getLength() < new:
                    st.growStructure(new - st.getLength())
        return {"success": True, "name": _s(st.getName()), "old_size": old, "new_size": st.getLength(),
                "clipped_fields": [_s(c.getFieldName()) for c in clipped], "fields": layout(st)}
        ''',
    ),
    JTool(
        name="recreate_struct",
        description="Replace a structure in one step: delete the same-named type (force=true required if it is in use), then create it from fields (same shape as create_struct, offsets allowed).",
        properties={"name": _p("Structure name"), "fields": FIELDS, "size": _p("Minimum total size", I),
                    "category": _p("Category path"), "force": _p("Replace even if referenced (default false)", B)},
        required=["name", "fields"],
        mode="write",
        helpers=_STRUCT_BUILD,
        body='''
        existing = find_dt_exact(arg("name"))
        category = arg("category")
        if existing is not None and not category:
            category = _s(existing.getCategoryPath().getPath())
        st = build_struct(arg("name"), arg_json("fields", []), arg("size"), category)
        with tx("Recreate struct"):
            if existing is not None:
                if isinstance(existing, Structure):
                    existing.replaceWith(st)
                    res = existing
                else:
                    if not arg_bool("force"):
                        raise Fail("Existing type is not a structure; pass force=true to replace")
                    res = dtm().replaceDataType(existing, st, True)
            else:
                res = dtm().addDataType(st, DataTypeConflictHandler.REPLACE_HANDLER)
        r = dt_info(res)
        r["fields"] = layout(res)
        r["replaced"] = existing is not None
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="resolve_duplicate_type",
        description="Find data types sharing a simple name; optionally delete unused size<=1 /Demangler stubs when a larger canonical type exists (fixes 'Can't resolve datatype' issues).",
        properties={"type_name": _p("Simple type name"),
                    "delete_demangler_stub": _p("Delete unused Demangler stubs (default false)", B)},
        required=["type_name"],
        mode="write",
        body='''
        from java.util import ArrayList
        found = ArrayList()
        dtm().findDataTypes(arg("type_name"), found)
        items = [dt for dt in found]
        info = [dict(dt_info(dt)) for dt in items]
        deleted = []
        if arg_bool("delete_demangler_stub") and len(items) > 1:
            biggest = max(dt.getLength() for dt in items)
            with tx("Resolve duplicate types"):
                for dt in items:
                    path = _s(dt.getCategoryPath().getPath())
                    if path.startswith("/Demangler") and dt.getLength() <= 1 and biggest > 1:
                        dtm().remove(dt, MONITOR)
                        deleted.append(_s(dt.getPathName()))
        return {"type_name": arg("type_name"), "count": len(info), "types": info, "deleted": deleted}
        ''',
    ),
    JTool(
        name="validate_data_type",
        description="Check that a data type string resolves and whether it can be applied at an address without clobbering instructions or other data.",
        properties={"type_name": _p("Data type (C syntax ok: 'char[16]', 'MyStruct *')"),
                    "address": _p("Optional address to test placement")},
        required=["type_name"],
        body='''
        dt = find_dt(arg("type_name"), required=False)
        if dt is None:
            return {"valid": False, "type_name": arg("type_name"), "reason": "type does not resolve"}
        res = {"valid": True, "type": dt_info(dt)}
        if arg("address"):
            a = addr(arg("address"))
            lst = prog().getListing()
            mem = prog().getMemory()
            n = max(dt.getLength(), 1)
            end = a.add(n - 1)
            conflicts = []
            if not mem.contains(a, end):
                conflicts.append("range not fully in memory")
            else:
                cu_iter = lst.getCodeUnits(prog().getAddressFactory().getAddressSet(a, end), True)
                for cu in cu_iter:
                    if hasattr(cu, "getMnemonicString") and lst.getInstructionAt(cu.getAddress()) is not None:
                        conflicts.append("instruction at " + _s(cu.getAddress()))
                    else:
                        d = lst.getDataAt(cu.getAddress())
                        if d is not None and d.isDefined():
                            conflicts.append("%s at %s" % (_s(d.getDataType().getName()), _s(cu.getAddress())))
            res["address"] = _s(a)
            res["end"] = _s(end)
            res["conflicts"] = conflicts[:50]
            res["can_apply_cleanly"] = len(conflicts) == 0
        return res
        ''',
    ),
    JTool(
        name="validate_function_prototype",
        description="Parse a C function prototype against the program's types without applying it; reports the parsed return type, parameters and calling convention or the parse error.",
        properties={"prototype": _p("C prototype, e.g. 'int foo(char *s, int n)'"),
                    "function": _p("Optional function (name/address) whose current signature is the base"),
                    "calling_convention": _p("Calling convention to check exists")},
        required=["prototype"],
        body='''
        from ghidra.app.util.parser import FunctionSignatureParser
        f = find_func(required=False)
        base = f.getSignature() if f is not None else None
        res = {"prototype": arg("prototype")}
        try:
            sig = FunctionSignatureParser(dtm(), None).parse(base, arg("prototype"))
        except (Exception, Throwable) as e:
            res.update({"valid": False, "error": _s(e)})
            return res
        res.update({"valid": True, "name": _s(sig.getName()),
                    "return_type": _s(sig.getReturnType().getName()),
                    "parameters": [{"name": _s(p.getName()), "type": _s(p.getDataType().getName()),
                                    "size": p.getLength()} for p in sig.getArguments()],
                    "varargs": sig.hasVarArgs()})
        cc = arg("calling_convention")
        if cc:
            names = [_s(m.getName()) for m in prog().getCompilerSpec().getCallingConventions()]
            res["calling_convention_valid"] = cc in names or cc in ("default", "unknown")
            if not res["calling_convention_valid"]:
                res["valid"] = False
                res["error"] = "Unknown calling convention %s (available: %s)" % (cc, ", ".join(names))
        return res
        ''',
    ),
    JTool(
        name="get_valid_data_types",
        description="List data type names usable in type arguments: built-ins plus the program's own types, optionally filtered by category.",
        properties={"category": _p("Category path filter"), "filter": _p("Name substring filter"),
                    "offset": _p("Offset", I), "limit": _p("Max results (default 200)", I)},
        body='''
        from ghidra.program.model.data import BuiltInDataTypeManager
        flt = (arg("filter") or "").lower()
        cat = arg("category")
        out = []
        for src, m in (("builtin", BuiltInDataTypeManager.getDataTypeManager()), ("program", dtm())):
            for dt in m.getAllDataTypes():
                cp = _s(dt.getCategoryPath().getPath())
                if cat and not cp.startswith(cat):
                    continue
                if flt and flt not in dt.getName().lower():
                    continue
                out.append({"name": _s(dt.getName()), "path": _s(dt.getPathName()),
                            "size": dt.getLength(), "source": src})
        out.sort(key=lambda d: (d["source"] != "builtin", d["name"]))
        return page(out, arg("offset"), arg("limit"), 200)
        ''',
    ),
    JTool(
        name="import_data_types",
        description="Import data types into the program from a Ghidra archive (.gdt) or a C header (.h, parsed with Ghidra's C parser).",
        properties={"source": _p("Path to a .gdt archive or .h header"),
                    "format": _p("gdt or c (auto from extension)", enum=["gdt", "c"]),
                    "filter": _p("Only import types whose name contains this")},
        required=["source"],
        mode="write",
        timeout=600,
        body='''
        import os
        from java.io import File
        src = arg("source")
        if not os.path.exists(src):
            raise Fail("Source not found: " + src)
        fmt = arg("format") or ("c" if src.lower().endswith((".h", ".hpp", ".c")) else "gdt")
        flt = (arg("filter") or "").lower()
        imported = []
        with tx("Import data types"):
            if fmt == "gdt":
                from ghidra.program.model.data import FileDataTypeManager
                fdm = FileDataTypeManager.openFileArchive(File(src), False)
                try:
                    for dt in fdm.getAllDataTypes():
                        if flt and flt not in dt.getName().lower():
                            continue
                        r = dtm().resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER)
                        imported.append(_s(r.getPathName()))
                finally:
                    fdm.close()
            else:
                from ghidra.app.util.cparser.C import CParser
                parser = CParser(dtm(), True, None)
                text = open(src).read()
                parser.parse(text)
                for dt in list(parser.getComposites().values()) + list(parser.getEnums().values()) + list(parser.getTypes().values()):
                    if flt and flt not in dt.getName().lower():
                        continue
                    imported.append(_s(dt.getPathName()))
        return {"success": True, "format": fmt, "count": len(imported), "types": imported[:500]}
        ''',
    ),
    JTool(
        name="suggest_field_names",
        description="Suggest names for the fields of a structure instance at an address, based on the data, pointers, strings and functions found at each offset.",
        properties={"struct_address": _p("Address of the struct instance"),
                    "struct_size": _p("Bytes to examine (default: applied type length or 64)", I)},
        required=["struct_address"],
        body='''
        p = prog()
        lst = p.getListing()
        mem = p.getMemory()
        a = addr(arg("struct_address"))
        d = lst.getDataAt(a)
        size = int(arg("struct_size") or (d.getLength() if d is not None and d.isDefined() else 64))
        ps = p.getDefaultPointerSize()
        fm = p.getFunctionManager()
        out = []
        off = 0
        while off < size:
            fa = a.add(off)
            comp = lst.getDataContaining(fa)
            sugg = None
            reason = None
            step = 1
            cd = lst.getDataAt(fa)
            if cd is not None and cd.isDefined():
                step = max(cd.getLength(), 1)
                if cd.isPointer():
                    tgt = cd.getValue()
                    f = fm.getFunctionAt(tgt) if tgt is not None else None
                    sd = lst.getDataAt(tgt) if tgt is not None else None
                    if f is not None:
                        sugg, reason = "pfn" + f.getName()[:1].upper() + f.getName()[1:], "points to function " + _s(f.getName())
                    elif sd is not None and sd.hasStringValue():
                        sugg, reason = "pszString_%x" % off, "points to string " + _s(sd.getValue())[:40]
                    else:
                        sugg, reason = "p_%x" % off, "pointer"
                elif cd.hasStringValue():
                    sugg, reason = "szBuf_%x" % off, "inline string"
                else:
                    sugg, reason = "%s_%x" % (_s(cd.getDataType().getName()).replace(" ", "_"), off), "defined data"
            else:
                try:
                    v = mem.getLong(fa) if ps == 8 else (mem.getInt(fa) & 0xffffffff)
                    tgt = p.getAddressFactory().getDefaultAddressSpace().getAddress(v)
                    if mem.contains(tgt) and off % ps == 0:
                        f = fm.getFunctionAt(tgt)
                        sugg = ("pfn" + f.getName()) if f else "p_%x" % off
                        reason = "value looks like pointer to " + _s(tgt)
                        step = ps
                except (Exception, Throwable):
                    pass
            refs = [_s(r.getFromAddress()) for r in p.getReferenceManager().getReferencesTo(fa)][:5]
            if sugg or refs:
                out.append({"offset": off, "suggested_name": sugg or ("field_%x" % off),
                            "reason": reason or "referenced", "referenced_from": refs})
            off += step
        return {"address": _s(a), "size": size, "suggestions": out}
        ''',
    ),
    JTool(
        name="analyze_struct_field_usage",
        description="Decompile functions that use a structure and report how often each field is accessed (and by which functions). Give struct_name, or an address whose applied type is a struct.",
        properties={"struct_name": _p("Structure name"), "address": _p("Address of an instance (alternative)"),
                    "max_functions": _p("Max functions to decompile (default 50)", I)},
        timeout=900,
        body='''
        from ghidra.app.decompiler import ClangFieldToken
        st = None
        if arg("struct_name"):
            st = find_dt_exact(arg("struct_name"))
        elif arg("address"):
            d = prog().getListing().getDataAt(addr(arg("address")))
            st = d.getDataType() if d is not None else None
        if st is None or not isinstance(st, Structure):
            raise Fail("Structure not found (struct_name or address with an applied struct)")
        target = st.getName()
        # Candidate functions: those whose signature/locals mention the struct, then xrefs to instances.
        cands = []
        for f in prog().getFunctionManager().getFunctions(True):
            txt = _s(f.getSignature().getPrototypeString())
            hit = target in txt
            if not hit:
                for v in f.getAllVariables():
                    if target in _s(v.getDataType().getName()):
                        hit = True
                        break
            if hit:
                cands.append(f)
        if arg("address"):
            for r in prog().getReferenceManager().getReferencesTo(addr(arg("address"))):
                f = prog().getFunctionManager().getFunctionContaining(r.getFromAddress())
                if f is not None and f not in cands:
                    cands.append(f)
        maxf = int(arg("max_functions", 50))
        fields = {}
        for c in st.getDefinedComponents():
            fields[c.getOffset()] = {"offset": c.getOffset(), "name": _s(c.getFieldName()),
                                     "type": _s(c.getDataType().getName()), "accesses": 0, "functions": []}
        scanned = []
        for f in cands[:maxf]:
            try:
                res = decompile(f, 30)
            except (Exception, Throwable):
                continue
            scanned.append(_s(f.getName()))
            stack = [res.getCCodeMarkup()]
            while stack:
                node = stack.pop()
                if isinstance(node, ClangFieldToken):
                    dt = node.getDataType()
                    if dt is not None and dt.getName() == target:
                        off = node.getOffset()
                        e = fields.get(off)
                        if e is None:
                            e = fields.setdefault(off, {"offset": off, "name": _s(node.getText()), "type": "?",
                                                        "accesses": 0, "functions": []})
                        e["accesses"] += 1
                        if _s(f.getName()) not in e["functions"]:
                            e["functions"].append(_s(f.getName()))
                for i in range(node.numChildren()) if hasattr(node, "numChildren") else []:
                    stack.append(node.Child(i))
        out = sorted(fields.values(), key=lambda e: e["offset"])
        return {"struct": _s(st.getPathName()), "functions_scanned": scanned,
                "unused_fields": [e["name"] for e in out if e["accesses"] == 0], "fields": out}
        ''',
    ),
    JTool(
        name="get_field_access_context",
        description="Show how a field of a struct instance is accessed: references to struct_address+field_offset with surrounding instructions and the containing function.",
        properties={"struct_address": _p("Struct instance address"), "field_offset": _p("Field offset in bytes", I),
                    "num_examples": _p("Max examples (default 5)", I)},
        required=["struct_address", "field_offset"],
        body='''
        p = prog()
        lst = p.getListing()
        fa = addr(arg("struct_address")).add(int(arg("field_offset")))
        out = []
        for r in p.getReferenceManager().getReferencesTo(fa):
            if len(out) >= int(arg("num_examples", 5)):
                break
            src = r.getFromAddress()
            ins = lst.getInstructionAt(src)
            ctx = []
            if ins is not None:
                cur = ins
                for _ in range(3):
                    prv = cur.getPrevious()
                    if prv is None: break
                    cur = prv
                for _ in range(7):
                    if cur is None: break
                    ctx.append({"address": _s(cur.getAddress()), "text": _s(cur),
                                "is_access": cur.getAddress().equals(src)})
                    cur = cur.getNext()
            f = p.getFunctionManager().getFunctionContaining(src)
            out.append({"from": _s(src), "ref_type": _s(r.getReferenceType()),
                        "function": _s(f.getName()) if f else None, "context": ctx})
        d = lst.getDataContaining(fa)
        return {"field_address": _s(fa), "containing_data": _s(d.getDataType().getName()) if d else None,
                "access_count": p.getReferenceManager().getReferenceCountTo(fa), "examples": out}
        ''',
    ),
    JTool(
        name="detect_array_bounds",
        description="Estimate the extent of an array starting at an address: element size from the applied/first data type and the end at the next referenced or labeled address.",
        properties={"address": _p("Array start address"), "max_scan_range": _p("Max bytes to scan (default 4096)", I)},
        required=["address"],
        body='''
        p = prog()
        lst = p.getListing()
        st = p.getSymbolTable()
        rm = p.getReferenceManager()
        a = addr(arg("address"))
        rng = int(arg("max_scan_range", 4096))
        d = lst.getDataAt(a)
        elem = None
        if d is not None and d.isDefined():
            dt = d.getDataType()
            if isinstance(dt, Array):
                elem = dt.getDataType()
            else:
                elem = dt
        esize = elem.getLength() if elem is not None else p.getDefaultPointerSize()
        end = a
        reason = "max_scan_range"
        blk = p.getMemory().getBlock(a)
        limit = a.add(min(rng, blk.getEnd().subtract(a) + 1)) if blk else a.add(rng)
        cur = a.add(esize)
        while cur.compareTo(limit) < 0:
            if rm.hasReferencesTo(cur) or st.getPrimarySymbol(cur) is not None:
                reason = "reference/label at " + _s(cur)
                break
            cur = cur.add(esize)
        count = int(cur.subtract(a) // esize)
        return {"address": _s(a), "element_type": _s(elem.getName()) if elem else "undefined%d" % esize,
                "element_size": esize, "estimated_count": count, "end": _s(cur.subtract(1)),
                "bound_reason": reason, "xrefs_to_start": rm.getReferenceCountTo(a)}
        ''',
    ),
    JTool(
        name="analyze_data_region",
        description="Profile a data region: defined data items, raw bytes, per-offset xrefs and the detected boundary (next label/xref target).",
        properties={"address": _p("Region start"), "max_scan_bytes": _p("Bytes to scan (default 256)", I),
                    "include_xref_map": _p("Include per-offset xref map (default true)", B),
                    "include_boundary_detection": _p("Detect the region end (default true)", B)},
        required=["address"],
        body='''
        p = prog()
        lst = p.getListing()
        rm = p.getReferenceManager()
        mem = p.getMemory()
        a = addr(arg("address"))
        n = int(arg("max_scan_bytes", 256))
        blk = mem.getBlock(a)
        if blk is None:
            raise Fail("Address not in memory: " + _s(a))
        n = min(n, int(blk.getEnd().subtract(a)) + 1)
        items, xmap = [], []
        boundary = None
        off = 0
        while off < n:
            cur = a.add(off)
            d = lst.getDataAt(cur)
            if off > 0 and boundary is None and arg_bool("include_boundary_detection", True):
                sym = p.getSymbolTable().getPrimarySymbol(cur)
                if sym is not None and not sym.isDynamic():
                    boundary = {"offset": off, "address": _s(cur), "reason": "label " + _s(sym.getName())}
                elif rm.hasReferencesTo(cur):
                    boundary = {"offset": off, "address": _s(cur), "reason": "referenced"}
            if arg_bool("include_xref_map", True) and rm.hasReferencesTo(cur):
                xmap.append({"offset": off, "count": rm.getReferenceCountTo(cur),
                             "from": [_s(r.getFromAddress()) for r in rm.getReferencesTo(cur)][:5]})
            if d is not None and d.isDefined():
                items.append({"offset": off, "address": _s(cur), "type": _s(d.getDataType().getName()),
                              "size": d.getLength(), "value": _s(d.getDefaultValueRepresentation())[:80]})
                off += max(d.getLength(), 1)
            else:
                off += 1
        from jarray import zeros
        raw = zeros(min(n, 64), "b")
        mem.getBytes(a, raw)
        sym = p.getSymbolTable().getPrimarySymbol(a)
        return {"address": _s(a), "block": _s(blk.getName()), "scanned": n,
                "label": _s(sym.getName()) if sym else None,
                "bytes_hex": " ".join("%02x" % (b & 0xff) for b in raw),
                "defined_items": items, "xref_map": xmap, "boundary": boundary}
        ''',
    ),
    JTool(
        name="apply_data_classification",
        description="Classify a data address in one call: apply a type (PRIMITIVE/STRING/ARRAY of an existing type, or STRUCTURE built from type_definition fields), then optionally rename and comment it.",
        properties={"address": _p("Data address"),
                    "classification": _p("Kind", enum=["PRIMITIVE", "STRING", "ARRAY", "STRUCTURE"]),
                    "type_name": _p("Type for PRIMITIVE/ARRAY element (default byte)"),
                    "count": _p("Element count for ARRAY", I),
                    "type_definition": {"type": "object", "description": 'For STRUCTURE: {"name": "...", "fields": [...]}'},
                    "name": _p("Label to set"), "comment": _p("Plate comment to set")},
        required=["address", "classification"],
        mode="write",
        helpers=_STRUCT_BUILD,
        body='''
        from ghidra.program.model.data import ArrayDataType, StringDataType, TerminatedStringDataType
        p = prog()
        a = addr(arg("address"))
        kind = arg("classification").upper()
        if kind == "STRING":
            dt = TerminatedStringDataType.dataType
        elif kind == "STRUCTURE":
            tdef = arg_json("type_definition", {})
            if not tdef.get("name"):
                raise Fail("type_definition.name is required for STRUCTURE")
            dt = find_dt_exact(tdef["name"])
            if dt is None or tdef.get("fields"):
                with tx("Create struct"):
                    dt = dtm().addDataType(build_struct(tdef["name"], tdef.get("fields", []), tdef.get("size"), tdef.get("category")),
                                           DataTypeConflictHandler.REPLACE_HANDLER)
        else:
            dt = find_dt(arg("type_name", "byte"))
            if kind == "ARRAY":
                dt = ArrayDataType(dt, int(arg("count", 1)), dt.getLength(), dtm())
        with tx("Apply data classification"):
            from ghidra.program.model.data import DataUtilities
            data = DataUtilities.createData(p, a, dt, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
            if arg("name"):
                p.getSymbolTable().createLabel(a, arg("name"), SourceType.USER_DEFINED).setPrimary()
            if arg("comment"):
                p.getListing().setComment(a, CodeUnit.PLATE_COMMENT, arg("comment"))
        return {"success": True, "address": _s(a), "type": _s(data.getDataType().getName()),
                "length": data.getLength(), "name": arg("name")}
        ''',
    ),
)
