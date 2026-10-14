"""Phase 11 — Globals, listings, symbols, comments and cross-references."""

from __future__ import annotations

from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


PAGING = {"offset": _p("Pagination offset", I), "limit": _p("Max results (default 100)", I)}

# Shared global-variable helpers
_GLOBALS = '''
def _exec_block(p, a):
    b = p.getMemory().getBlock(a)
    return b is not None and b.isExecute()

def iter_globals(p, include_all_sections=False):
    """Yield (symbol, data) for named/defined global data outside executable blocks."""
    lst = p.getListing()
    st = p.getSymbolTable()
    seen = set()
    for d in lst.getDefinedData(True):
        a = d.getAddress()
        if not include_all_sections and _exec_block(p, a):
            continue
        if p.getMemory().getBlock(a) is None or a.isExternalAddress():
            continue
        sym = st.getPrimarySymbol(a)
        seen.add(a)
        yield sym, d
    for sym in st.getAllSymbols(True):
        if sym.getSymbolType() != SymbolType.LABEL or sym.isExternal():
            continue
        a = sym.getAddress()
        if a in seen or not a.isMemoryAddress():
            continue
        if not include_all_sections and _exec_block(p, a):
            continue
        if lst.getInstructionAt(a) is not None:
            continue
        seen.add(a)
        yield sym, lst.getDataAt(a)

def global_record(p, sym, d):
    rm = p.getReferenceManager()
    a = d.getAddress() if d is not None else sym.getAddress()
    name = _s(sym.getName()) if sym is not None else None
    dt = d.getDataType() if d is not None else None
    defined = d is not None and d.isDefined()
    return {"address": _s(a), "name": name,
            "type": _s(dt.getName()) if (dt is not None and defined) else None,
            "length": d.getLength() if d is not None else 0,
            "xrefs": rm.getReferenceCountTo(a),
            "block": _s(p.getMemory().getBlock(a).getName()),
            "default_name": (name is None) or is_default_name(name)}

def audit(p, a):
    lst = p.getListing()
    st = p.getSymbolTable()
    sym = st.getPrimarySymbol(a)
    d = lst.getDataAt(a)
    rec = global_record(p, sym, d) if (sym is not None or d is not None) else {"address": _s(a)}
    plate = lst.getComment(CodeUnit.PLATE_COMMENT, a)
    rec["plate_comment"] = _s(plate)
    issues = []
    if sym is None or is_default_name(sym.getName()):
        issues.append("default or missing name")
    if d is None or not d.isDefined() or _s(d.getDataType().getName()).startswith("undefined"):
        issues.append("no real data type")
    if not plate:
        issues.append("no plate comment")
    if rec.get("xrefs", 0) == 0:
        issues.append("no references")
    rec["issues"] = issues
    rec["documented"] = len([i for i in issues if i != "no references"]) == 0
    return rec
'''

register(
    JTool(
        name="list_globals",
        description="List global variables (defined data and data labels outside executable code) with type, size and xref counts. Filters: name substring, type, minimum xrefs.",
        properties={**PAGING, "filter": _p("Name substring filter"), "type_filter": _p("Data type name substring"),
                    "min_xrefs": _p("Minimum incoming references", I),
                    "include_all_sections": _p("Include executable sections (default false)", B),
                    "undocumented_only": _p("Only globals with default names (default false)", B)},
        helpers=_GLOBALS,
        body='''
        p = prog()
        flt = (arg("filter") or arg("name_substring") or "").lower()
        tflt = (arg("type_filter") or "").lower()
        minx = int(arg("min_xrefs", 0))
        out = []
        for sym, d in iter_globals(p, arg_bool("include_all_sections")):
            r = global_record(p, sym, d)
            if flt and flt not in (r["name"] or "").lower():
                continue
            if tflt and tflt not in (r["type"] or "").lower():
                continue
            if r["xrefs"] < minx:
                continue
            if arg_bool("undocumented_only") and not r["default_name"]:
                continue
            out.append(r)
        return page(out, arg("offset"), arg("limit"))
        ''',
    ),
    JTool(
        name="list_shadowed_globals",
        description="List named global data symbols with no type of their own because a larger data unit starting earlier covers them (invisible to list_globals, which reports the covering unit).",
        properties={**PAGING, "include_all_sections": _p("Include executable sections", B)},
        helpers=_GLOBALS,
        body='''
        p = prog()
        lst = p.getListing()
        out = []
        for sym in p.getSymbolTable().getAllSymbols(True):
            if sym.getSymbolType() != SymbolType.LABEL or sym.isExternal() or sym.isDynamic():
                continue
            a = sym.getAddress()
            if not a.isMemoryAddress() or p.getMemory().getBlock(a) is None:
                continue
            if not arg_bool("include_all_sections") and _exec_block(p, a):
                continue
            cont = lst.getDataContaining(a)
            if cont is not None and not cont.getAddress().equals(a) and cont.isDefined():
                out.append({"address": _s(a), "name": _s(sym.getName()),
                            "covered_by": _s(cont.getAddress()), "covering_type": _s(cont.getDataType().getName()),
                            "offset_in_cover": int(a.subtract(cont.getAddress())),
                            "xrefs": p.getReferenceManager().getReferenceCountTo(a)})
        return page(out, arg("offset"), arg("limit"))
        ''',
    ),
    JTool(
        name="list_data_items_by_xrefs",
        description="List defined data items sorted by incoming reference count (most-referenced first) — a fast way to find important globals and tables.",
        properties={**PAGING, "filter": _p("Name substring"), "type_filter": _p("Type substring"),
                    "min_xrefs": _p("Minimum xrefs (default 1)", I),
                    "include_all_sections": _p("Include executable sections", B)},
        helpers=_GLOBALS,
        body='''
        p = prog()
        flt = (arg("filter") or "").lower()
        tflt = (arg("type_filter") or "").lower()
        minx = int(arg("min_xrefs", 1))
        out = []
        for sym, d in iter_globals(p, arg_bool("include_all_sections")):
            r = global_record(p, sym, d)
            if r["xrefs"] < minx:
                continue
            if flt and flt not in (r["name"] or "").lower():
                continue
            if tflt and tflt not in (r["type"] or "").lower():
                continue
            out.append(r)
        out.sort(key=lambda r: -r["xrefs"])
        return page(out, arg("offset"), arg("limit"))
        ''',
    ),
    JTool(
        name="list_program_items",
        description="List one kind of program inventory with pagination in a uniform envelope. kind: classes, methods, namespaces, imports, exports, segments, data_items, external_locations, functions_by_tag is separate.",
        properties={**PAGING, "kind": _p("Inventory kind", enum=["classes", "methods", "namespaces", "imports", "exports",
                                                                  "segments", "data_items", "external_locations"]),
                    "filter": _p("Name substring filter")},
        required=["kind"],
        body='''
        p = prog()
        st = p.getSymbolTable()
        kind = arg("kind")
        flt = (arg("filter") or "").lower()
        items = []
        if kind == "classes":
            for c in st.getClassNamespaces():
                items.append({"name": _s(c.getName(True)), "id": c.getID()})
        elif kind == "methods":
            for f in p.getFunctionManager().getFunctions(True):
                ns = f.getParentNamespace()
                if ns is not None and ns.getSymbol().getSymbolType() == SymbolType.CLASS:
                    items.append({"name": _s(f.getName(True)), "address": _s(f.getEntryPoint()),
                                  "class": _s(ns.getName(True))})
        elif kind == "namespaces":
            for sym in st.getAllSymbols(True):
                if sym.getSymbolType() in (SymbolType.NAMESPACE, SymbolType.CLASS, SymbolType.LIBRARY):
                    items.append({"name": _s(sym.getName(True)), "type": _s(sym.getSymbolType())})
        elif kind == "imports":
            for sym in st.getExternalSymbols():
                loc = p.getExternalManager().getExternalLocation(sym)
                items.append({"name": _s(sym.getName()), "library": _s(loc.getLibraryName()) if loc else None,
                              "address": _s(loc.getAddress()) if loc and loc.getAddress() else None})
        elif kind == "exports":
            it = st.getExternalEntryPointIterator()
            while it.hasNext():
                a = it.next()
                s = st.getPrimarySymbol(a)
                items.append({"name": _s(s.getName()) if s else None, "address": _s(a)})
        elif kind == "segments":
            for b in p.getMemory().getBlocks():
                items.append({"name": _s(b.getName()), "start": _s(b.getStart()), "end": _s(b.getEnd()),
                              "size": b.getSize(), "perms": ("r" if b.isRead() else "-") + ("w" if b.isWrite() else "-") + ("x" if b.isExecute() else "-"),
                              "initialized": b.isInitialized(), "overlay": b.isOverlay()})
        elif kind == "data_items":
            for d in p.getListing().getDefinedData(True):
                s = st.getPrimarySymbol(d.getAddress())
                items.append({"address": _s(d.getAddress()), "name": _s(s.getName()) if s else None,
                              "type": _s(d.getDataType().getName()), "length": d.getLength()})
        elif kind == "external_locations":
            em = p.getExternalManager()
            for lib in em.getExternalLibraryNames():
                it = em.getExternalLocations(lib)
                while it.hasNext():
                    loc = it.next()
                    items.append({"library": _s(lib), "label": _s(loc.getLabel()),
                                  "address": _s(loc.getAddress()), "is_function": loc.isFunction()})
        else:
            raise Fail("Unknown kind: " + _s(kind))
        if flt:
            items = [i for i in items if flt in json.dumps(i).lower()]
        r = page(items, arg("offset"), arg("limit"))
        r["kind"] = kind
        r["count"] = len(r["items"])
        return r
        ''',
    ),
    JTool(
        name="set_global",
        description="Atomically set a global's name, type, array length and plate comment in one transaction; rejects on validation failure with no partial write.",
        properties={"address": _p("Global address"), "name": _p("New name"), "type_name": _p("Data type"),
                    "array_length": _p("Make an array of this many elements", I),
                    "plate_comment": _p("Plate comment"),
                    "allow_evict": _p("Clear conflicting data/labels in the way (default true)", B)},
        required=["address"],
        mode="write",
        helpers=_GLOBALS,
        body='''
        from ghidra.program.model.data import ArrayDataType, DataUtilities
        p = prog()
        a = addr(arg("address"))
        dt = None
        if arg("type_name"):
            dt = find_dt(arg("type_name"))
            if arg("array_length"):
                n = int(arg("array_length"))
                dt = ArrayDataType(dt, n, dt.getLength(), dtm())
        tid = p.startTransaction("set_global")
        ok = False
        try:
            if dt is not None:
                mode = DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA if arg_bool("allow_evict", True) \\
                    else DataUtilities.ClearDataMode.CHECK_FOR_SPACE
                DataUtilities.createData(p, a, dt, -1, mode)
            if arg("name"):
                st = p.getSymbolTable()
                sym = st.getPrimarySymbol(a)
                if sym is not None and not sym.isDynamic() and sym.getSymbolType() == SymbolType.LABEL:
                    sym.setName(arg("name"), SourceType.USER_DEFINED)
                else:
                    st.createLabel(a, arg("name"), SourceType.USER_DEFINED).setPrimary()
            if arg("plate_comment") is not None:
                p.getListing().setComment(a, CodeUnit.PLATE_COMMENT, arg("plate_comment"))
            ok = True
        finally:
            p.endTransaction(tid, ok)
        r = audit(p, a)
        r["success"] = True
        return r
        ''',
    ),
    JTool(
        name="audit_global",
        description="Audit a global variable's documentation state: name, type, length, plate comment, xref count and a list of issues (run before set_global).",
        properties={"address": _p("Global address or name")},
        required=["address"],
        helpers=_GLOBALS,
        body='''
        return audit(prog(), addr(arg("address")))
        ''',
    ),
    JTool(
        name="audit_globals_in_function",
        description="Audit every global referenced from a function in one call, plus a summary of how many are fully documented.",
        properties={"function": _p("Function name or address")},
        required=["function"],
        helpers=_GLOBALS,
        body='''
        p = prog()
        f = find_func()
        seen = []
        out = []
        for ins in p.getListing().getInstructions(f.getBody(), True):
            for ref in ins.getReferencesFrom():
                t = ref.getToAddress()
                if not t.isMemoryAddress() or t in seen:
                    continue
                if not ref.getReferenceType().isData():
                    continue
                if p.getFunctionManager().getFunctionAt(t) is not None:
                    continue
                if p.getMemory().getBlock(t) is None or _exec_block(p, t):
                    continue
                seen.append(t)
                out.append(audit(p, t))
        doc = len([g for g in out if g["documented"]])
        return {"function": _s(f.getName()), "globals": out,
                "summary": {"total": len(out), "documented": doc, "undocumented": len(out) - doc}}
        ''',
    ),
    JTool(
        name="analyze_global_completeness",
        description="Score a global's documentation completeness 0-100: meaningful name, plate comment, real type, formatted bytes, and references (data analog of analyze_function_completeness).",
        properties={"address": _p("Global address or name"), "compact": _p("Omit details (default false)", B)},
        required=["address"],
        helpers=_GLOBALS,
        body='''
        p = prog()
        a = addr(arg("address"))
        r = audit(p, a)
        d = p.getListing().getDataAt(a)
        axes = {
            "meaningful_name": 30 if "default or missing name" not in r["issues"] else 0,
            "plate_comment": 25 if r.get("plate_comment") else 0,
            "real_type": 30 if "no real data type" not in r["issues"] else 0,
            "formatted": 10 if (d is not None and d.isDefined()) else 0,
            "referenced": 5 if r.get("xrefs", 0) > 0 else 0,
        }
        score = sum(axes.values())
        res = {"address": _s(a), "name": r.get("name"), "score": score, "axes": axes,
               "issues": r["issues"],
               "status": "DOCUMENTED" if score >= 85 else ("PARTIAL" if score >= 40 else "UNDOCUMENTED")}
        if not arg_bool("compact"):
            res["global"] = r
        return res
        ''',
    ),
    JTool(
        name="can_rename_at_address",
        description="Check whether the symbol at an address can be renamed and what kind of symbol it is (function, label, data, external, none).",
        properties={"address": _p("Address")},
        required=["address"],
        body='''
        p = prog()
        a = addr(arg("address"))
        sym = p.getSymbolTable().getPrimarySymbol(a)
        f = p.getFunctionManager().getFunctionAt(a)
        d = p.getListing().getDataAt(a)
        kind = "function" if f else ("data" if (d is not None and d.isDefined()) else ("label" if sym else "none"))
        res = {"address": _s(a), "kind": kind, "current_name": _s(sym.getName()) if sym else None,
               "is_default_name": (sym is None) or sym.isDynamic() or is_default_name(sym.getName()),
               "source": _s(sym.getSource()) if sym else None}
        res["can_rename"] = sym is None or not sym.isExternal()
        res["action"] = "rename_function" if f else ("rename existing symbol" if sym and not sym.isDynamic() else "create label")
        return res
        ''',
    ),
    JTool(
        name="rename_symbol",
        description="Rename a symbol of any kind. Target is an address (renames function/data/label there, creating a label if needed) or a name (a global symbol). kind forces data|global|label|external|function.",
        properties={"target": _p("Address or current symbol name"), "new_name": _p("New name"),
                    "kind": _p("auto (default), function, data, global, label, external",
                               enum=["auto", "function", "data", "global", "label", "external"]),
                    "old_name": _p("For kind=label at an address with several labels: which one")},
        required=["target", "new_name"],
        mode="write",
        body='''
        p = prog()
        st = p.getSymbolTable()
        tgt = arg("target")
        kind = arg("kind", "auto")
        new = arg("new_name")
        a = try_addr(tgt) if (kind != "external") else None
        with tx("rename_symbol"):
            if kind == "external":
                syms = [s for s in st.getExternalSymbols() if s.getName() == tgt]
                if not syms:
                    raise Fail("External symbol not found: " + tgt)
                syms[0].setName(new, SourceType.USER_DEFINED)
                return {"success": True, "kind": "external", "new_name": new}
            if a is not None and p.getMemory().contains(a):
                f = p.getFunctionManager().getFunctionAt(a)
                if f is not None and kind in ("auto", "function"):
                    old = f.getName(); f.setName(new, SourceType.USER_DEFINED)
                    return {"success": True, "kind": "function", "address": _s(a), "old_name": _s(old), "new_name": new}
                if arg("old_name"):
                    sym = st.getSymbol(arg("old_name"), a, None)
                    if sym is None:
                        raise Fail("No label %s at %s" % (arg("old_name"), _s(a)))
                else:
                    sym = st.getPrimarySymbol(a)
                if sym is None or sym.isDynamic():
                    st.createLabel(a, new, SourceType.USER_DEFINED).setPrimary()
                    return {"success": True, "kind": "label", "created": True, "address": _s(a), "new_name": new}
                old = sym.getName(); sym.setName(new, SourceType.USER_DEFINED)
                return {"success": True, "kind": _s(sym.getSymbolType()).lower(), "address": _s(a),
                        "old_name": _s(old), "new_name": new}
            syms = list(st.getGlobalSymbols(tgt)) or list(st.getSymbols(tgt))
            if not syms:
                raise Fail("Symbol not found: " + tgt)
            syms[0].setName(new, SourceType.USER_DEFINED)
            return {"success": True, "kind": _s(syms[0].getSymbolType()).lower(),
                    "address": _s(syms[0].getAddress()), "old_name": tgt, "new_name": new}
        ''',
    ),
    JTool(
        name="get_comment",
        description="Get listing comments (plate/pre/eol/post/repeatable) at one address or many (addresses=a,b,c), including data addresses.",
        properties={"address": _p("Address"), "addresses": _p("Comma-separated addresses (bulk)"),
                    "only_with_comments": _p("Skip addresses with no comments (default false)", B)},
        body='''
        targets = arg_list("addresses") or ([arg("address")] if arg("address") else [])
        if not targets:
            raise Fail("address or addresses is required")
        out = []
        for t in targets:
            a = addr(t)
            c = get_comments(a)
            if arg_bool("only_with_comments") and not any(c.values()):
                continue
            c["address"] = _s(a)
            out.append(c)
        return out[0] if (len(out) == 1 and arg("address") and not arg("addresses")) else {"comments": out, "count": len(out)}
        ''',
    ),
    JTool(
        name="set_repeatable_comment",
        description="Set a repeatable comment (shown at every reference to the address) — complements set_comment's EOL/PRE/POST/PLATE kinds.",
        properties={"address": _p("Address"), "comment": _p("Comment text ('' clears)")},
        required=["address", "comment"],
        mode="write",
        body='''
        a = addr(arg("address"))
        with tx("Set repeatable comment"):
            prog().getListing().setComment(a, CodeUnit.REPEATABLE_COMMENT, ARGS.get("comment") or None)
        return {"success": True, "address": _s(a)}
        ''',
    ),
    JTool(
        name="add_memory_reference",
        description="Create a user-defined cross-reference the analyzer missed (runtime pointer tables, vtables, late-bound function pointers, switch tables) without changing bytes.",
        properties={"from_address": _p("Source address (instruction or data)"), "to_address": _p("Target address"),
                    "ref_type": _p("Reference type (DATA, READ, WRITE, READ_WRITE, COMPUTED_CALL, COMPUTED_JUMP, UNCONDITIONAL_CALL, UNCONDITIONAL_JUMP, INDIRECTION). Default DATA"),
                    "operand_index": _p("Operand index (default 0; -1 for mnemonic)", I),
                    "primary": _p("Make primary reference (default true)", B)},
        required=["from_address", "to_address"],
        mode="write",
        body='''
        from ghidra.program.model.symbol import RefType as RT
        p = prog()
        fa, ta = addr(arg("from_address")), addr(arg("to_address"))
        rtn = (arg("ref_type") or "DATA").upper()
        rt = getattr(RT, rtn, None)
        if rt is None:
            raise Fail("Unknown ref_type: " + rtn)
        op = int(arg("operand_index", 0))
        with tx("Add memory reference"):
            ref = p.getReferenceManager().addMemoryReference(fa, ta, rt, SourceType.USER_DEFINED, op)
            if arg_bool("primary", True):
                p.getReferenceManager().setPrimary(ref, True)
        return {"success": True, "from": _s(fa), "to": _s(ta), "type": _s(ref.getReferenceType()), "operand_index": op}
        ''',
    ),
    JTool(
        name="remove_reference",
        description="Remove memory cross-reference(s) from one address to another (inverse of add_memory_reference). All operands by default, or only operand_index.",
        properties={"from_address": _p("Source address"), "to_address": _p("Target address"),
                    "operand_index": _p("Only this operand (default all)", I)},
        required=["from_address", "to_address"],
        mode="write",
        body='''
        p = prog()
        rm = p.getReferenceManager()
        fa, ta = addr(arg("from_address")), addr(arg("to_address"))
        op = ARGS.get("operand_index")
        removed = []
        with tx("Remove reference"):
            for ref in list(rm.getReferencesFrom(fa)):
                if not ref.getToAddress().equals(ta):
                    continue
                if op is not None and int(op) >= 0 and ref.getOperandIndex() != int(op):
                    continue
                rm.delete(ref)
                removed.append({"operand_index": ref.getOperandIndex(), "type": _s(ref.getReferenceType())})
        if not removed:
            raise Fail("No reference %s -> %s" % (_s(fa), _s(ta)))
        return {"success": True, "removed": removed}
        ''',
    ),
    JTool(
        name="get_assembly_context",
        description="For one or more source addresses (e.g. xref sources), return the surrounding instructions with the containing function.",
        properties={"xref_sources": _p("Comma-separated addresses"),
                    "context_instructions": _p("Instructions before/after (default 5)", I)},
        required=["xref_sources"],
        body='''
        p = prog()
        lst = p.getListing()
        n = int(arg("context_instructions", 5))
        out = []
        for t in arg_list("xref_sources"):
            a = addr(t)
            ins = lst.getInstructionContaining(a)
            if ins is None:
                out.append({"address": _s(a), "error": "no instruction"})
                continue
            cur = ins
            for _ in range(n):
                prv = cur.getPrevious()
                if prv is None: break
                cur = prv
            lines = []
            while cur is not None and len(lines) < 2 * n + 1:
                lines.append({"address": _s(cur.getAddress()), "text": _s(cur),
                              "bytes": " ".join("%02x" % (b & 0xff) for b in cur.getBytes()),
                              "is_target": cur.getAddress().equals(ins.getAddress())})
                if cur.getAddress().equals(ins.getAddress()) and len(lines) > n:
                    pass
                cur = cur.getNext()
            f = p.getFunctionManager().getFunctionContaining(a)
            out.append({"address": _s(a), "function": _s(f.getName()) if f else None, "instructions": lines})
        return {"contexts": out}
        ''',
    ),
    JTool(
        name="get_full_call_graph",
        description="Whole-program call graph as an edge list, DOT or Mermaid (limit caps the edge count).",
        properties={"format": _p("edges (default), dot or mermaid", enum=["edges", "dot", "mermaid"]),
                    "limit": _p("Max edges (default 1000)", I),
                    "include_external": _p("Include calls to external functions (default false)", B)},
        timeout=600,
        body='''
        p = prog()
        limit = int(arg("limit", 1000))
        edges = []
        truncated = False
        for f in p.getFunctionManager().getFunctions(True):
            for c in f.getCalledFunctions(MONITOR):
                if c.isExternal() and not arg_bool("include_external"):
                    continue
                if len(edges) >= limit:
                    truncated = True
                    break
                edges.append((_s(f.getName()), _s(c.getName())))
            if truncated:
                break
        fmt = arg("format", "edges")
        res = {"edge_count": len(edges), "truncated": truncated}
        if fmt == "dot":
            res["graph"] = "digraph calls {\\n" + "\\n".join('  "%s" -> "%s";' % e for e in edges) + "\\n}"
        elif fmt == "mermaid":
            ids = {}
            def nid(n):
                if n not in ids: ids[n] = "n%d" % len(ids)
                return ids[n]
            res["graph"] = "graph LR\\n" + "\\n".join('  %s["%s"] --> %s["%s"]' % (nid(a), a, nid(b), b) for a, b in edges)
        else:
            res["edges"] = [{"caller": a, "callee": b} for a, b in edges]
        return res
        ''',
    ),
    JTool(
        name="analyze_call_graph",
        description="Call-graph analysis: shortest call path between two functions (analysis_type=path), recursion cycles (cycles), or hub/leaf/root statistics (stats).",
        properties={"start_function": _p("Start function (path)"), "end_function": _p("End function (path)"),
                    "analysis_type": _p("path, cycles or stats (default stats)", enum=["path", "cycles", "stats"]),
                    "limit": _p("Max results (default 20)", I)},
        timeout=600,
        body='''
        p = prog()
        fm = p.getFunctionManager()
        graph = {}
        for f in fm.getFunctions(True):
            graph[_s(f.getName())] = [_s(c.getName()) for c in f.getCalledFunctions(MONITOR)]
        kind = arg("analysis_type", "stats")
        lim = int(arg("limit", 20))
        if kind == "path":
            s = _s(find_func(arg("start_function")).getName())
            e = _s(find_func(arg("end_function")).getName())
            prev = {s: None}
            q = [s]
            while q:
                n = q.pop(0)
                if n == e: break
                for m in graph.get(n, []):
                    if m not in prev:
                        prev[m] = n
                        q.append(m)
            if e not in prev:
                return {"path": None, "message": "no call path from %s to %s" % (s, e)}
            path = []
            n = e
            while n is not None:
                path.append(n); n = prev[n]
            path.reverse()
            return {"path": path, "length": len(path) - 1}
        if kind == "cycles":
            cycles = []
            for n, cs in graph.items():
                if n in cs:
                    cycles.append([n])
            # 2-cycles and longer via DFS (bounded)
            color = {}
            stack = []
            def dfs(n, depth):
                if len(cycles) >= lim or depth > 50: return
                color[n] = 1; stack.append(n)
                for m in graph.get(n, []):
                    if color.get(m) == 1 and m != n:
                        cyc = stack[stack.index(m):]
                        if len(cyc) > 1: cycles.append(list(cyc))
                    elif m not in color:
                        dfs(m, depth + 1)
                stack.pop(); color[n] = 2
            for n in graph:
                if n not in color: dfs(n, 0)
            return {"cycles": cycles[:lim], "count": len(cycles)}
        callers = {}
        for n, cs in graph.items():
            for m in cs:
                callers.setdefault(m, set()).add(n)
        hubs = sorted(graph, key=lambda n: -len(callers.get(n, ())))[:lim]
        fanout = sorted(graph, key=lambda n: -len(graph[n]))[:lim]
        return {"functions": len(graph), "edges": sum(len(v) for v in graph.values()),
                "roots": len([n for n in graph if not callers.get(n)]),
                "leaves": len([n for n in graph if not graph[n]]),
                "most_called": [{"name": n, "callers": len(callers.get(n, ()))} for n in hubs],
                "most_calls": [{"name": n, "callees": len(graph[n])} for n in fanout]}
        ''',
    ),
    JTool(
        name="search_instructions",
        description="Search parsed instructions by mnemonic and/or operand substring (e.g. 'mov' + '[rcx+0xd0]'), optionally inside one function. Case-insensitive.",
        properties={"mnemonic": _p("Mnemonic (exact, case-insensitive)"), "operand_pattern": _p("Substring of the operand text"),
                    "function": _p("Limit to this function"), "limit": _p("Max results (default 100)", I)},
        body='''
        p = prog()
        lst = p.getListing()
        mn = (arg("mnemonic") or "").lower()
        op = (arg("operand_pattern") or "").lower().replace(" ", "")
        if not mn and not op:
            raise Fail("mnemonic or operand_pattern is required")
        lim = int(arg("limit", 100))
        f = find_func(required=False) if arg("function") else None
        it = lst.getInstructions(f.getBody(), True) if f else lst.getInstructions(True)
        out = []
        for ins in it:
            if mn and ins.getMnemonicString().lower() != mn:
                continue
            text = _s(ins)
            if op:
                ops = text[len(ins.getMnemonicString()):].lower().replace(" ", "")
                if op not in ops:
                    continue
            fn = p.getFunctionManager().getFunctionContaining(ins.getAddress())
            out.append({"address": _s(ins.getAddress()), "instruction": text,
                        "function": _s(fn.getName()) if fn else None})
            if len(out) >= lim:
                break
        return {"count": len(out), "truncated": len(out) >= lim, "matches": out}
        ''',
    ),
    JTool(
        name="find_code_gaps",
        description="Find runs of undefined bytes between functions in executable memory (candidate missed functions or data).",
        properties={**PAGING, "min_size": _p("Minimum gap size in bytes (default 16)", I)},
        body='''
        p = prog()
        lst = p.getListing()
        minsz = int(arg("min_size", 16))
        gaps = []
        for b in p.getMemory().getBlocks():
            if not b.isExecute() or not b.isInitialized():
                continue
            it = lst.getUndefinedRanges(p.getAddressFactory().getAddressSet(b.getStart(), b.getEnd()), False, MONITOR)
            for rng in it:
                n = rng.getLength()
                if n < minsz:
                    continue
                prev = p.getFunctionManager().getFunctionContaining(rng.getMinAddress().subtract(1)) if rng.getMinAddress().compareTo(b.getStart()) > 0 else None
                gaps.append({"start": _s(rng.getMinAddress()), "end": _s(rng.getMaxAddress()), "size": n,
                             "block": _s(b.getName()), "after_function": _s(prev.getName()) if prev else None})
        return page(gaps, arg("offset"), arg("limit"))
        ''',
    ),
    JTool(
        name="find_next_undefined_function",
        description="Find the next address (from start_address, forward or backward) that looks like an undefined function: called/referenced code with no function, or an instruction run not inside any function.",
        properties={"start_address": _p("Where to start (default program start)"),
                    "direction": _p("forward (default) or backward", enum=["forward", "backward"]),
                    "criteria": _p("referenced (default) or any_code", enum=["referenced", "any_code"])},
        body='''
        p = prog()
        fm = p.getFunctionManager()
        rm = p.getReferenceManager()
        fwd = arg("direction", "forward") != "backward"
        start = addr(arg("start_address")) if arg("start_address") else (p.getMinAddress() if fwd else p.getMaxAddress())
        crit = arg("criteria", "referenced")
        for ins in p.getListing().getInstructions(start, fwd):
            a = ins.getAddress()
            if a.equals(start):
                continue
            if fm.getFunctionContaining(a) is not None:
                continue
            refs = [r for r in rm.getReferencesTo(a)]
            called = [r for r in refs if r.getReferenceType().isCall()]
            if crit == "referenced" and not refs:
                continue
            return {"found": True, "address": _s(a), "instruction": _s(ins),
                    "call_refs": len(called), "total_refs": len(refs),
                    "from": [_s(r.getFromAddress()) for r in refs][:10]}
        return {"found": False, "message": "no undefined function found"}
        ''',
    ),
    JTool(
        name="list_class_members",
        description="List member functions of a C++ class: functions in the class namespace or whose 'this' parameter is '<class> *'.",
        properties={**PAGING, "class_name": _p("Class name")},
        required=["class_name"],
        body='''
        p = prog()
        cname = arg("class_name")
        out = []
        for f in p.getFunctionManager().getFunctions(True):
            ns = f.getParentNamespace()
            how = None
            if ns is not None and (ns.getName() == cname or ns.getName(True) == cname):
                how = "namespace"
            else:
                params = f.getParameters()
                if params and _s(params[0].getName()) == "this":
                    t = _s(params[0].getDataType().getName()).replace(" ", "")
                    if t == cname + "*":
                        how = "this_type"
            if how:
                out.append({"name": _s(f.getName(True)), "address": _s(f.getEntryPoint()),
                            "signature": _s(f.getSignature().getPrototypeString()), "matched_by": how})
        r = page(out, arg("offset"), arg("limit"))
        r["class"] = cname
        return r
        ''',
    ),
)
