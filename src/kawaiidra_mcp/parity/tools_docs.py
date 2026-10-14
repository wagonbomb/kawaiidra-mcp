"""Phase 13 — Documentation workflow and cross-binary matching."""

from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from .framework import JTool, execute, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
N = {"type": "number"}
O = {"type": "object"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


FUNC = {"function": _p("Function name or address")}

# Helpers shared by program- and project-mode tools (Jython 2.7).
_DOC = '''
import hashlib
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.lang import Register

def norm_hash(f, p=None):
    """Address-independent opcode hash: mnemonics + operand kinds (registers kept, constants/addresses masked)."""
    p = p or prog()
    parts = []
    for ins in p.getListing().getInstructions(f.getBody(), True):
        toks = [ins.getMnemonicString()]
        for i in range(ins.getNumOperands()):
            objs = ins.getOpObjects(i)
            kinds = []
            for o in objs:
                if isinstance(o, Register):
                    kinds.append(_s(o.getName()))
                elif isinstance(o, Scalar):
                    v = o.getUnsignedValue()
                    kinds.append("IMM" if v > 0xff else "imm%d" % v)
                else:
                    kinds.append("ADDR")
            toks.append(",".join(kinds))
        parts.append(" ".join(toks))
    return hashlib.sha256("\\n".join(parts).encode("utf-8")).hexdigest(), len(parts)

def features(f, p=None):
    p = p or prog()
    hist = {}
    n = 0
    for ins in p.getListing().getInstructions(f.getBody(), True):
        m = ins.getMnemonicString()
        hist[m] = hist.get(m, 0) + 1
        n += 1
    calls = len(list(f.getCalledFunctions(MONITOR)))
    return {"hist": hist, "n": n, "calls": calls}

def similarity(a, b):
    import math
    keys = set(a["hist"]) | set(b["hist"])
    dot = sum(a["hist"].get(k, 0) * b["hist"].get(k, 0) for k in keys)
    na = math.sqrt(sum(v * v for v in a["hist"].values()))
    nb = math.sqrt(sum(v * v for v in b["hist"].values()))
    cos = dot / (na * nb) if na and nb else 0.0
    size = min(a["n"], b["n"]) / float(max(a["n"], b["n"])) if max(a["n"], b["n"]) else 1.0
    calls = 1.0 if a["calls"] == b["calls"] else min(a["calls"], b["calls"]) / float(max(a["calls"], b["calls"]) or 1)
    return round(0.6 * cos + 0.3 * size + 0.1 * calls, 4)

def is_documented(f):
    return not is_default_name(f.getName())

def completeness(f, p=None, with_decomp=False):
    p = p or prog()
    params = list(f.getParameters())
    locs = list(f.getLocalVariables())
    def default_var(n):
        n = _s(n)
        for pre in ("param_", "local_", "uVar", "iVar", "pvVar", "lVar", "bVar", "cVar", "sVar", "auVar", "in_", "unaff_", "extraout_", "Var"):
            if n.startswith(pre):
                return True
        return False
    undefined_types = [x for x in params + locs if _s(x.getDataType().getName()).startswith("undefined")]
    axes = {
        "name": 25 if not is_default_name(f.getName()) else 0,
        "plate_comment": 20 if f.getComment() else 0,
        "signature": 15 if f.getSignatureSource() != SourceType.DEFAULT else 0,
        "parameters_named": 15 if (not params or all(not default_var(x.getName()) for x in params)) else
            int(15 * len([x for x in params if not default_var(x.getName())]) / float(len(params))),
        "locals_named": 10 if (not locs or all(not default_var(x.getName()) for x in locs)) else
            int(10 * len([x for x in locs if not default_var(x.getName())]) / float(len(locs))),
        "types_defined": 10 if not undefined_types else int(10 * (1 - len(undefined_types) / float(len(params + locs)))),
        "tagged": 5 if len(list(f.getTags())) else 0,
    }
    score = sum(axes.values())
    issues = [k for k, v in axes.items() if v == 0]
    return {"function": _s(f.getName()), "address": _s(f.getEntryPoint()), "score": score, "axes": axes,
            "issues": issues,
            "status": "DOCUMENTED" if score >= 85 else ("PARTIAL" if score >= 40 else "UNDOCUMENTED")}

def classify(f, p=None):
    """Rough role classification used by analyze_for_documentation."""
    p = p or prog()
    callees = [_s(c.getName()).lower() for c in f.getCalledFunctions(MONITOR)]
    n = len(list(p.getListing().getInstructions(f.getBody(), True)))
    if f.isThunk(): return "thunk"
    if n <= 4: return "trivial/wrapper"
    if not callees: return "leaf"
    joined = " ".join(callees)
    for k, role in (("crypt", "crypto"), ("alloc", "memory-management"), ("free", "memory-management"),
                    ("send", "network"), ("recv", "network"), ("socket", "network"), ("printf", "formatting/logging"),
                    ("file", "file-io"), ("read", "io"), ("write", "io"), ("str", "string-handling"),
                    ("mem", "buffer-handling"), ("thread", "concurrency"), ("lock", "concurrency")):
        if k in joined: return role
    return "logic"

def function_doc(f, p=None):
    p = p or prog()
    lst = p.getListing()
    ctypes = comment_types()
    comments = []
    for cu in lst.getCodeUnits(f.getBody(), True):
        for k in ("eol", "pre", "post"):
            c = cu.getComment(ctypes[k])
            if c:
                comments.append({"offset": int(cu.getAddress().subtract(f.getEntryPoint())),
                                 "address": _s(cu.getAddress()), "type": k, "text": _s(c)})
    labels = []
    for s in p.getSymbolTable().getSymbols(f.getBody(), SymbolType.LABEL, True):
        if not s.isDynamic():
            labels.append({"offset": int(s.getAddress().subtract(f.getEntryPoint())), "name": _s(s.getName())})
    h, n = norm_hash(f, p)
    return {"name": _s(f.getName()), "address": _s(f.getEntryPoint()), "hash": h, "instruction_count": n,
            "prototype": _s(f.getSignature().getPrototypeString()),
            "calling_convention": _s(f.getCallingConventionName()),
            "plate_comment": _s(f.getComment()),
            "parameters": [{"name": _s(x.getName()), "type": _s(x.getDataType().getName())} for x in f.getParameters()],
            "locals": [{"name": _s(x.getName()), "type": _s(x.getDataType().getName())} for x in f.getLocalVariables()],
            "comments": comments, "labels": labels, "tags": sorted(_s(t.getName()) for t in f.getTags())}

def apply_doc(f, e, p=None):
    """Apply a documentation entry; each step independent; returns per-step results."""
    p = p or prog()
    res = {}
    def step(name, fn):
        try:
            fn(); res[name] = "ok"
        except (Exception, Throwable) as ex:
            res[name] = "error: " + _s(ex)
    nm = e.get("name") or e.get("function_name")
    if nm and nm != f.getName():
        step("rename", lambda: f.setName(nm, SourceType.USER_DEFINED))
    if e.get("prototype"):
        def _proto():
            from ghidra.app.util.parser import FunctionSignatureParser
            from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
            sig = FunctionSignatureParser(p.getDataTypeManager(), None).parse(f.getSignature(), e["prototype"])
            cmd = ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED)
            if not cmd.applyTo(p, MONITOR):
                raise Fail(_s(cmd.getStatusMsg()))
        step("prototype", _proto)
    if e.get("calling_convention"):
        step("calling_convention", lambda: f.setCallingConvention(e["calling_convention"]))
    if e.get("return_type"):
        step("return_type", lambda: f.setReturnType(find_dt(e["return_type"], p), SourceType.USER_DEFINED))
    if e.get("plate_comment") is not None:
        step("plate_comment", lambda: f.setComment(e["plate_comment"]))
    vt = e.get("variable_types") or {}
    vr = e.get("variable_renames") or {}
    if vt or vr:
        def _vars():
            from ghidra.program.model.pcode import HighFunctionDBUtil
            hf = decompile(f, 60, p).getHighFunction()
            syms = dict((_s(s.getName()), s) for s in hf.getLocalSymbolMap().getSymbols())
            if any(syms.get(k) is not None and syms[k].isParameter() for k in list(vt) + list(vr)):
                try:
                    HighFunctionDBUtil.commitParamsToDatabase(hf, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)
                except (Exception, Throwable):
                    HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.USER_DEFINED)
                hf = decompile(f, 60, p).getHighFunction()
                syms = dict((_s(s.getName()), s) for s in hf.getLocalSymbolMap().getSymbols())
            missing = []
            for k, t in vt.items():
                if k in syms: HighFunctionDBUtil.updateDBVariable(syms[k], None, find_dt(t, p), SourceType.USER_DEFINED)
                else: missing.append(k)
            if vr:
                hf2 = decompile(f, 60, p).getHighFunction()
                syms2 = dict((_s(s.getName()), s) for s in hf2.getLocalSymbolMap().getSymbols())
                for k, n2 in vr.items():
                    if k in syms2: HighFunctionDBUtil.updateDBVariable(syms2[k], n2, None, SourceType.USER_DEFINED)
                    else: missing.append(k)
            if missing:
                raise Fail("variables not found: " + ", ".join(missing))
        step("variables", _vars)
    if e.get("comments"):
        def _cm():
            ct = comment_types()
            for c in e["comments"]:
                a = addr(c["address"], p) if c.get("address") else f.getEntryPoint().add(int(c["offset"]))
                p.getListing().setComment(a, ct[(c.get("type") or "eol").lower()], c["text"])
        step("comments", _cm)
    if e.get("labels"):
        def _lb():
            for l in e["labels"]:
                a = addr(l["address"], p) if l.get("address") else f.getEntryPoint().add(int(l["offset"]))
                p.getSymbolTable().createLabel(a, l["name"], SourceType.USER_DEFINED)
        step("labels", _lb)
    if e.get("tags"):
        def _tg():
            tm = p.getFunctionManager().getFunctionTagManager()
            tags = e["tags"] if isinstance(e["tags"], list) else [t.strip() for t in e["tags"].split(",") if t.strip()]
            for t in tags:
                if tm.getFunctionTag(t) is None:
                    tm.createFunctionTag(t, (e.get("tag_comments") or {}).get(t, ""))
                f.addTag(t)
        step("tags", _tg)
    return res
'''

register(
    JTool(
        name="analyze_function_completeness",
        description="Score documentation completeness (0-100) of one function, or many (addresses=a,b,c): name, plate comment, signature, parameter/local naming, defined types, tags.",
        properties={**FUNC, "addresses": _p("Comma-separated functions (bulk)"),
                    "compact": _p("Only score/status (default false)", B)},
        helpers=_DOC,
        body='''
        targets = arg_list("addresses") or [None]
        out = []
        for t in targets:
            c = completeness(find_func(t))
            if arg_bool("compact"):
                c = {"function": c["function"], "address": c["address"], "score": c["score"], "status": c["status"]}
            out.append(c)
        return out[0] if len(out) == 1 and not arg("addresses") else {"results": out, "count": len(out)}
        ''',
    ),
    JTool(
        name="analyze_for_documentation",
        description="Composite documentation analysis for one function: decompilation, role classification, variables, callers/callees, strings referenced and completeness score with next steps.",
        properties=FUNC,
        required=["function"],
        helpers=_DOC,
        body='''
        p = prog()
        f = find_func()
        c = completeness(f)
        strings = []
        for ins in p.getListing().getInstructions(f.getBody(), True):
            for r in ins.getReferencesFrom():
                d = p.getListing().getDataAt(r.getToAddress())
                if d is not None and d.hasStringValue():
                    strings.append(_s(d.getValue())[:120])
        try:
            code = _s(decompile(f, 60).getDecompiledFunction().getC())
        except Fail as e:
            code = None
        steps = []
        if "name" in c["issues"]: steps.append("rename the function (rename_function / apply_documentation)")
        if "signature" in c["issues"]: steps.append("set a prototype (set_function_prototype)")
        if c["axes"]["parameters_named"] < 15 or c["axes"]["locals_named"] < 10: steps.append("rename variables (rename_variables / set_variables)")
        if "types_defined" in c["issues"] or c["axes"]["types_defined"] < 10: steps.append("type undefined variables (set_variable_type)")
        if "plate_comment" in c["issues"]: steps.append("add a plate comment")
        return {"function": func_info(f), "classification": classify(f), "completeness": c,
                "callers": [_s(x.getName()) for x in f.getCallingFunctions(MONITOR)][:30],
                "callees": [_s(x.getName()) for x in f.getCalledFunctions(MONITOR)][:30],
                "strings": strings[:30],
                "variables": [{"name": _s(x.getName()), "type": _s(x.getDataType().getName())} for x in f.getAllVariables()],
                "decompiled": code, "next_steps": steps}
        ''',
    ),
    JTool(
        name="analyze_function_complete",
        description="Comprehensive single-call function analysis: decompile, disassembly, callers, callees, xrefs, variables and completeness (each section toggleable).",
        properties={**FUNC, "include_xrefs": _p("default true", B), "include_callees": _p("default true", B),
                    "include_callers": _p("default true", B), "include_disasm": _p("default true", B),
                    "include_variables": _p("default true", B), "include_completeness": _p("default true", B)},
        required=["function"],
        helpers=_DOC,
        body='''
        p = prog()
        f = find_func()
        r = {"function": func_info(f)}
        try:
            r["decompiled"] = _s(decompile(f, 60).getDecompiledFunction().getC())
        except Fail as e:
            r["decompile_error"] = _s(e.args[0])
        if arg_bool("include_disasm", True):
            r["disassembly"] = ["%s  %s" % (_s(i.getAddress()), _s(i)) for i in p.getListing().getInstructions(f.getBody(), True)][:400]
        if arg_bool("include_callers", True):
            r["callers"] = [func_info(x) for x in f.getCallingFunctions(MONITOR)][:50]
        if arg_bool("include_callees", True):
            r["callees"] = [func_info(x) for x in f.getCalledFunctions(MONITOR)][:50]
        if arg_bool("include_xrefs", True):
            r["xrefs_to"] = [{"from": _s(x.getFromAddress()), "type": _s(x.getReferenceType())}
                             for x in p.getReferenceManager().getReferencesTo(f.getEntryPoint())][:100]
        if arg_bool("include_variables", True):
            r["variables"] = [{"name": _s(x.getName()), "type": _s(x.getDataType().getName()),
                               "storage": _s(x.getVariableStorage()), "is_parameter": x in list(f.getParameters())}
                              for x in f.getAllVariables()]
        if arg_bool("include_completeness", True):
            r["completeness"] = completeness(f)
        return r
        ''',
    ),
    JTool(
        name="get_function_documentation",
        description="Export a function's documentation as JSON (name, prototype, plate comment, variables, inline comments and labels by offset, tags, normalized hash) — input for apply_documentation on another binary.",
        properties=FUNC,
        required=["function"],
        helpers=_DOC,
        body='''
        return function_doc(find_func())
        ''',
    ),
    JTool(
        name="apply_documentation",
        description="Apply documentation to one function (fields at top level) or many (entries=[{address, ...}]). Every step is optional and independent and reported: rename, prototype, calling convention, return type, variable types/renames, plate comment, comments, labels, tags.",
        properties={"address": _p("Function address/name (single mode)"), "name": _p("New function name"),
                    "prototype": _p("C prototype"), "calling_convention": _p("Calling convention"),
                    "return_type": _p("Return type"), "plate_comment": _p("Plate comment"),
                    "variable_types": O, "variable_renames": O,
                    "comments": {"type": "array", "items": O, "description": '[{"address"|"offset", "type": "eol|pre|post|plate", "text"}]'},
                    "labels": {"type": "array", "items": O, "description": '[{"address"|"offset", "name"}]'},
                    "tags": _p("Comma-separated tags"),
                    "entries": {"type": "array", "items": O, "description": "Bulk mode: list of the above objects with address"}},
        mode="write",
        timeout=900,
        helpers=_DOC,
        body='''
        entries = arg_json("entries", []) or [dict((k, v) for k, v in ARGS.items() if not k.startswith("_") and k not in ("binary_name", "project_name"))]
        out = []
        with tx("apply_documentation"):
            for e in entries:
                try:
                    f = find_func(e.get("address") or e.get("target_address") or e.get("function"))
                except Fail as ex:
                    out.append({"address": e.get("address"), "error": _s(ex.args[0])}); continue
                steps = apply_doc(f, e)
                out.append({"address": _s(f.getEntryPoint()), "function": _s(f.getName()), "steps": steps,
                            "score": completeness(f)["score"]})
        errors = sum(1 for o in out if o.get("error") or any(_s(v).startswith("error") for v in o.get("steps", {}).values()))
        return {"success": errors == 0, "applied": len(out), "with_errors": errors, "results": out}
        ''',
    ),
    JTool(
        name="find_undocumented_by_string",
        description="Find undocumented (default-named) functions that reference a given string address — anchor naming via strings.",
        properties={"address": _p("String data address")},
        required=["address"],
        helpers=_DOC,
        body='''
        p = prog()
        a = addr(arg("address"))
        d = p.getListing().getDataAt(a)
        out = []
        for r in p.getReferenceManager().getReferencesTo(a):
            f = p.getFunctionManager().getFunctionContaining(r.getFromAddress())
            if f is not None and not is_documented(f) and _s(f.getName()) not in [o["name"] for o in out]:
                out.append({"name": _s(f.getName()), "address": _s(f.getEntryPoint()), "ref_from": _s(r.getFromAddress())})
        return {"string": _s(d.getValue()) if d is not None and d.hasStringValue() else None,
                "address": _s(a), "undocumented_functions": out}
        ''',
    ),
    JTool(
        name="batch_string_anchor_report",
        description="Report strings matching a pattern (default: source file names like *.c/*.cpp/*.h) and the undocumented FUN_* functions that reference them — fast naming anchors.",
        properties={"pattern": _p("Regex over string values (default source-file names)"),
                    "limit": _p("Max strings (default 200)", I)},
        helpers=_DOC,
        body='''
        import re
        p = prog()
        pat = re.compile(arg("pattern") or r"[\\w/\\\\.-]+\\.(c|cc|cpp|cxx|h|hpp|m|mm|rs|go)\\b", re.I)
        lim = int(arg("limit", 200))
        out = []
        for d in p.getListing().getDefinedData(True):
            if not d.hasStringValue():
                continue
            v = _s(d.getValue())
            if not v or not pat.search(v):
                continue
            funcs = []
            for r in p.getReferenceManager().getReferencesTo(d.getAddress()):
                f = p.getFunctionManager().getFunctionContaining(r.getFromAddress())
                if f is not None and _s(f.getName()) not in [x["name"] for x in funcs]:
                    funcs.append({"name": _s(f.getName()), "address": _s(f.getEntryPoint()), "documented": is_documented(f)})
            out.append({"string": v[:200], "address": _s(d.getAddress()), "functions": funcs})
            if len(out) >= lim:
                break
        undoc = len(set(x["name"] for o in out for x in o["functions"] if not x["documented"]))
        return {"count": len(out), "undocumented_functions": undoc, "anchors": out}
        ''',
    ),
    JTool(
        name="get_function_hashes",
        description="Normalized (address-independent) opcode hash for every function, paged, optionally only documented or undocumented ones. Same normalization as cross-binary matching; get_function_hash gives the raw-bytes SHA-256 of one function.",
        properties={"offset": _p("Offset", I), "limit": _p("Limit (default 100)", I),
                    "filter": _p("all (default), documented or undocumented", enum=["all", "documented", "undocumented"]),
                    "function": _p("Only this function")},
        timeout=900,
        helpers=_DOC,
        body='''
        p = prog()
        flt = arg("filter", "all")
        if arg("function"):
            f = find_func()
            h, n = norm_hash(f)
            return {"name": _s(f.getName()), "address": _s(f.getEntryPoint()), "hash": h, "instruction_count": n,
                    "documented": is_documented(f)}
        funcs = [f for f in p.getFunctionManager().getFunctions(True) if not f.isThunk()]
        if flt == "documented": funcs = [f for f in funcs if is_documented(f)]
        elif flt == "undocumented": funcs = [f for f in funcs if not is_documented(f)]
        pg = page(funcs, arg("offset"), arg("limit"))
        items = []
        for f in pg["items"]:
            h, n = norm_hash(f)
            items.append({"name": _s(f.getName()), "address": _s(f.getEntryPoint()), "hash": h,
                          "instruction_count": n, "documented": is_documented(f)})
        pg["items"] = items
        return pg
        ''',
    ),
    # ----- cross-binary (project mode: several programs open at once) ---------
    JTool(
        name="find_similar_functions_fuzzy",
        description="Cross-binary fuzzy matching: find functions in target_program most similar to one function in source_program (exact normalized-hash match = 1.0, else mnemonic-histogram/size/call similarity).",
        properties={**FUNC, "source_program": _p("Binary containing the function"),
                    "target_program": _p("Binary to search"), "threshold": _p("Min similarity (default 0.7)", N),
                    "limit": _p("Max matches (default 10)", I)},
        required=["function", "source_program", "target_program"],
        mode="project",
        timeout=900,
        helpers=_DOC,
        body='''
        gp = open_project()
        src = open_program(gp, arg("source_program"))
        tgt = open_program(gp, arg("target_program"))
        use_program(src)
        f = find_func(arg("function"), src)
        fh, _ = norm_hash(f, src)
        ff = features(f, src)
        thr = float(arg("threshold", 0.7))
        out = []
        for g in tgt.getFunctionManager().getFunctions(True):
            if g.isThunk(): continue
            gh, _ = norm_hash(g, tgt)
            sim = 1.0 if gh == fh else similarity(ff, features(g, tgt))
            if sim >= thr:
                out.append({"name": _s(g.getName()), "address": _s(g.getEntryPoint()), "similarity": sim,
                            "exact_hash_match": gh == fh, "documented": is_documented(g)})
        out.sort(key=lambda r: -r["similarity"])
        return {"source": {"program": arg("source_program"), "function": _s(f.getName()), "hash": fh},
                "target_program": arg("target_program"), "matches": out[:int(arg("limit", 10))]}
        ''',
    ),
    JTool(
        name="bulk_fuzzy_match",
        description="Match every function of source_program against target_program (exact normalized hash first, then fuzzy). filter=documented restricts sources to named functions — the input for documentation transfer.",
        properties={"source_program": _p("Source binary"), "target_program": _p("Target binary"),
                    "threshold": _p("Min fuzzy similarity (default 0.85)", N),
                    "filter": _p("all, documented (default) or undocumented", enum=["all", "documented", "undocumented"]),
                    "offset": _p("Offset", I), "limit": _p("Limit (default 100)", I),
                    "exact_only": _p("Skip fuzzy matching (fast; default false)", B)},
        required=["source_program", "target_program"],
        mode="project",
        timeout=1800,
        helpers=_DOC,
        body='''
        gp = open_project()
        src = open_program(gp, arg("source_program"))
        tgt = open_program(gp, arg("target_program"))
        flt = arg("filter", "documented")
        thr = float(arg("threshold", 0.85))
        tidx = {}
        tfeat = []
        for g in tgt.getFunctionManager().getFunctions(True):
            if g.isThunk(): continue
            h, n = norm_hash(g, tgt)
            tidx.setdefault(h, []).append(g)
            if not arg_bool("exact_only"):
                tfeat.append((g, features(g, tgt)))
        sources = [f for f in src.getFunctionManager().getFunctions(True) if not f.isThunk()]
        if flt == "documented": sources = [f for f in sources if is_documented(f)]
        elif flt == "undocumented": sources = [f for f in sources if not is_documented(f)]
        matches = []
        for f in sources:
            h, n = norm_hash(f, src)
            if h in tidx and len(tidx[h]) == 1:
                g = tidx[h][0]
                matches.append({"source": _s(f.getName()), "source_address": _s(f.getEntryPoint()),
                                "target": _s(g.getName()), "target_address": _s(g.getEntryPoint()),
                                "similarity": 1.0, "method": "exact_hash"})
                continue
            if arg_bool("exact_only") or n < 5:
                continue
            ff = features(f, src)
            best, bs = None, 0.0
            for g, gf in tfeat:
                if abs(gf["n"] - ff["n"]) > max(ff["n"], gf["n"]) * 0.3: continue
                s = similarity(ff, gf)
                if s > bs: best, bs = g, s
            if best is not None and bs >= thr:
                matches.append({"source": _s(f.getName()), "source_address": _s(f.getEntryPoint()),
                                "target": _s(best.getName()), "target_address": _s(best.getEntryPoint()),
                                "similarity": bs, "method": "fuzzy"})
        r = page(matches, arg("offset"), arg("limit"))
        r.update({"sources_considered": len(sources), "exact": len([m for m in matches if m["method"] == "exact_hash"]),
                  "fuzzy": len([m for m in matches if m["method"] == "fuzzy"])})
        return r
        ''',
    ),
    JTool(
        name="merge_program_documentation",
        description="Copy RE documentation (function names, prototypes, plate comments, EOL/PRE/POST comments, non-default labels) from one program to another. match_by=address (same build) or hash (normalized-hash matches, works across rebuilt binaries). dry_run reports without writing.",
        properties={"source": _p("Source binary"), "target": _p("Target binary"),
                    "match_by": _p("address (default) or hash", enum=["address", "hash"]),
                    "dry_run": _p("Report only (default false)", B)},
        required=["source", "target"],
        mode="project",
        timeout=1800,
        helpers=_DOC,
        body='''
        gp = open_project()
        src = open_program(gp, arg("source"))
        dry = arg_bool("dry_run")
        tgt = open_program(gp, arg("target"), read_only=dry)
        by_hash = arg("match_by", "address") == "hash"
        tidx = {}
        if by_hash:
            for g in tgt.getFunctionManager().getFunctions(True):
                h, _ = norm_hash(g, tgt)
                tidx.setdefault(h, []).append(g)
        planned = []
        for f in src.getFunctionManager().getFunctions(True):
            if not is_documented(f) and not f.getComment():
                continue
            if by_hash:
                h, _ = norm_hash(f, src)
                cand = tidx.get(h, [])
                g = cand[0] if len(cand) == 1 else None
            else:
                a = tgt.getAddressFactory().getAddress(_s(f.getEntryPoint()))
                g = tgt.getFunctionManager().getFunctionAt(a) if a else None
            if g is None:
                continue
            planned.append((f, g))
        results = []
        if not dry:
            tid = tgt.startTransaction("merge_program_documentation")
            try:
                for f, g in planned:
                    doc = function_doc(f, src)
                    e = {"name": doc["name"], "plate_comment": doc["plate_comment"],
                         "comments": [{"offset": c["offset"], "type": c["type"], "text": c["text"]} for c in doc["comments"]],
                         "labels": [{"offset": l["offset"], "name": l["name"]} for l in doc["labels"]],
                         "tags": doc["tags"]}
                    if f.getSignatureSource() != SourceType.DEFAULT:
                        e["prototype"] = doc["prototype"]
                    use_program(tgt)
                    results.append({"source": doc["name"], "target_address": _s(g.getEntryPoint()), "steps": apply_doc(g, e, tgt)})
            finally:
                tgt.endTransaction(tid, True)
            gp.save(tgt)
        return {"dry_run": dry, "match_by": "hash" if by_hash else "address", "matched": len(planned),
                "planned": [{"source": _s(f.getName()), "target": _s(g.getName()), "target_address": _s(g.getEntryPoint())}
                            for f, g in planned][:200],
                "applied": len(results), "results": results[:100]}
        ''',
    ),
    JTool(
        name="compare_programs_documentation",
        description="Compare documentation progress across every program in a project: function counts, documented/undocumented, plate comments, average completeness.",
        properties={"programs": _p("Comma-separated subset (default all)")},
        mode="project",
        timeout=1800,
        helpers=_DOC,
        body='''
        gp = open_project()
        names = arg_list("programs") or [df.getName() for df in walk_files(gp) if df.getContentType() == "Program"]
        out = []
        for n in names:
            try:
                p = open_program(gp, n)
            except (Exception, Throwable) as e:
                out.append({"program": n, "error": _s(e)}); continue
            funcs = [f for f in p.getFunctionManager().getFunctions(True) if not f.isThunk()]
            doc = [f for f in funcs if is_documented(f)]
            plate = [f for f in funcs if f.getComment()]
            sample = funcs[:200]
            avg = sum(completeness(f, p)["score"] for f in sample) / float(len(sample)) if sample else 0
            out.append({"program": n, "functions": len(funcs), "documented": len(doc),
                        "undocumented": len(funcs) - len(doc), "with_plate_comment": len(plate),
                        "documented_pct": round(100.0 * len(doc) / len(funcs), 1) if funcs else 0,
                        "avg_completeness_sample": round(avg, 1)})
        return {"project": ARGS.get("project_name"), "programs": out}
        ''',
    ),
)


# ---------------------------------------------------------------------------
# Documentation archive (local JSONL store, optional HTTP upsert)
# ---------------------------------------------------------------------------

def _archive_path() -> Path:
    p = Path(os.environ.get("KAWAIIDRA_DOC_ARCHIVE", Path.home() / ".kawaiidra" / "doc_archive.jsonl"))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _archive_store(records: list, dry_run: bool) -> dict:
    url = os.environ.get("KAWAIIDRA_ARCHIVE_URL") or os.environ.get("GHIDRA_MCP_ARCHIVE_URL")
    path = _archive_path()
    existing = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                existing[(r["hash"], r.get("binary"))] = r
            except (ValueError, KeyError):
                continue
    created = updated = 0
    for r in records:
        key = (r["hash"], r.get("binary"))
        if key in existing:
            merged = dict(existing[key])
            merged.update({k: v for k, v in r.items() if v not in (None, "", [], {})})
            existing[key] = merged
            updated += 1
        else:
            existing[key] = r
            created += 1
    errors = []
    if not dry_run:
        path.write_text("".join(json.dumps(v) + "\n" for v in existing.values()), encoding="utf-8")
        if url:
            for r in records:
                try:
                    req = urllib.request.Request(url.rstrip("/") + "/v1/doc_archive/upsert",
                                                 data=json.dumps(r).encode(), method="POST",
                                                 headers={"Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=10).read()
                except Exception as e:  # noqa: BLE001
                    errors.append(str(e))
    return {"archive": str(path), "remote": url, "created": created, "updated": updated,
            "errors": errors[:10], "dry_run": dry_run}


def _ingest(args: dict, single: bool) -> dict:
    tool = REGISTRY_DOC_EXPORT
    sub = dict(args)
    if not single:
        sub["_bulk"] = True
    res = execute(tool, sub)
    if res.get("error"):
        return res
    docs = res.get("docs", [])
    version = args.get("version_override")
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for d in docs:
        d["binary"] = args.get("binary_name")
        d["version"] = version
        d["ingested_at"] = now
    out = _archive_store(docs, bool(args.get("dry_run")))
    out["functions"] = len(docs)
    return out


REGISTRY_DOC_EXPORT = JTool(
    name="_doc_export",
    description="internal",
    properties={"function": S, "limit": I, "skip_default_named": B},
    helpers=_DOC,
    body='''
    p = prog()
    if ARGS.get("_bulk"):
        funcs = [f for f in p.getFunctionManager().getFunctions(True) if not f.isThunk()]
        if arg_bool("skip_default_named", True):
            funcs = [f for f in funcs if is_documented(f)]
        lim = arg("limit")
        if lim: funcs = funcs[:int(lim)]
    else:
        funcs = [find_func()]
    return {"docs": [function_doc(f) for f in funcs]}
    ''',
)

register(
    JTool(name="archive_ingest_function", mode="local",
          local=lambda a: _ingest(a, True),
          needs_binary=True,
          description="Ingest one function's documentation (keyed by normalized hash) into the cross-version doc archive: a local JSONL store (~/.kawaiidra/doc_archive.jsonl or KAWAIIDRA_DOC_ARCHIVE), also POSTed to KAWAIIDRA_ARCHIVE_URL/GHIDRA_MCP_ARCHIVE_URL if set. Idempotent field-level merge.",
          properties={**FUNC, "version_override": _p("Version label for this binary"),
                      "dry_run": _p("Do not write (default false)", B),
                      "project_name": _p("Project name (optional)")},
          required=["function"]),
    JTool(name="archive_ingest_program", mode="local",
          local=lambda a: _ingest(a, False),
          needs_binary=True,
          description="Bulk-ingest every documented function of a binary into the cross-version doc archive (see archive_ingest_function). Returns created/updated counts.",
          properties={"version_override": _p("Version label"), "limit": _p("Max functions", I),
                      "skip_default_named": _p("Skip FUN_* functions (default true)", B),
                      "dry_run": _p("Do not write (default false)", B),
                      "project_name": _p("Project name (optional)")}),
)
