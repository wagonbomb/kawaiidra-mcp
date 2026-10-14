"""Phase 12 — Function editing: tags, this-type, storage, bulk variables, flow, P-code, dataflow."""

from __future__ import annotations

from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
O = {"type": "object"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


FUNC = {"function": _p("Function name or address")}

# Decompiler-level variable helpers
_HIGH = '''
from ghidra.program.model.pcode import HighFunctionDBUtil

def high_symbols(f):
    res = decompile(f, 60)
    hf = res.getHighFunction()
    syms = {}
    lsm = hf.getLocalSymbolMap()
    for s in lsm.getSymbols():
        syms[_s(s.getName())] = s
    return hf, syms

def commit_params(hf):
    try:
        HighFunctionDBUtil.commitParamsToDatabase(hf, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)
    except (Exception, Throwable):
        HighFunctionDBUtil.commitParamsToDatabase(hf, True, SourceType.USER_DEFINED)

def update_var(sym, new_name=None, new_type=None):
    HighFunctionDBUtil.updateDBVariable(sym, new_name, new_type, SourceType.USER_DEFINED)
'''

register(
    # ----- tags --------------------------------------------------------------
    JTool(
        name="add_function_tag",
        description="Attach tags to one function (function + tags) or many in one transaction (assignments=[{function, tags}]). Tags are comma-separated and created on the fly; tag_comments gives new tags a description.",
        properties={**FUNC, "tags": _p("Comma-separated tags"),
                    "tag_comments": {"type": "object", "description": "{tag: description} for new tags"},
                    "assignments": {"type": "array", "items": O, "description": '[{"function": "...", "tags": "a,b"}]'}},
        mode="write",
        body='''
        p = prog()
        tm = p.getFunctionManager().getFunctionTagManager()
        comments = arg_json("tag_comments", {}) or {}
        jobs = arg_json("assignments", []) or []
        if not jobs:
            if not arg("tags"):
                raise Fail("tags (or assignments) is required")
            jobs = [{"function": None, "tags": arg("tags")}]
        out = []
        with tx("Add function tags"):
            for job in jobs:
                f = find_func(job.get("function"))
                tags = job["tags"] if isinstance(job["tags"], list) else [t.strip() for t in job["tags"].split(",") if t.strip()]
                for t in tags:
                    if tm.getFunctionTag(t) is None:
                        tm.createFunctionTag(t, comments.get(t, ""))
                    f.addTag(t)
                out.append({"function": _s(f.getName()), "tags": sorted(_s(t.getName()) for t in f.getTags())})
        return {"success": True, "results": out}
        ''',
    ),
    JTool(
        name="remove_function_tag",
        description="Detach tags from one function (or many via assignments). Does not delete the program-wide tag definition.",
        properties={**FUNC, "tags": _p("Comma-separated tags"),
                    "assignments": {"type": "array", "items": O, "description": '[{"function": "...", "tags": "a,b"}]'}},
        mode="write",
        body='''
        jobs = arg_json("assignments", []) or [{"function": None, "tags": arg("tags") or ""}]
        out = []
        with tx("Remove function tags"):
            for job in jobs:
                f = find_func(job.get("function"))
                tags = job["tags"] if isinstance(job["tags"], list) else [t.strip() for t in job["tags"].split(",") if t.strip()]
                for t in tags:
                    f.removeTag(t)
                out.append({"function": _s(f.getName()), "tags": sorted(_s(t.getName()) for t in f.getTags())})
        return {"success": True, "results": out}
        ''',
    ),
    JTool(
        name="delete_function_tag",
        description="Delete a program-wide function tag definition (detaches it from every function).",
        properties={"name": _p("Tag name")},
        required=["name"],
        mode="write",
        body='''
        tm = prog().getFunctionManager().getFunctionTagManager()
        t = tm.getFunctionTag(arg("name"))
        if t is None:
            raise Fail("Tag not found: " + arg("name"))
        with tx("Delete function tag"):
            t.delete()
        return {"success": True, "deleted": arg("name")}
        ''',
    ),
    JTool(
        name="list_function_tags",
        description="List program-wide function tags with use counts; with tag= list the functions carrying that tag.",
        properties={"tag": _p("List functions with this tag"), "offset": _p("Offset", I), "limit": _p("Limit", I)},
        body='''
        p = prog()
        tm = p.getFunctionManager().getFunctionTagManager()
        if arg("tag"):
            out = []
            for f in p.getFunctionManager().getFunctions(True):
                if any(t.getName() == arg("tag") for t in f.getTags()):
                    out.append(func_info(f))
            r = page(out, arg("offset"), arg("limit"))
            r["tag"] = arg("tag")
            return r
        tags = []
        for t in tm.getAllFunctionTags():
            tags.append({"name": _s(t.getName()), "comment": _s(t.getComment()), "use_count": tm.getUseCount(t)})
        return page(sorted(tags, key=lambda t: t["name"]), arg("offset"), arg("limit"))
        ''',
    ),
    JTool(
        name="set_function_tag_comment",
        description="Update the description of an existing program-wide function tag.",
        properties={"name": _p("Tag name"), "comment": _p("New description")},
        required=["name", "comment"],
        mode="write",
        body='''
        t = prog().getFunctionManager().getFunctionTagManager().getFunctionTag(arg("name"))
        if t is None:
            raise Fail("Tag not found: " + arg("name"))
        with tx("Set tag comment"):
            t.setComment(arg("comment"))
        return {"success": True, "name": arg("name"), "comment": arg("comment")}
        ''',
    ),
    # ----- signatures & variables -------------------------------------------
    JTool(
        name="set_function_this_type",
        description="Make a function a member of a class so the implicit 'this' is '<Class> *' (moves it into the class namespace, creating the class if needed, and switches to __thiscall when the compiler spec has it).",
        properties={**FUNC, "this_type": _p("Class name, 'MyClass' or 'MyClass *'")},
        required=["function", "this_type"],
        mode="write",
        body='''
        p = prog()
        f = find_func()
        cname = arg("this_type").replace("*", "").strip()
        st = p.getSymbolTable()
        with tx("Set this type"):
            ns = None
            for s in st.getSymbols(cname):
                if s.getSymbolType() == SymbolType.CLASS:
                    ns = s.getObject(); break
            if ns is None:
                existing = None
                for s in st.getSymbols(cname):
                    if s.getSymbolType() == SymbolType.NAMESPACE:
                        existing = s.getObject(); break
                if existing is not None:
                    from ghidra.app.util import NamespaceUtils
                    ns = NamespaceUtils.convertNamespaceToClass(existing)
                else:
                    ns = st.createClass(p.getGlobalNamespace(), cname, SourceType.USER_DEFINED)
            f.setParentNamespace(ns)
            names = [_s(m.getName()) for m in p.getCompilerSpec().getCallingConventions()]
            if "__thiscall" in names:
                f.setCallingConvention("__thiscall")
        params = [{"name": _s(x.getName()), "type": _s(x.getDataType().getName())} for x in f.getParameters()]
        return {"success": True, "function": _s(f.getName(True)), "class": cname,
                "calling_convention": _s(f.getCallingConventionName()), "parameters": params}
        ''',
    ),
    JTool(
        name="set_variable_type",
        description="Set the data type of a function variable (local OR parameter) by name at the decompiler layer. variable_name='this' types the implicit this.",
        properties={**FUNC, "variable_name": _p("Variable or parameter name"), "new_type": _p("Data type")},
        required=["function", "variable_name", "new_type"],
        mode="write",
        helpers=_HIGH,
        body='''
        f = find_func()
        dt = find_dt(arg("new_type"))
        hf, syms = high_symbols(f)
        sym = syms.get(arg("variable_name"))
        if sym is None:
            raise Fail("Variable not found: %s (have: %s)" % (arg("variable_name"), ", ".join(sorted(syms))))
        with tx("Set variable type"):
            if sym.isParameter():
                commit_params(hf)
                hf, syms = high_symbols(f)
                sym = syms[arg("variable_name")]
            update_var(sym, None, dt)
        return {"success": True, "function": _s(f.getName()), "variable": arg("variable_name"),
                "type": _s(dt.getName()), "is_parameter": sym.isParameter()}
        ''',
    ),
    JTool(
        name="rename_variables",
        description="Rename several decompiler variables/parameters of a function in one transaction: variable_renames={old: new}.",
        properties={**FUNC, "variable_renames": {"type": "object", "description": '{"local_10": "count", "param_1": "ctx"}'},
                    "force_individual": _p("Continue past failures (default true)", B)},
        required=["function", "variable_renames"],
        mode="write",
        helpers=_HIGH,
        body='''
        f = find_func()
        ren = arg_json("variable_renames", {})
        hf, syms = high_symbols(f)
        if any(syms.get(o) is not None and syms[o].isParameter() for o in ren):
            with tx("Commit params"):
                commit_params(hf)
            hf, syms = high_symbols(f)
        done, failed = [], []
        with tx("Rename variables"):
            for old, new in ren.items():
                s = syms.get(old)
                if s is None:
                    failed.append({"old": old, "error": "not found"})
                    if not arg_bool("force_individual", True): raise Fail("Variable not found: " + old)
                    continue
                try:
                    update_var(s, new, None)
                    done.append({"old": old, "new": new})
                except (Exception, Throwable) as e:
                    failed.append({"old": old, "error": _s(e)})
                    if not arg_bool("force_individual", True): raise
        return {"success": len(failed) == 0, "renamed": done, "failed": failed}
        ''',
    ),
    JTool(
        name="set_variables",
        description="Set types and names for several variables atomically (types first, then renames). variables=[{name, new_name?, type?}].",
        properties={**FUNC, "variables": {"type": "array", "items": O,
                                          "description": '[{"name": "local_10", "new_name": "dwCount", "type": "uint"}]'}},
        required=["function", "variables"],
        mode="write",
        helpers=_HIGH,
        body='''
        f = find_func()
        specs = arg_json("variables", [])
        hf, syms = high_symbols(f)
        if any(syms.get(v["name"]) is not None and syms[v["name"]].isParameter() for v in specs):
            with tx("Commit params"):
                commit_params(hf)
            hf, syms = high_symbols(f)
        for v in specs:
            if syms.get(v["name"]) is None:
                raise Fail("Variable not found: %s" % v["name"])
        tid = prog().startTransaction("set_variables")
        ok = False
        try:
            for v in specs:
                if v.get("type"):
                    update_var(syms[v["name"]], None, find_dt(v["type"]))
            hf, syms2 = high_symbols(f)
            for v in specs:
                if v.get("new_name"):
                    s = syms2.get(v["name"])
                    if s is not None:
                        update_var(s, v["new_name"], None)
            ok = True
        finally:
            prog().endTransaction(tid, ok)
        _, final = high_symbols(f)
        return {"success": True, "variables": [{"name": n, "type": _s(s.getDataType().getName()),
                                                "is_parameter": s.isParameter()} for n, s in sorted(final.items())]}
        ''',
    ),
    JTool(
        name="batch_rename_function_components",
        description="In one call: rename parameters (parameter_renames) and locals (local_renames) and set the return type of a function.",
        properties={**FUNC, "parameter_renames": O, "local_renames": O, "return_type": _p("New return type")},
        required=["function"],
        mode="write",
        helpers=_HIGH,
        body='''
        f = find_func()
        pr = arg_json("parameter_renames", {}) or {}
        lr = arg_json("local_renames", {}) or {}
        hf, syms = high_symbols(f)
        out = {"parameters": [], "locals": [], "failed": []}
        with tx("Batch rename function components"):
            if pr:
                commit_params(hf)
                for prm in f.getParameters():
                    old = _s(prm.getName())
                    if old in pr:
                        prm.setName(pr[old], SourceType.USER_DEFINED)
                        out["parameters"].append({"old": old, "new": pr[old]})
            if arg("return_type"):
                f.setReturnType(find_dt(arg("return_type")), SourceType.USER_DEFINED)
                out["return_type"] = arg("return_type")
        if lr:
            hf, syms = high_symbols(f)
            with tx("Rename locals"):
                for old, new in lr.items():
                    s = syms.get(old)
                    if s is None:
                        out["failed"].append(old); continue
                    update_var(s, new, None)
                    out["locals"].append({"old": old, "new": new})
        out["signature"] = _s(f.getSignature().getPrototypeString())
        out["success"] = not out["failed"]
        return out
        ''',
    ),
    JTool(
        name="set_variable_storage",
        description="Pin a function variable to explicit storage: a register ('RCX', 'x0') or a stack offset ('Stack[0x10]' / 'stack:0x10'). Enables custom storage for parameters.",
        properties={**FUNC, "variable_name": _p("Variable or parameter name"),
                    "storage": _p("Register name or Stack[offset]"), "type": _p("Optional new data type")},
        required=["function", "variable_name", "storage"],
        mode="write",
        body='''
        from ghidra.program.model.listing import VariableStorage
        import re as _re
        p = prog()
        f = find_func()
        target = None
        for v in f.getAllVariables():
            if v.getName() == arg("variable_name"):
                target = v; break
        if target is None:
            raise Fail("Variable not found in database (commit it first via set_variable_type): " + arg("variable_name"))
        dt = find_dt(arg("type")) if arg("type") else target.getDataType()
        spec = arg("storage").strip()
        m = _re.match(r"(?i)(?:stack\\[|stack:)\\s*(-?0x[0-9a-f]+|-?\\d+)\\]?", spec)
        if m:
            storage = VariableStorage(p, int(m.group(1), 0), dt.getLength())
        else:
            reg = p.getRegister(spec) or p.getRegister(spec.upper()) or p.getRegister(spec.lower())
            if reg is None:
                raise Fail("Unknown register: " + spec)
            size = dt.getLength() if dt.getLength() > 0 else reg.getMinimumByteSize()
            if size > reg.getMinimumByteSize():
                raise Fail("Type %s (%d bytes) does not fit register %s" % (_s(dt.getName()), size, _s(reg.getName())))
            # Little-endian sub-register: low bytes live at the register's base address
            storage = VariableStorage(p, reg.getAddress().add(reg.getMinimumByteSize() - size) if p.getLanguage().isBigEndian() else reg.getAddress(), size)
        with tx("Set variable storage"):
            if target in list(f.getParameters()):
                f.setCustomVariableStorage(True)
                target = [x for x in f.getParameters() if x.getName() == arg("variable_name")][0]
            target.setDataType(dt, storage, True, SourceType.USER_DEFINED)
        return {"success": True, "variable": arg("variable_name"), "storage": _s(target.getVariableStorage()),
                "type": _s(target.getDataType().getName())}
        ''',
    ),
    # ----- flow ----------------------------------------------------------------
    JTool(
        name="clear_flow_and_repair",
        description="Ghidra's 'Clear Flow and Repair': clear instruction flow reachable from a seed range, then repair function bodies and re-disassemble retained flow. Use to undo bad disassembly.",
        properties={"start_address": _p("Seed start"), "end_address": _p("Seed end (default = start)"),
                    "clear_data": _p("Also clear data (default false)", B),
                    "clear_labels": _p("Also clear labels (default false)", B)},
        required=["start_address"],
        mode="write",
        timeout=600,
        body='''
        from ghidra.app.plugin.core.clear import ClearFlowAndRepairCmd
        p = prog()
        s = addr(arg("start_address"))
        e = addr(arg("end_address")) if arg("end_address") else s
        aset = p.getAddressFactory().getAddressSet(s, e)
        before = p.getFunctionManager().getFunctionCount()
        with tx("Clear flow and repair"):
            cmd = ClearFlowAndRepairCmd(aset, arg_bool("clear_data"), arg_bool("clear_labels"), True)
            ok = cmd.applyTo(p, MONITOR)
        if not ok:
            raise Fail("ClearFlowAndRepair failed: " + _s(cmd.getStatusMsg()))
        return {"success": True, "start": _s(s), "end": _s(e),
                "functions_before": before, "functions_after": p.getFunctionManager().getFunctionCount()}
        ''',
    ),
    JTool(
        name="clear_instruction_flow_override",
        description="Clear a flow override (CALL/BRANCH/RETURN/CALL_RETURN override) on the instruction at an address, or set one with flow_override.",
        properties={"address": _p("Instruction address"),
                    "flow_override": _p("Set this override instead of clearing", enum=["NONE", "BRANCH", "CALL", "CALL_RETURN", "RETURN"])},
        required=["address"],
        mode="write",
        body='''
        from ghidra.program.model.listing import FlowOverride
        ins = prog().getListing().getInstructionAt(addr(arg("address")))
        if ins is None:
            raise Fail("No instruction at " + arg("address"))
        old = _s(ins.getFlowOverride())
        new = getattr(FlowOverride, (arg("flow_override") or "NONE").upper())
        with tx("Flow override"):
            ins.setFlowOverride(new)
        return {"success": True, "address": _s(ins.getAddress()), "old_override": old, "new_override": _s(ins.getFlowOverride())}
        ''',
    ),
    # ----- decompiler / P-code ---------------------------------------------------
    JTool(
        name="force_decompile",
        description="Decompile a function fresh (no kawaiidra result cache, new decompiler session) — use after edits.",
        properties={**FUNC, "timeout": _p("Decompiler timeout seconds (default 60)", I)},
        required=["function"],
        body='''
        f = find_func()
        res = decompile(f, int(arg("timeout", 60)))
        return {"function": _s(f.getName()), "address": _s(f.getEntryPoint()),
                "signature": _s(res.getDecompiledFunction().getSignature()),
                "code": _s(res.getDecompiledFunction().getC())}
        ''',
    ),
    JTool(
        name="get_functions",
        description="Everything about one or many functions in one call. functions= comma-separated names/addresses (bulk, up to 20) or function= for one. fields= subset of: signature,decompile,callers,callees,xrefs,variables,disasm,tags,comments,metrics.",
        properties={**FUNC, "functions": _p("Comma-separated names or addresses (bulk, max 20)"),
                    "fields": _p("Comma-separated field subset (default: signature,callers,callees,variables,tags,comments,metrics)"),
                    "include_disasm": _p("Shortcut to add disasm", B)},
        timeout=600,
        body='''
        p = prog()
        names = arg_list("functions") or [None]
        if len(names) > 20:
            raise Fail("At most 20 functions per call")
        fields = set(arg_list("fields") or ["signature", "callers", "callees", "variables", "tags", "comments", "metrics"])
        if arg_bool("include_disasm"): fields.add("disasm")
        out = []
        for n in names:
            try:
                f = find_func(n)
            except Fail as e:
                out.append({"query": n, "error": _s(e.args[0])}); continue
            d = func_info(f)
            if "signature" in fields:
                d["calling_convention"] = _s(f.getCallingConventionName())
                d["is_thunk"] = f.isThunk(); d["no_return"] = f.hasNoReturn()
            if "callers" in fields:
                d["callers"] = [_s(c.getName()) for c in f.getCallingFunctions(MONITOR)]
            if "callees" in fields:
                d["callees"] = [_s(c.getName()) for c in f.getCalledFunctions(MONITOR)]
            if "xrefs" in fields:
                d["xrefs"] = [{"from": _s(r.getFromAddress()), "type": _s(r.getReferenceType())}
                              for r in p.getReferenceManager().getReferencesTo(f.getEntryPoint())][:50]
            if "variables" in fields:
                d["parameters"] = [{"name": _s(x.getName()), "type": _s(x.getDataType().getName()),
                                    "storage": _s(x.getVariableStorage())} for x in f.getParameters()]
                d["locals"] = [{"name": _s(x.getName()), "type": _s(x.getDataType().getName()),
                                "storage": _s(x.getVariableStorage())} for x in f.getLocalVariables()]
            if "tags" in fields:
                d["tags"] = sorted(_s(t.getName()) for t in f.getTags())
            if "comments" in fields:
                d["plate_comment"] = _s(f.getComment())
                d["repeatable_comment"] = _s(f.getRepeatableComment())
            if "metrics" in fields:
                ins = list(p.getListing().getInstructions(f.getBody(), True))
                d["instruction_count"] = len(ins)
                from ghidra.program.model.block import BasicBlockModel
                bbm = BasicBlockModel(p)
                d["basic_blocks"] = len(list(bbm.getCodeBlocksContaining(f.getBody(), MONITOR)))
            if "disasm" in fields:
                d["disasm"] = ["%s  %s" % (_s(i.getAddress()), _s(i)) for i in p.getListing().getInstructions(f.getBody(), True)][:500]
            if "decompile" in fields:
                try:
                    d["decompile"] = _s(decompile(f, 60).getDecompiledFunction().getC())
                except Fail as e:
                    d["decompile_error"] = _s(e.args[0])
            out.append(d)
        return out[0] if (len(out) == 1 and not arg("functions")) else {"functions": out, "count": len(out)}
        ''',
    ),
    JTool(
        name="get_function_pcode",
        description="Dump P-code for a function: 'basic' = raw per-instruction P-code; 'high' (default) = decompiler HighFunction P-code by basic block with varnodes.",
        properties={**FUNC, "granularity": _p("basic or high", enum=["basic", "high"]),
                    "max_ops": _p("Cap on emitted ops (default 2000)", I)},
        required=["function"],
        body='''
        p = prog()
        f = find_func()
        maxops = int(arg("max_ops", 2000))
        n = 0
        if arg("granularity", "high") == "basic":
            out = []
            for ins in p.getListing().getInstructions(f.getBody(), True):
                ops = [_s(op) for op in ins.getPcode()]
                n += len(ops)
                out.append({"address": _s(ins.getAddress()), "instruction": _s(ins), "pcode": ops})
                if n >= maxops: break
            return {"function": _s(f.getName()), "granularity": "basic", "instructions": out, "op_count": n,
                    "truncated": n >= maxops}
        hf = decompile(f, 60).getHighFunction()
        blocks = []
        for bb in hf.getBasicBlocks():
            ops = []
            it = bb.getIterator()
            while it.hasNext() and n < maxops:
                op = it.next()
                ops.append({"seq": _s(op.getSeqnum()), "op": _s(op.getMnemonic()),
                            "out": _s(op.getOutput()) if op.getOutput() else None,
                            "in": [_s(v) for v in op.getInputs()], "text": _s(op)})
                n += 1
            blocks.append({"index": bb.getIndex(), "start": _s(bb.getStart()), "stop": _s(bb.getStop()),
                           "in": [bb.getIn(i).getIndex() for i in range(bb.getInSize())],
                           "out": [bb.getOut(i).getIndex() for i in range(bb.getOutSize())], "ops": ops})
        return {"function": _s(f.getName()), "granularity": "high", "blocks": blocks, "op_count": n,
                "truncated": n >= maxops}
        ''',
    ),
    JTool(
        name="analyze_dataflow",
        description="Trace value propagation for a decompiler variable through a function's P-code graph: backward (where does it come from) or forward (where does it flow).",
        properties={"address": _p("Address inside the function"), "variable": _p("Variable name (decompiler view)"),
                    "direction": _p("backward (default) or forward", enum=["backward", "forward"]),
                    "max_steps": _p("Max P-code ops visited (default 200)", I)},
        required=["address", "variable"],
        body='''
        p = prog()
        a = addr(arg("address"))
        f = p.getFunctionManager().getFunctionContaining(a)
        if f is None:
            raise Fail("No function contains " + _s(a))
        hf = decompile(f, 60).getHighFunction()
        hv = None
        for s in hf.getLocalSymbolMap().getSymbols():
            if s.getName() == arg("variable"):
                hv = s.getHighVariable(); break
        if hv is None:
            for s in hf.getGlobalSymbolMap().getSymbols():
                if s.getName() == arg("variable"):
                    hv = s.getHighVariable(); break
        if hv is None:
            raise Fail("Variable not found in decompiled function: " + arg("variable"))
        fwd = arg("direction", "backward") == "forward"
        maxs = int(arg("max_steps", 200))
        seen = set()
        steps = []
        work = list(hv.getInstances())
        while work and len(steps) < maxs:
            vn = work.pop(0)
            ops = list(vn.getDescendants()) if fwd else ([vn.getDef()] if vn.getDef() is not None else [])
            for op in ops:
                key = _s(op.getSeqnum())
                if key in seen: continue
                seen.add(key)
                hvo = op.getOutput().getHigh() if op.getOutput() is not None else None
                steps.append({"address": _s(op.getSeqnum().getTarget()), "op": _s(op.getMnemonic()),
                              "text": _s(op),
                              "output_var": _s(hvo.getName()) if hvo is not None else None,
                              "input_vars": [_s(i.getHigh().getName()) if i.getHigh() is not None else _s(i) for i in op.getInputs()]})
                if fwd:
                    if op.getOutput() is not None: work.append(op.getOutput())
                else:
                    work.extend(list(op.getInputs()))
        sources = sorted(set(s2 for st in steps for s2 in st["input_vars"] if s2)) if not fwd else None
        sinks = [st for st in steps if st["op"] in ("CALL", "CALLIND", "STORE", "RETURN")] if fwd else None
        return {"function": _s(f.getName()), "variable": arg("variable"), "direction": "forward" if fwd else "backward",
                "type": _s(hv.getDataType().getName()), "steps": steps, "truncated": len(steps) >= maxs,
                "contributing_values": sources, "sinks": sinks}
        ''',
    ),
)
