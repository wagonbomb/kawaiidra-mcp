"""Phase 16 — GUI-session tools: debugger (Trace RMI), UI cursor, running tools.

These run inside a live Ghidra GUI through kawaiidra's GUI bridge
(KAWAIIDRA_GUI_MODE=true + ghidra_bridge server running in Ghidra), exactly as
bethington/ghidra-mcp exposes them only from its GUI plugin. The Jython is
executed remotely with ``remote_exec`` and returns JSON via ``_mcp_out``.
"""

from __future__ import annotations

import json
import textwrap

from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


GUI_PRELUDE = r'''
import json, traceback, time
from java.lang import Throwable
from java.util.concurrent import TimeUnit
def _s(v):
    if v is None: return None
    try: return unicode(v)
    except Exception: return str(v)
class Fail(Exception): pass
TOOL = state.getTool()
def svc(cname):
    import java.lang
    cls = java.lang.Class.forName(cname)
    s = TOOL.getService(cls) if TOOL is not None else None
    if s is None:
        raise Fail("Service unavailable: %s (open the Debugger tool in Ghidra)" % cname.rsplit(".", 1)[-1])
    return s
def traces():
    return svc("ghidra.app.services.DebuggerTraceManagerService")
def coords():
    c = traces().getCurrent()
    if c is None or c.getTrace() is None:
        raise Fail("No active debug trace (use debugger_launch first)")
    return c
def target():
    t = coords().getTarget()
    if t is None or not t.isValid():
        raise Fail("No live target for the current trace")
    return t
def process_state():
    """Process-wide state. Debuggers here (dbgeng, gdb default) are all-stop, so
    any STOPPED thread means the process is stopped; agents may leave a stale
    RUNNING on other threads after an interrupt."""
    c = traces().getCurrent()
    t = c.getTarget() if c is not None else None
    if t is None or not t.isValid():
        return "TERMINATED"
    states = set()
    try:
        snap = max(c.getSnap(), latest_snap())
        for th in c.getTrace().getThreadManager().getLiveThreads(snap):
            states.add(_s(t.getThreadExecutionState(th)))
    except (Exception, Throwable):
        pass
    if not states and c.getThread() is not None:
        states.add(_s(t.getThreadExecutionState(c.getThread())))
    if "STOPPED" in states:
        return "STOPPED"
    if "RUNNING" in states:
        return "RUNNING"
    return ",".join(sorted(x for x in states if x)) or None
def latest_snap():
    c = traces().getCurrent()
    try:
        return c.getTrace().getTimeManager().getMaxSnap()
    except (Exception, Throwable):
        return c.getSnap()
def wait_state(want, secs, after_snap=None):
    """Wait for process state `want`; with after_snap, also require a newer snapshot."""
    deadline = time.time() + secs
    while True:
        st = process_state()
        fresh = after_snap is None or latest_snap() > after_snap
        if (st == want and fresh) or time.time() > deadline:
            return st if fresh else "PENDING"
        time.sleep(0.2)
def wait(fut, secs=30):
    return fut.get(secs, TimeUnit.SECONDS) if fut is not None else None
def dyn_addr(text):
    """Dynamic address from hex text, or the value of a register (e.g. RIP)."""
    c = coords()
    v = c.getView()
    a = None
    try:
        a = v.getAddressFactory().getAddress(_s(text))
    except (Exception, Throwable):
        a = None
    if a is None:
        reg = c.getPlatform().getLanguage().getRegister(_s(text).upper()) or c.getPlatform().getLanguage().getRegister(_s(text))
        if reg is not None and c.getThread() is not None:
            rs = c.getTrace().getMemoryManager().getMemoryRegisterSpace(c.getThread(), c.getFrame(), False)
            val = rs.getValue(c.getSnap(), reg) if rs else None
            if val is not None and val.hasValue():
                a = v.getAddressFactory().getDefaultAddressSpace().getAddress(long(val.getUnsignedValue()))
    if a is None:
        raise Fail("Invalid address or register: " + _s(text))
    return a
def run_action(name, prompt=None):
    if prompt is None:
        prompt = bool(ARGS.get("_prompts"))
    from ghidra.debug.api.target import ActionName
    from ghidra.debug.api.target.Target import ObjectArgumentPolicy
    an = getattr(ActionName, name)
    pol = None
    for p in ObjectArgumentPolicy.values():
        if "CURRENT" in p.name():
            pol = p
            break
    # Enablement follows the target state (e.g. Interrupt only while running),
    # which lags just-issued commands: retry briefly before giving up.
    best = None
    deadline = time.time() + 5
    while True:
        acts = target().collectActions(an, None, pol)
        for e in acts.values():
            if e.isEnabled() and (best is None or e.specificity() > best.specificity()):
                best = e
        if best is not None or time.time() > deadline:
            break
        time.sleep(0.2)
    if best is None:
        raise Fail("Action %s not available for this target" % name)
    wait(best.invokeAsync(prompt), 60)
    return _s(best.display())
'''


def build_gui_script(code: str, args: dict) -> str:
    """Module-level ARGS + helpers, then the tool body as _mcp_main()."""
    body = textwrap.indent(textwrap.dedent(code).strip("\n"), "    ")
    return (GUI_PRELUDE + "\nARGS = json.loads(%r)\n" % json.dumps(args)
            + "\ndef _mcp_main():\n" + body + "\n"
            # Keep exceptions inside a function: the bridge server shares one
            # __main__ across clients, and a module-level `except ... as e`
            # would leave an unserializable exception bound to `e` there.
            "def _mcp_wrap():\n"
            "    try:\n        return json.dumps(_mcp_main(), default=_s)\n"
            "    except Fail as ex:\n        return json.dumps({'error': _s(ex.args[0])})\n"
            "    except Exception as ex:\n        return json.dumps({'error': _s(ex), 'traceback': traceback.format_exc()[-1500:]})\n"
            "    except Throwable as ex:\n        return json.dumps({'error': _s(ex.toString())})\n"
            "_mcp_out = _mcp_wrap()\n")


def _remote(code: str, args: dict) -> dict:
    from ..bridge.gui_context import get_gui_bridge
    gb = get_gui_bridge()
    if not gb.is_connected and not gb.connect():
        return {"error": "GUI bridge not connected: " + str(gb._connection_error or "unknown") +
                ". Set KAWAIIDRA_GUI_MODE=true, pip install ghidra_bridge, and run the ghidra_bridge server in the Ghidra GUI."}
    script = build_gui_script(code, args)
    try:
        gb._bridge.remote_exec(script)
        return json.loads(gb._bridge.remote_eval("_mcp_out"))
    except Exception as e:  # noqa: BLE001
        return {"error": f"GUI bridge call failed: {e}"}


def _gui_tool(name: str, description: str, code: str, properties: dict | None = None,
              required: list | None = None) -> JTool:
    def run(args: dict, _code=code) -> dict:
        return _remote(_code, {**args, "_prompts": PROMPT_POLICY["enabled"]})
    tool = JTool(name=name, description=description + " [GUI mode]", mode="local", local=run,
                 properties=properties or {}, required=required or [])
    tool.gui_code = code
    return tool


PROMPT_POLICY = {"enabled": False, "reason": None}


def _prompt_policy(args: dict) -> dict:
    action = (args.get("action") or "query").lower()
    if action == "enable":
        PROMPT_POLICY.update(enabled=True, reason=args.get("reason"))
    elif action == "disable":
        PROMPT_POLICY.update(enabled=False, reason=args.get("reason"))
    return {"prompts_allowed": PROMPT_POLICY["enabled"], "reason": PROMPT_POLICY["reason"],
            "note": "When enabled, GUI debugger actions may open Ghidra prompts/dialogs; disabled (default) runs them non-interactively."}


register(
    _gui_tool("debugger_status", "Debugger status: active trace, thread, execution state, snap, frame and module count.", '''
        try:
            c = traces().getCurrent()
        except Fail as e:
            return {"available": False, "reason": _s(e.args[0])}
        if c is None or c.getTrace() is None:
            return {"available": True, "active_trace": None}
        tr = c.getTrace()
        t = c.getTarget()
        th = c.getThread()
        mods = 0
        try:
            mods = len(list(tr.getModuleManager().getLoadedModules(c.getSnap())))
        except (Exception, Throwable):
            pass
        return {"available": True, "active_trace": _s(tr.getName()), "thread": _s(th.getName(c.getSnap())) if th else None,
                "snap": c.getSnap(), "frame": c.getFrame(), "target_alive": bool(t is not None and t.isValid()),
                "target": _s(t.describe()) if t is not None else None,
                "execution_state": _s(t.getThreadExecutionState(th)) if (t is not None and th is not None) else None,
                "process_state": process_state(),
                "module_count": mods}
    '''),
    _gui_tool("debugger_traces", "List all open debug traces.", '''
        cur = traces().getCurrentTrace()
        return {"traces": [{"name": _s(t.getName()), "current": t == cur} for t in traces().getOpenTraces()]}
    '''),
    _gui_tool("debugger_launch_offers", "List debugger launch/attach offers (gdb, lldb, dbgeng, ...) for the current program.", '''
        l = svc("ghidra.app.services.TraceRmiLauncherService")
        out = []
        for o in l.getOffers(currentProgram):
            out.append({"title": _s(o.getTitle()), "config_name": _s(o.getConfigName()),
                        "description": _s(o.getDescription())[:300], "requires_image": o.requiresImage(),
                        "parameters": sorted(_s(k) for k in o.getParameters().keySet())})
        return {"program": _s(currentProgram.getName()) if currentProgram else None, "offers": out}
    '''),
    _gui_tool("debugger_launch", "Launch an executable through Ghidra's Trace RMI launcher (choose offer by title/config name substring; default first offer).", '''
        from ghidra.debug.api.tracermi.TraceRmiLaunchOffer import LaunchConfigurator
        from java.util import HashMap
        from ghidra.util.task import TaskMonitor
        l = svc("ghidra.app.services.TraceRmiLauncherService")
        offers = list(l.getOffers(currentProgram))
        if not offers:
            raise Fail("No launch offers for this program/platform")
        want = (ARGS.get("offer") or "").lower()
        local = [o for o in offers if o.supportsImage() and not any(
            k in _s(o.getConfigName()).lower() for k in ("kernel", "attach", "remote", "svrcx", "-ext", "-trace"))]
        offer = local[0] if local else offers[0]
        if want:
            m = [o for o in offers if want in _s(o.getTitle()).lower() or want in _s(o.getConfigName()).lower()]
            if not m:
                raise Fail("No offer matches %r; available: %s" % (want, ", ".join(_s(o.getTitle()) for o in offers)))
            offer = m[0]
        class Cfg(LaunchConfigurator):
            def configureLauncher(self, off, arguments, relPrompt):
                m2 = HashMap(arguments)
                params = off.getParameters()
                for k in params.keySet():
                    lk = _s(k).lower()
                    p = params.get(k)
                    if ARGS.get("executable_path") and ("image" in lk):
                        m2.put(k, p.decode(ARGS["executable_path"]))
                    elif ARGS.get("args") and ("args" in lk):
                        m2.put(k, p.decode(ARGS["args"]))
                    elif ARGS.get("windbg_dir") and "windbg" in lk:
                        m2.put(k, p.decode(ARGS["windbg_dir"]))
                    elif ARGS.get("cwd") and "cwd" in lk:
                        m2.put(k, p.decode(ARGS["cwd"]))
                    elif ARGS.get("python_executable") and "python" in lk:
                        m2.put(k, p.decode(ARGS["python_executable"]))
                return m2
        import time
        try:
            traces().closeDeadTraces()
        except (Exception, Throwable):
            pass
        res = offer.launchProgram(TaskMonitor.DUMMY, Cfg())
        exc = res.exception()
        if exc is not None:
            raise Fail("Launch failed: " + _s(exc))
        tr = res.trace()
        if tr is not None:
            traces().activateTrace(tr)
        # Ready = thread present, program image statically mapped, and the
        # module list stable for ~1s (the agent populates the trace async).
        from ghidra.program.util import ProgramLocation
        ms = svc("ghidra.app.services.DebuggerStaticMappingService")
        ready = False
        last_mods, stable = -1, 0
        deadline = time.time() + float(ARGS.get("timeout_seconds") or 30)
        while time.time() < deadline:
            c = traces().getCurrent()
            if c is not None and c.getThread() is not None and c.getTarget() is not None:
                try:
                    mods = len(list(c.getTrace().getModuleManager().getLoadedModules(c.getSnap())))
                    mapped = ms.getOpenMappedLocation(c.getTrace(), ProgramLocation(
                        currentProgram, currentProgram.getImageBase()), c.getSnap()) is not None
                    stable = stable + 1 if (mods == last_mods and mods > 0) else 0
                    last_mods = mods
                    if mapped and stable >= 4:
                        ready = True
                        break
                except (Exception, Throwable):
                    pass
            time.sleep(0.25)
        return {"success": True, "offer": _s(offer.getTitle()), "trace": _s(tr.getName()) if tr else None,
                "ready": ready}
    ''', {"executable_path": _p("Executable (default: current program's image)"), "args": _p("Command-line arguments"),
          "cwd": _p("Working directory"), "offer": _p("Offer title/config substring (debugger_launch_offers)"),
          "python_executable": _p("Python for the Trace RMI agent"),
          "windbg_dir": _p("dbgeng.dll directory (Windows dbgeng offers)"), "timeout_seconds": _p("Timeout", I)}),
    _gui_tool("debugger_interrupt", "Interrupt (break into) the running target and wait (up to 10s) until it reports STOPPED.", '''
        import time
        before = latest_snap()
        act = run_action("INTERRUPT")
        return {"success": True, "action": act, "process_state": wait_state("STOPPED", 10, before)}
    '''),
    _gui_tool("debugger_resume", "Resume execution of the target; with wait_seconds, block until it stops again (e.g. at a breakpoint).", '''
        before = latest_snap()
        act = run_action("RESUME")
        res = {"success": True, "action": act}
        if ARGS.get("wait_seconds"):
            state = wait_state("STOPPED", float(ARGS["wait_seconds"]), before)
            res["process_state"] = state
            res["stopped"] = state == "STOPPED"
        return res
    ''', {"wait_seconds": _p("Wait up to N seconds for the target to stop", I)}),
    _gui_tool("debugger_step", "Single-step the target: into (follows calls), over, or out (run to return).", '''
        kind = (ARGS.get("kind") or "into").lower()
        name = {"into": "STEP_INTO", "over": "STEP_OVER", "out": "STEP_OUT", "skip": "STEP_SKIP"}.get(kind)
        if name is None:
            raise Fail("kind must be into, over, out or skip")
        import time
        before = coords().getSnap()
        act = run_action(name)
        for _ in range(100):
            if traces().getCurrent().getSnap() > before:
                break
            time.sleep(0.1)
        c = coords()
        pc = None
        try:
            from ghidra.program.model.lang import Register
            reg = c.getPlatform().getLanguage().getProgramCounter()
            rs = c.getTrace().getMemoryManager().getMemoryRegisterSpace(c.getThread(), c.getFrame(), False)
            pc = "0x%x" % long(rs.getValue(c.getSnap(), reg).getUnsignedValue()) if rs else None
        except (Exception, Throwable):
            pass
        return {"success": True, "action": act, "pc": pc}
    ''', {"kind": _p("into (default), over, out, skip", enum=["into", "over", "out", "skip"])}),
    _gui_tool("debugger_registers", "Read CPU registers of the current thread/frame (refreshed from the live target).", '''
        c = coords()
        tr, th = c.getTrace(), c.getThread()
        if th is None:
            raise Fail("No current thread")
        lang = c.getPlatform().getLanguage()
        regs = [r for r in lang.getRegisters() if r.isBaseRegister() and not r.isProcessorContext() and r.getBitLength() <= 128]
        want = [x.strip().lower() for x in (ARGS.get("registers") or "").split(",") if x.strip()]
        if want:
            regs = [r for r in regs if r.getName().lower() in want]
        t = c.getTarget()
        if t is not None and t.isValid():
            from java.util import HashSet
            hs = HashSet(regs)
            try:
                wait(t.readRegistersAsync(c.getPlatform(), th, c.getFrame(), hs))
            except (Exception, Throwable):
                pass
        rs = tr.getMemoryManager().getMemoryRegisterSpace(th, c.getFrame(), False)
        out = {}
        for r in regs:
            try:
                v = rs.getValue(c.getSnap(), r) if rs else None
                if v is not None and v.hasValue():
                    out[_s(r.getName())] = "0x%x" % long(v.getUnsignedValue())
            except (Exception, Throwable):
                pass
        return {"thread": _s(th.getName(c.getSnap())), "frame": c.getFrame(), "registers": out}
    ''', {"registers": _p("Comma-separated subset (default: all general registers)")}),
    _gui_tool("debugger_read_memory", "Read memory from the debugged process (hex dump plus little-endian DWORDs).", '''
        from ghidra.program.model.address import AddressSet
        from ghidra.util.task import TaskMonitor
        from java.nio import ByteBuffer
        c = coords()
        a = dyn_addr(ARGS["address"])
        n = int(ARGS.get("size") or 64)
        t = c.getTarget()
        if t is not None and t.isValid():
            t.readMemory(AddressSet(a, a.add(n - 1)), TaskMonitor.DUMMY)
        buf = ByteBuffer.allocate(n)
        c.getTrace().getMemoryManager().getBytes(c.getSnap(), a, buf)
        data = [b & 0xff for b in buf.array()]
        dwords = []
        for i in range(0, n - 3, 4):
            dwords.append("0x%08x" % (data[i] | data[i+1] << 8 | data[i+2] << 16 | data[i+3] << 24))
        return {"address": _s(a), "size": n, "hex": " ".join("%02x" % b for b in data), "dwords": dwords}
    ''', {"address": _p("Dynamic address"), "size": _p("Bytes (default 64)", I)}, ["address"]),
    _gui_tool("debugger_stack_trace", "Call stack of the current thread.", '''
        c = coords()
        if c.getThread() is None:
            raise Fail("No current thread")
        # The agent records the stack asynchronously after a stop: wait until
        # frame 0 agrees with the live program counter.
        pc_now = None
        try:
            preg = c.getPlatform().getLanguage().getProgramCounter()
            rs = c.getTrace().getMemoryManager().getMemoryRegisterSpace(c.getThread(), c.getFrame(), False)
            v = rs.getValue(c.getSnap(), preg) if rs else None
            pc_now = long(v.getUnsignedValue()) if (v is not None and v.hasValue()) else None
        except (Exception, Throwable):
            pass
        st = None
        for _ in range(15):
            c = coords()
            st = c.getTrace().getStackManager().getLatestStack(c.getThread(), c.getSnap())
            fr = st.getFrames(c.getSnap()) if st is not None else []
            if pc_now is None or (fr and fr[0].getProgramCounter(c.getSnap()) is not None
                                  and fr[0].getProgramCounter(c.getSnap()).getOffset() == pc_now):
                break
            time.sleep(0.2)
        if st is None:
            return {"frames": []}
        frames = []
        for f in st.getFrames(c.getSnap())[:int(ARGS.get("depth") or 32)]:
            pc = f.getProgramCounter(c.getSnap())
            fn = None
            try:
                ms = svc("ghidra.app.services.DebuggerStaticMappingService")
                from ghidra.trace.model import DefaultTraceLocation, Lifespan
                loc = ms.getOpenMappedLocation(DefaultTraceLocation(c.getTrace(), None, Lifespan.at(c.getSnap()), pc))
                if loc is not None:
                    func = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress())
                    fn = _s(func.getName()) if func else None
            except (Exception, Throwable):
                pass
            frames.append({"level": f.getLevel(), "pc": _s(pc), "function": fn})
        return {"thread": _s(c.getThread().getName(c.getSnap())), "frames": frames}
    ''', {"depth": _p("Max frames (default 32)", I)}),
    _gui_tool("debugger_modules", "Modules (EXEs/DLLs/shared objects) loaded in the debugged process.", '''
        c = coords()
        out = []
        for m in c.getTrace().getModuleManager().getLoadedModules(c.getSnap()):
            try:
                out.append({"name": _s(m.getName(c.getSnap())), "base": _s(m.getBase(c.getSnap())),
                            "max": _s(m.getMaxAddress(c.getSnap()))})
            except (Exception, Throwable):
                out.append({"name": _s(m.getName()), "base": _s(m.getBase()), "max": _s(m.getMaxAddress())})
        return {"count": len(out), "modules": out}
    '''),
    _gui_tool("debugger_list_breakpoints", "List all logical breakpoints (static and dynamic) with state.", '''
        out = []
        bsvc = svc("ghidra.app.services.DebuggerLogicalBreakpointService")
        wait(bsvc.changesSettled(), 10)
        for lb in bsvc.getAllBreakpoints():
            loc = lb.getProgramLocation()
            out.append({"name": _s(lb.getName()), "static": _s(loc.getAddress()) if loc else None,
                        "length": lb.getLength(), "kinds": sorted(_s(k) for k in lb.getKinds()),
                        "state": _s(lb.computeState())})
        return {"count": len(out), "breakpoints": out}
    '''),
    _gui_tool("debugger_set_breakpoint", "Set a software execution breakpoint at an address (dynamic address in the trace, or static program address when static=true).", '''
        from ghidra.trace.model.breakpoint import TraceBreakpointKind
        from java.util import HashSet
        bs = svc("ghidra.app.services.DebuggerLogicalBreakpointService")
        kinds = HashSet([TraceBreakpointKind.SW_EXECUTE])
        if ARGS.get("static"):
            a = currentProgram.getAddressFactory().getAddress(ARGS["address"])
            wait(bs.placeBreakpointAt(currentProgram, a, 1, kinds, ARGS.get("name") or ""))
        else:
            c = coords()
            a = dyn_addr(ARGS["address"])
            wait(bs.placeBreakpointAt(c.getTrace(), a, 1, kinds, ARGS.get("name") or ""))
        wait(bs.changesSettled(), 10)
        return {"success": True, "address": _s(a)}
    ''', {"address": _p("Address"), "static": _p("Address is a static program address", B), "name": _p("Name")}, ["address"]),
    _gui_tool("debugger_remove_breakpoint", "Remove breakpoints at an address (dynamic, or static=true).", '''
        bs = svc("ghidra.app.services.DebuggerLogicalBreakpointService")
        if ARGS.get("static"):
            a = currentProgram.getAddressFactory().getAddress(ARGS["address"])
            lbs = bs.getBreakpointsAt(currentProgram, a)
            tr = None
        else:
            c = coords()
            a = dyn_addr(ARGS["address"])
            lbs = bs.getBreakpointsAt(c.getTrace(), a)
            tr = c.getTrace()
        if not lbs:
            raise Fail("No breakpoint at " + _s(a))
        wait(bs.deleteAll(lbs, tr))
        wait(bs.changesSettled(), 10)
        return {"success": True, "removed": len(lbs), "address": _s(a)}
    ''', {"address": _p("Address"), "static": _p("Address is a static program address", B)}, ["address"]),
    _gui_tool("debugger_static_to_dynamic", "Translate a static program address to the runtime address in the current trace.", '''
        from ghidra.program.util import ProgramLocation
        c = coords()
        ms = svc("ghidra.app.services.DebuggerStaticMappingService")
        a = currentProgram.getAddressFactory().getAddress(ARGS["address"])
        loc = ms.getOpenMappedLocation(c.getTrace(), ProgramLocation(currentProgram, a), c.getSnap())
        if loc is None:
            raise Fail("No static mapping for " + _s(a) + " (module not mapped yet?)")
        return {"static": _s(a), "dynamic": _s(loc.getAddress())}
    ''', {"address": _p("Static address")}, ["address"]),
    _gui_tool("debugger_dynamic_to_static", "Translate a runtime address in the current trace back to a static program address.", '''
        from ghidra.trace.model import DefaultTraceLocation, Lifespan
        c = coords()
        ms = svc("ghidra.app.services.DebuggerStaticMappingService")
        a = dyn_addr(ARGS["address"])
        loc = ms.getOpenMappedLocation(DefaultTraceLocation(c.getTrace(), None, Lifespan.at(c.getSnap()), a))
        if loc is None:
            raise Fail("No static mapping for " + _s(a))
        return {"dynamic": _s(a), "static": _s(loc.getAddress()), "program": _s(loc.getProgram().getName())}
    ''', {"address": _p("Dynamic address")}, ["address"]),
    _gui_tool("get_ui_cursor", "What the analyst is looking at: cursor address, function under it, selection and focused program (type=address|function|selection|program|all).", '''
        typ = (ARGS.get("type") or "all").lower()
        res = {}
        if typ in ("address", "all"):
            res["address"] = _s(currentAddress)
        if typ in ("function", "all"):
            f = getFunctionContaining(currentAddress) if currentAddress else None
            res["function"] = {"name": _s(f.getName()), "entry": _s(f.getEntryPoint())} if f else None
        if typ in ("selection", "all"):
            sel = currentSelection
            res["selection"] = [{"start": _s(r.getMinAddress()), "end": _s(r.getMaxAddress())} for r in sel] if sel else []
        if typ in ("program", "all"):
            res["program"] = _s(currentProgram.getName()) if currentProgram else None
        return res
    ''', {"type": _p("address, function, selection, program or all (default)")}),
    _gui_tool("goto_address", "Navigate the CodeBrowser listing and decompiler to an address or symbol.", '''
        a = currentProgram.getAddressFactory().getAddress(ARGS["address"])
        if a is None:
            syms = list(currentProgram.getSymbolTable().getSymbols(ARGS["address"]))
            a = syms[0].getAddress() if syms else None
        if a is None:
            raise Fail("Invalid address or symbol: " + ARGS["address"])
        ok = goTo(a)
        return {"success": bool(ok), "address": _s(a)}
    ''', {"address": _p("Address or symbol")}, ["address"]),
    _gui_tool("running_tools", "List running Ghidra tool windows and the programs open in each.", '''
        out = []
        proj = state.getProject()
        tm = proj.getToolManager() if proj is not None else None
        if tm is None:
            raise Fail("No tool manager: the bridge is running in a headless Ghidra session, not the GUI")
        for t in tm.getRunningTools():
            progs = []
            try:
                import java.lang
                pm = t.getService(java.lang.Class.forName("ghidra.app.services.ProgramManager"))
                progs = [_s(p.getName()) for p in pm.getAllOpenPrograms()] if pm else []
            except (Exception, Throwable):
                pass
            out.append({"name": _s(t.getName()), "instance": _s(t.getInstanceName()), "programs": progs})
        return {"tools": out}
    '''),
    JTool(name="prompt_policy", mode="local", local=_prompt_policy,
          description="Enable, disable or query whether GUI debugger actions may open interactive Ghidra prompts (default: non-interactive).",
          properties={"action": _p("enable, disable or query (default)", enum=["enable", "disable", "query"]),
                      "reason": _p("Why (recorded)"), "seconds": _p("Unused; accepted for compatibility", I)}),
)
