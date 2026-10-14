"""Phase 14 — P-code emulation (EmulatorHelper)."""

from __future__ import annotations

from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}
O = {"type": "object"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


_EMU = '''
from ghidra.app.emulator import EmulatorHelper
from java.math import BigInteger

SENTINEL = 0x0dead0000
STACK_TOP = 0x0fff0000
SCRATCH = 0x0e0000000

def _int(v):
    if isinstance(v, (int, long)):
        return long(v)
    return long(_s(v), 0)

def reg(p, name):
    r = p.getRegister(name) or p.getRegister(name.upper()) or p.getRegister(name.lower())
    if r is None:
        raise Fail("Unknown register: " + name)
    return r

from ghidra.pcode.memstate import MemoryFaultHandler

class _Lenient(MemoryFaultHandler):
    """Treat reads of never-written memory (fresh stack slots) as zeros."""
    def uninitializedRead(self, address, size, buf, bufOffset):
        return True
    def unknownAddress(self, address, write):
        return False

def new_emu(p, f):
    emu = EmulatorHelper(p)
    emu.setMemoryFaultHandler(_Lenient())
    lang = p.getLanguage()
    ps = p.getDefaultPointerSize()
    sp = p.getCompilerSpec().getStackPointer()
    emu.writeRegister(sp, BigInteger.valueOf(STACK_TOP))
    # Return to a sentinel: link register on RISC targets, pushed return address otherwise
    lr = None
    for n in ("lr", "x30", "ra", "LR", "RA"):
        if p.getRegister(n) is not None:
            lr = p.getRegister(n); break
    if lr is not None:
        emu.writeRegister(lr, BigInteger.valueOf(SENTINEL))
    else:
        sp_val = STACK_TOP - ps
        emu.writeRegister(sp, BigInteger.valueOf(sp_val))
        emu.writeMemoryValue(p.getAddressFactory().getDefaultAddressSpace().getAddress(sp_val), ps, SENTINEL)
    emu.writeRegister(emu.getPCRegister(), BigInteger(_s(f.getEntryPoint().getOffset())))
    emu.setBreakpoint(p.getAddressFactory().getDefaultAddressSpace().getAddress(SENTINEL))
    return emu

def run(emu, p, max_steps):
    steps = 0
    sentinel = p.getAddressFactory().getDefaultAddressSpace().getAddress(SENTINEL)
    while steps < max_steps:
        pc = emu.getExecutionAddress()
        if pc.equals(sentinel):
            return {"status": "returned", "steps": steps}
        if not emu.step(MONITOR):
            return {"status": "fault", "steps": steps, "pc": _s(pc), "error": _s(emu.getLastError())}
        steps += 1
    return {"status": "max_steps", "steps": steps, "pc": _s(emu.getExecutionAddress())}

def write_bytes(emu, p, a, data):
    from jarray import array
    jb = array([((ord(c) + 128) % 256) - 128 for c in data], "b")
    emu.writeMemory(a if not isinstance(a, (int, long)) else p.getAddressFactory().getDefaultAddressSpace().getAddress(a), jb)

def ret_reg(p, f, override=None):
    if override:
        return reg(p, override)
    r = f.getReturn().getRegister() if f.getReturn() is not None else None
    if r is not None:
        return r
    for n in ("RAX", "EAX", "x0", "r0", "a0", "v0"):
        if p.getRegister(n) is not None:
            return p.getRegister(n)
    raise Fail("Cannot determine return register; pass result_register")

def first_arg_reg(p, f, override=None):
    if override:
        return reg(p, override)
    params = f.getParameters()
    if params and params[0].getRegister() is not None:
        return params[0].getRegister()
    try:
        model = f.getCallingConvention() or p.getCompilerSpec().getDefaultCallingConvention()
        st = model.getPotentialInputRegisterStorage(p)
        if st and st[0].getRegister() is not None:
            return st[0].getRegister()
    except (Exception, Throwable):
        pass
    return None
'''

register(
    JTool(
        name="emulate_function",
        description="Emulate a single function with controlled register/memory inputs (Ghidra P-code emulator) and return final register state. Ideal for hash, crypto, decoding or pure-computation routines. Calls to unmapped/external code stop with status=fault.",
        properties={"function": _p("Function name or address"),
                    "registers": {"type": "object", "description": '{"RCX": "0x1000", "EDX": 5}'},
                    "memory": {"type": "array", "items": O,
                               "description": '[{"address": "0xe0000000", "bytes_hex": "41424300"} | {"address", "string": "abc", "wide": false}]'},
                    "max_steps": _p("Instruction limit (default 100000)", I),
                    "return_registers": _p("Comma-separated registers to report (default: return register)"),
                    "read_memory_after": {"type": "array", "items": O, "description": '[{"address": "...", "length": 16}]'}},
        required=["function"],
        timeout=600,
        helpers=_EMU,
        body='''
        import binascii
        p = prog()
        f = find_func()
        emu = new_emu(p, f)
        try:
            for name, v in (arg_json("registers", {}) or {}).items():
                emu.writeRegister(reg(p, name), BigInteger(_s(_int(v))))
            for m in arg_json("memory", []) or []:
                a = addr(m["address"])
                if m.get("bytes_hex"):
                    data = binascii.unhexlify(m["bytes_hex"].replace(" ", ""))
                else:
                    s = m.get("string", "")
                    data = (s.encode("utf-16-le") + "\\x00\\x00") if m.get("wide") else (s.encode("utf-8") + "\\x00")
                write_bytes(emu, p, a, data)
            r = run(emu, p, int(arg("max_steps", 100000)))
            names = arg_list("return_registers") or [ret_reg(p, f).getName()]
            regs = {}
            for n in names:
                v = long(emu.readRegister(reg(p, n)))
                regs[_s(n)] = {"hex": "0x%x" % v, "dec": _s(v)}
            r["registers"] = regs
            mem = []
            for m in arg_json("read_memory_after", []) or []:
                a = addr(m["address"])
                b = emu.readMemory(a, int(m.get("length", 16)))
                mem.append({"address": _s(a), "bytes_hex": " ".join("%02x" % (x & 0xff) for x in b)})
            if mem: r["memory"] = mem
            r["function"] = _s(f.getName())
            return r
        finally:
            emu.dispose()
        ''',
    ),
    JTool(
        name="emulate_hash_batch",
        description="Brute-force API hash resolution: emulate a hash function once per candidate string and return the candidate(s) whose result equals target_hash (ROR13, CRC32, djb2, FNV, custom). The string pointer goes in string_register (default: first argument register).",
        properties={"hash_function_address": _p("Hash function name or address"),
                    "target_hash": _p("Hash to match (hex or decimal); omit to just list results"),
                    "candidates": _p("Comma-separated or JSON list of candidate strings (e.g. API names)"),
                    "string_register": _p("Register receiving the string pointer"),
                    "result_register": _p("Register holding the hash (default: return register)"),
                    "initial_registers": {"type": "object", "description": "Extra register values"},
                    "wide_string": _p("Pass UTF-16LE strings (default false)", B),
                    "result_bits": _p("Compare low N bits (default 32)", I),
                    "max_steps": _p("Per-candidate instruction limit (default 20000)", I)},
        required=["hash_function_address", "candidates"],
        timeout=900,
        helpers=_EMU,
        body='''
        p = prog()
        f = find_func(arg("hash_function_address"))
        sreg = first_arg_reg(p, f, arg("string_register"))
        rreg = ret_reg(p, f, arg("result_register"))
        bits = int(arg("result_bits", 32))
        mask = (1 << bits) - 1
        target = (_int(arg("target_hash")) & mask) if arg("target_hash") is not None else None
        cands = arg_list("candidates")
        results, matches = [], []
        for c in cands:
            emu = new_emu(p, f)
            try:
                for name, v in (arg_json("initial_registers", {}) or {}).items():
                    emu.writeRegister(reg(p, name), BigInteger(_s(_int(v))))
                data = (c.encode("utf-16-le") + "\\x00\\x00") if arg_bool("wide_string") else (c.encode("utf-8") + "\\x00")
                write_bytes(emu, p, SCRATCH, data)
                if sreg is not None:
                    emu.writeRegister(sreg, BigInteger.valueOf(SCRATCH))
                else:
                    # stack-passed argument (cdecl/stdcall): above the return address
                    ps = p.getDefaultPointerSize()
                    spv = long(emu.readRegister(p.getCompilerSpec().getStackPointer()))
                    emu.writeMemoryValue(p.getAddressFactory().getDefaultAddressSpace().getAddress(spv + ps), ps, SCRATCH)
                r = run(emu, p, int(arg("max_steps", 20000)))
                val = long(emu.readRegister(rreg)) & mask
                rec = {"candidate": c, "hash": "0x%x" % val, "status": r["status"]}
                results.append(rec)
                if target is not None and val == target and r["status"] == "returned":
                    matches.append(c)
            finally:
                emu.dispose()
        res = {"function": _s(f.getName()), "string_register": _s(sreg.getName()) if sreg else "stack",
               "result_register": _s(rreg.getName()), "candidates_tested": len(cands),
               "target_hash": ("0x%x" % target) if target is not None else None, "matches": matches}
        if target is None or len(cands) <= 50:
            res["results"] = results
        return res
        ''',
    ),
)
