"""Phase 9 — Program, memory, options, property maps and utility tools."""

from __future__ import annotations

import json
import platform
import sys

from ..config import config
from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


register(
    JTool(
        name="get_address_spaces",
        description="List all physical and overlay address spaces in the program (overlays include is_overlay and overlayed_space).",
        body='''
        out = []
        for sp in prog().getAddressFactory().getAllAddressSpaces():
            d = {"name": _s(sp.getName()), "type": _s(sp.getType()),
                 "size_bits": sp.getSize(), "unique_id": sp.getSpaceID(),
                 "is_memory": sp.isMemorySpace(), "is_overlay": sp.isOverlaySpace(),
                 "min": _s(sp.getMinAddress()), "max": _s(sp.getMaxAddress())}
            if sp.isOverlaySpace():
                d["overlayed_space"] = _s(sp.getOverlayedSpace().getName())
            out.append(d)
        return {"default_space": _s(prog().getAddressFactory().getDefaultAddressSpace().getName()),
                "spaces": out}
        ''',
    ),
    JTool(
        name="get_language_metadata",
        description="Dump the program's SLEIGH language description: processor, endianness, pointer size, address spaces, optionally registers and default symbols. Useful for emulators and ML pipelines.",
        properties={
            "include_registers": _p("Include the register list (default false)", B),
            "include_default_symbols": _p("Include language default symbols (default false)", B),
        },
        body='''
        p = prog()
        lang = p.getLanguage()
        cs = p.getCompilerSpec()
        res = {
            "language_id": _s(lang.getLanguageID()),
            "processor": _s(lang.getProcessor()),
            "variant": _s(lang.getLanguageDescription().getVariant()),
            "version": "%d.%d" % (lang.getVersion(), lang.getMinorVersion()),
            "big_endian": lang.isBigEndian(),
            "pointer_size": p.getDefaultPointerSize(),
            "instruction_alignment": lang.getInstructionAlignment(),
            "compiler_spec": _s(cs.getCompilerSpecID()),
            "default_calling_convention": _s(cs.getDefaultCallingConvention().getName()),
            "program_counter": _s(lang.getProgramCounter().getName()),
            "stack_pointer": _s(cs.getStackPointer().getName()),
            "address_spaces": [_s(sp.getName()) for sp in lang.getAddressFactory().getAllAddressSpaces()],
        }
        if arg_bool("include_registers"):
            regs = []
            for r in lang.getRegisters():
                regs.append({"name": _s(r.getName()), "bits": r.getBitLength(),
                             "address": _s(r.getAddress()), "base": _s(r.getBaseRegister().getName()),
                             "is_pc": r.isProgramCounter(), "is_flag": r.isProcessorContext()})
            res["registers"] = regs
        if arg_bool("include_default_symbols"):
            res["default_symbols"] = [{"name": _s(s.getName()), "address": _s(s.getAddress()),
                                       "type": _s(s.getType())} for s in lang.getDefaultSymbols()]
        return res
        ''',
    ),
    JTool(
        name="get_program_options",
        description="Read all options in a program option group (types, current values, defaults, descriptions). Omit group to list the option groups (e.g. 'Program Information', 'Analyzers', 'Decompiler').",
        properties={"group": _p("Option group name")},
        body='''
        p = prog()
        group = arg("group")
        if not group:
            groups = []
            for g in p.getOptionsNames():
                groups.append({"group": _s(g), "option_count": len(p.getOptions(g).getOptionNames())})
            return {"groups": groups}
        opts = p.getOptions(group)
        out = []
        for n in opts.getOptionNames():
            item = {"name": _s(n)}
            try:
                item["type"] = _s(opts.getType(n))
                item["value"] = _s(opts.getValueAsString(n))
                item["default"] = _s(opts.getDefaultValueAsString(n))
                item["description"] = _s(opts.getDescription(n))
                item["is_default"] = opts.isDefaultValue(n)
            except (Exception, Throwable) as e:
                item["error"] = _s(e)
            out.append(item)
        return {"group": group, "options": out, "count": len(out)}
        ''',
    ),
    JTool(
        name="set_program_option",
        description="Set a typed program option. Existing options keep their type; new options need type (string|int|long|double|float|boolean).",
        properties={"group": _p("Option group"), "name": _p("Option name"),
                    "value": _p("New value (string form)"),
                    "type": _p("Value type for new options", enum=["string", "int", "long", "double", "float", "boolean"])},
        required=["group", "name", "value"],
        mode="write",
        body='''
        p = prog()
        opts = p.getOptions(arg("group"))
        name = arg("name")
        val = _s(ARGS.get("value"))
        typ = arg("type")
        if typ is None and opts.contains(name):
            typ = _s(opts.getType(name)).lower().replace("_type", "")
        typ = (typ or "string").lower()
        with tx("Set option " + name):
            if typ in ("int", "integer"):
                opts.setInt(name, int(val, 0))
            elif typ == "long":
                opts.setLong(name, long(val, 0))
            elif typ == "double":
                opts.setDouble(name, float(val))
            elif typ == "float":
                opts.setFloat(name, float(val))
            elif typ == "boolean":
                opts.setBoolean(name, val.lower() in ("1", "true", "yes", "on"))
            elif typ == "string":
                opts.setString(name, val)
            else:
                raise Fail("Unsupported option type: " + typ)
        return {"success": True, "group": arg("group"), "name": name, "type": typ,
                "value": _s(opts.getValueAsString(name))}
        ''',
    ),
    JTool(
        name="remove_program_option",
        description="Remove an option from a program option group (mainly for custom options; built-ins may be re-created with defaults).",
        properties={"group": _p("Option group"), "name": _p("Option name")},
        required=["group", "name"],
        mode="write",
        body='''
        opts = prog().getOptions(arg("group"))
        name = arg("name")
        if not opts.contains(name):
            raise Fail("Option not found: " + name)
        with tx("Remove option " + name):
            opts.removeOption(name)
        return {"success": True, "removed": name}
        ''',
    ),
    # ----- property maps -----------------------------------------------------
    JTool(
        name="create_property_map",
        description="Create a user property map storing typed values keyed by address. Types: int, long, string, void (address-presence tag). Store JSON in a string map for structured data.",
        properties={"name": _p("Map name"),
                    "type": _p("Map value type", enum=["int", "long", "string", "void"])},
        required=["name", "type"],
        mode="write",
        body='''
        pm = prog().getUsrPropertyManager()
        name, typ = arg("name"), arg("type").lower()
        if pm.getPropertyMap(name) is not None:
            raise Fail("Property map already exists: " + name)
        with tx("Create property map " + name):
            if typ == "int": pm.createIntPropertyMap(name)
            elif typ == "long": pm.createLongPropertyMap(name)
            elif typ == "string": pm.createStringPropertyMap(name)
            elif typ == "void": pm.createVoidPropertyMap(name)
            else: raise Fail("Unsupported type: " + typ)
        return {"success": True, "name": name, "type": typ}
        ''',
    ),
    JTool(
        name="delete_property_map",
        description="Delete a user property map and every value in it.",
        properties={"name": _p("Map name")},
        required=["name"],
        mode="write",
        body='''
        pm = prog().getUsrPropertyManager()
        with tx("Delete property map"):
            ok = pm.removePropertyMap(arg("name"))
        if not ok:
            raise Fail("Property map not found: " + arg("name"))
        return {"success": True, "deleted": arg("name")}
        ''',
    ),
    JTool(
        name="set_property",
        description="Set a value at an address in a property map (coerced to the map's type; void maps just tag the address).",
        properties={"map": _p("Map name"), "address": _p("Address"), "value": _p("Value (ignored for void maps)")},
        required=["map", "address"],
        mode="write",
        body='''
        from ghidra.program.model.util import IntPropertyMap, LongPropertyMap, StringPropertyMap, VoidPropertyMap
        m = prog().getUsrPropertyManager().getPropertyMap(arg("map"))
        if m is None:
            raise Fail("Property map not found: " + arg("map"))
        a = addr(arg("address"))
        v = ARGS.get("value")
        with tx("Set property"):
            if isinstance(m, IntPropertyMap): m.add(a, int(_s(v), 0))
            elif isinstance(m, LongPropertyMap): m.add(a, long(_s(v), 0))
            elif isinstance(m, StringPropertyMap):
                m.add(a, v if isinstance(v, basestring) else json.dumps(v))
            elif isinstance(m, VoidPropertyMap): m.add(a)
            else: raise Fail("Unsupported map type")
        return {"success": True, "map": arg("map"), "address": _s(a)}
        ''',
    ),
    JTool(
        name="get_property",
        description="Read the value stored at an address in a property map (has_value=false when absent).",
        properties={"map": _p("Map name"), "address": _p("Address")},
        required=["map", "address"],
        body='''
        m = prog().getUsrPropertyManager().getPropertyMap(arg("map"))
        if m is None:
            raise Fail("Property map not found: " + arg("map"))
        a = addr(arg("address"))
        has = m.hasProperty(a)
        val = None
        if has:
            try:
                val = m.get(a)
            except (Exception, Throwable):
                val = True
        if val is not None and not isinstance(val, (int, long, float, bool)):
            val = _s(val)
        return {"map": arg("map"), "address": _s(a), "has_value": has, "value": val}
        ''',
    ),
    JTool(
        name="remove_property",
        description="Remove the value stored at one address in a property map.",
        properties={"map": _p("Map name"), "address": _p("Address")},
        required=["map", "address"],
        mode="write",
        body='''
        m = prog().getUsrPropertyManager().getPropertyMap(arg("map"))
        if m is None:
            raise Fail("Property map not found: " + arg("map"))
        a = addr(arg("address"))
        with tx("Remove property"):
            removed = m.remove(a)
        return {"success": True, "removed": bool(removed), "address": _s(a)}
        ''',
    ),
    JTool(
        name="list_properties",
        description="List (address, value) entries in a property map with pagination, optionally within start/end. Omit map to list the maps with their value types and entry counts.",
        properties={"map": _p("Map name"), "start": _p("Range start address"), "end": _p("Range end address"),
                    "offset": _p("Pagination offset", I), "limit": _p("Max entries (default 100)", I)},
        body='''
        pm = prog().getUsrPropertyManager()
        if not arg("map"):
            maps = []
            it = pm.propertyManagers()
            while it.hasNext():
                n = it.next()
                m = pm.getPropertyMap(n)
                maps.append({"name": _s(n), "type": _s(m.getClass().getSimpleName()).replace("PropertyMapDB", "").lower(),
                             "count": m.getSize()})
            return {"maps": maps}
        m = pm.getPropertyMap(arg("map"))
        if m is None:
            raise Fail("Property map not found: " + arg("map"))
        if arg("start") or arg("end"):
            s = addr(arg("start")) if arg("start") else prog().getMinAddress()
            e = addr(arg("end")) if arg("end") else prog().getMaxAddress()
            it = m.getPropertyIterator(s, e)
        else:
            it = m.getPropertyIterator()
        items = []
        while it.hasNext():
            a = it.next()
            try:
                v = m.get(a)
            except (Exception, Throwable):
                v = True
            if v is not None and not isinstance(v, (int, long, float, bool)):
                v = _s(v)
            items.append({"address": _s(a), "value": v})
        r = page(items, arg("offset"), arg("limit"))
        r["map"] = arg("map")
        return r
        ''',
    ),
    # ----- memory ------------------------------------------------------------
    JTool(
        name="create_memory_block",
        description="Create a memory block, optionally initialized from bytes (hex or base64) or a fill byte; supports overlays and permissions.",
        properties={
            "name": _p("Block name"), "address": _p("Start address"), "size": _p("Size in bytes (inferred from bytes if given)", I),
            "read": _p("Readable (default true)", B), "write": _p("Writable (default false)", B),
            "execute": _p("Executable (default false)", B), "volatile": _p("Volatile (default false)", B),
            "comment": _p("Block comment"), "bytes_hex": _p("Initial contents as hex"),
            "bytes_base64": _p("Initial contents as base64"),
            "initialized": _p("Create initialized block (default true)", B),
            "fill_byte": _p("Fill byte for initialized blocks (default 0)", I),
            "overlay": _p("Create as overlay (default false)", B),
        },
        required=["name", "address"],
        mode="write",
        body='''
        from java.io import ByteArrayInputStream
        import binascii
        mem = prog().getMemory()
        start = addr(arg("address"))
        data = None
        if arg("bytes_hex"):
            data = binascii.unhexlify(_s(arg("bytes_hex")).replace(" ", "").replace("0x", ""))
        elif arg("bytes_base64"):
            data = base64.b64decode(arg("bytes_base64"))
        size = arg("size") or (len(data) if data is not None else None)
        if not size:
            raise Fail("size is required when no bytes are given")
        size = int(size)
        overlay = arg_bool("overlay")
        with tx("Create memory block"):
            if data is not None:
                from jarray import array
                jb = array([((ord(c) + 128) % 256) - 128 for c in data], "b")
                blk = mem.createInitializedBlock(arg("name"), start, ByteArrayInputStream(jb), size, MONITOR, overlay)
            elif arg_bool("initialized", True):
                fb = int(arg("fill_byte", 0))
                if fb > 127: fb -= 256
                blk = mem.createInitializedBlock(arg("name"), start, size, fb, MONITOR, overlay)
            else:
                blk = mem.createUninitializedBlock(arg("name"), start, size, overlay)
            blk.setRead(arg_bool("read", True))
            blk.setWrite(arg_bool("write", False))
            blk.setExecute(arg_bool("execute", False))
            blk.setVolatile(arg_bool("volatile", False))
            if arg("comment"):
                blk.setComment(arg("comment"))
        return {"success": True, "name": _s(blk.getName()), "start": _s(blk.getStart()),
                "end": _s(blk.getEnd()), "size": blk.getSize(), "initialized": blk.isInitialized(),
                "overlay": blk.isOverlay()}
        ''',
    ),
    JTool(
        name="set_memory_block",
        description="Change an existing memory block's permissions or volatility (e.g. clear write on flash so the decompiler folds literal-pool constants). Identify by block name or an address inside it.",
        properties={"block": _p("Block name"), "address": _p("Address inside the block"),
                    "read": _p("Readable", B), "write": _p("Writable", B),
                    "execute": _p("Executable", B), "volatile": _p("Volatile", B),
                    "new_name": _p("Rename the block"), "comment": _p("Block comment")},
        mode="write",
        body='''
        mem = prog().getMemory()
        blk = mem.getBlock(arg("block")) if arg("block") else None
        if blk is None and arg("address"):
            blk = mem.getBlock(addr(arg("address")))
        if blk is None:
            raise Fail("Memory block not found (pass block name or address)")
        with tx("Set memory block"):
            for k, fn in (("read", blk.setRead), ("write", blk.setWrite),
                          ("execute", blk.setExecute), ("volatile", blk.setVolatile)):
                if ARGS.get(k) is not None:
                    fn(arg_bool(k))
            if arg("new_name"):
                blk.setName(arg("new_name"))
            if arg("comment") is not None:
                blk.setComment(arg("comment"))
        return {"success": True, "name": _s(blk.getName()), "start": _s(blk.getStart()),
                "read": blk.isRead(), "write": blk.isWrite(), "execute": blk.isExecute(),
                "volatile": blk.isVolatile()}
        ''',
    ),
    JTool(
        name="set_image_base",
        description="Set the program's image base address (rebases every address in the program).",
        properties={"address": _p("New image base")},
        required=["address"],
        mode="write",
        timeout=600,
        body='''
        p = prog()
        old = p.getImageBase()
        with tx("Set image base"):
            p.setImageBase(addr(arg("address")), True)
        return {"success": True, "old_base": _s(old), "new_base": _s(p.getImageBase())}
        ''',
    ),
    # ----- analysis ----------------------------------------------------------
    JTool(
        name="analysis_status",
        description="Get auto-analysis status: whether the program has been analyzed, analysis timestamps and enabled analyzer counts.",
        body='''
        p = prog()
        info = p.getOptions("Program Information")
        res = {"program": _s(p.getName())}
        try:
            from ghidra.program.util import GhidraProgramUtilities
            res["analyzed"] = GhidraProgramUtilities.isAnalyzed(p)
        except (Exception, Throwable):
            res["analyzed"] = info.getBoolean("Analyzed", False) if info.contains("Analyzed") else None
        for k in ("Date Created", "Executable Format", "Created With Ghidra Version"):
            if info.contains(k):
                res[k.lower().replace(" ", "_")] = _s(info.getValueAsString(k))
        an = p.getOptions("Analyzers")
        enabled = disabled = 0
        for n in an.getOptionNames():
            if "." in n:
                continue
            try:
                if an.getBoolean(n, False): enabled += 1
                else: disabled += 1
            except (Exception, Throwable):
                pass
        res["analyzers_enabled"] = enabled
        res["analyzers_disabled"] = disabled
        res["function_count"] = p.getFunctionManager().getFunctionCount()
        return res
        ''',
    ),
    JTool(
        name="configure_analyzer",
        description="Enable or disable an auto-analysis analyzer (or set one of its options) for this program. Takes effect on the next run_analysis.",
        properties={"name": _p("Analyzer name, e.g. 'Decompiler Parameter ID'; use list_analyzers"),
                    "enabled": _p("Enable (true) or disable (false)", B),
                    "option": _p("Optional analyzer sub-option name"),
                    "value": _p("Value for the sub-option")},
        required=["name"],
        mode="write",
        body='''
        an = prog().getOptions("Analyzers")
        name = arg("name")
        if not an.contains(name):
            matches = [_s(n) for n in an.getOptionNames() if "." not in n and name.lower() in n.lower()]
            if len(matches) == 1:
                name = matches[0]
            else:
                raise Fail("Analyzer not found: %s (candidates: %s)" % (name, ", ".join(matches[:20])))
        with tx("Configure analyzer"):
            if ARGS.get("enabled") is not None:
                an.setBoolean(name, arg_bool("enabled"))
            if arg("option"):
                key = name + "." + arg("option")
                if not an.contains(key):
                    raise Fail("Analyzer option not found: " + key)
                t = _s(an.getType(key))
                v = _s(ARGS.get("value"))
                if t.startswith("BOOLEAN"): an.setBoolean(key, v.lower() in ("1", "true", "yes", "on"))
                elif t.startswith("INT"): an.setInt(key, int(v, 0))
                elif t.startswith("LONG"): an.setLong(key, long(v, 0))
                elif t.startswith("DOUBLE"): an.setDouble(key, float(v))
                else: an.setString(key, v)
        return {"success": True, "analyzer": _s(name), "enabled": an.getBoolean(name, False)}
        ''',
    ),
    JTool(
        name="delete_bookmark",
        description="Delete bookmarks at an address (optionally only those of one category or type).",
        properties={"address": _p("Bookmark address"), "category": _p("Only delete this category"),
                    "type": _p("Only delete this bookmark type (Note, Info, Warning, Error, Analysis)")},
        required=["address"],
        mode="write",
        body='''
        bm = prog().getBookmarkManager()
        a = addr(arg("address"))
        deleted = []
        with tx("Delete bookmark"):
            for b in list(bm.getBookmarks(a)):
                if arg("category") and b.getCategory() != arg("category"):
                    continue
                if arg("type") and b.getTypeString() != arg("type"):
                    continue
                deleted.append({"type": _s(b.getTypeString()), "category": _s(b.getCategory()),
                                "comment": _s(b.getComment())})
                bm.removeBookmark(b)
        if not deleted:
            raise Fail("No matching bookmark at " + _s(a))
        return {"success": True, "deleted": deleted}
        ''',
    ),
    JTool(
        name="list_calling_conventions",
        description="List calling conventions available for the program's compiler spec (and the default).",
        body='''
        cs = prog().getCompilerSpec()
        out = []
        for m in cs.getCallingConventions():
            out.append({"name": _s(m.getName()), "stack_shift": m.getStackshift(),
                        "has_this": m.hasThisPointer()})
        return {"default": _s(cs.getDefaultCallingConvention().getName()), "conventions": out}
        ''',
    ),
    JTool(
        name="get_external_location",
        description="Get external location details: by address (external/thunk/IAT address) or every location for a library (dll_name).",
        properties={"address": _p("External, thunk or pointer address"), "dll_name": _p("Library name")},
        body='''
        p = prog()
        em = p.getExternalManager()
        def info(loc):
            return {"label": _s(loc.getLabel()), "library": _s(loc.getLibraryName()),
                    "original_name": _s(loc.getOriginalImportedName()),
                    "address": _s(loc.getAddress()),
                    "external_space_address": _s(loc.getExternalSpaceAddress()),
                    "is_function": loc.isFunction(), "source": _s(loc.getSource())}
        out = []
        if arg("address"):
            a = addr(arg("address"))
            sym = p.getSymbolTable().getPrimarySymbol(a)
            if sym is not None and sym.isExternal():
                loc = em.getExternalLocation(sym)
                if loc: out.append(info(loc))
            f = p.getFunctionManager().getFunctionAt(a)
            if f is not None and f.isThunk():
                tf = f.getThunkedFunction(True)
                if tf is not None and tf.isExternal():
                    out.append(info(tf.getExternalLocation()))
            it = em.getExternalLocations(a)
            while it.hasNext():
                out.append(info(it.next()))
            for ref in p.getReferenceManager().getReferencesFrom(a):
                if ref.isExternalReference():
                    out.append(info(ref.getExternalLocation()))
        elif arg("dll_name"):
            it = em.getExternalLocations(arg("dll_name"))
            while it.hasNext():
                out.append(info(it.next()))
        else:
            return {"libraries": [_s(n) for n in em.getExternalLibraryNames()]}
        return {"count": len(out), "locations": out}
        ''',
    ),
)


# ---------------------------------------------------------------------------
# Local (no Ghidra process) utility tools
# ---------------------------------------------------------------------------

def _convert_number(args: dict) -> dict:
    text = str(args.get("text", "")).strip().replace("_", "")
    size = int(args.get("size") or 0)
    neg = text.startswith("-")
    body = text[1:] if neg else text
    low = body.lower()
    try:
        if low.startswith("0x"):
            v = int(low, 16)
        elif low.endswith("h") and all(c in "0123456789abcdef" for c in low[:-1]):
            v = int(low[:-1], 16)
        elif low.startswith("0b"):
            v = int(low, 2)
        elif low.startswith("0o"):
            v = int(low, 8)
        elif all(c in "0123456789" for c in low):
            v = int(low, 10)
        else:
            v = int(low, 16)
    except ValueError:
        return {"error": f"Cannot parse number: {text}"}
    if neg:
        v = -v
    if not size:
        bits = max(8, (abs(v).bit_length() + (1 if v < 0 else 0) + 7) // 8 * 8)
        size = min(8, max(1, bits // 8))
        for s in (1, 2, 4, 8):
            if s >= size:
                size = s
                break
    bits = size * 8
    mask = (1 << bits) - 1
    u = v & mask
    signed = u - (1 << bits) if u >> (bits - 1) else u
    raw = u.to_bytes(size, "little")
    return {"input": text, "size": size, "unsigned": u, "signed": signed,
            "hex": hex(u), "binary": bin(u), "octal": oct(u),
            "bytes_le": raw.hex(" "), "bytes_be": raw[::-1].hex(" "),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in raw[::-1])}


def _check_connection(args: dict) -> dict:
    from .. import server as srv
    res = {"status": "ok", "server_kind": "headless", "server": "kawaiidra",
           "ghidra_home": str(config.ghidra_home), "tool_count": len(srv.TOOLS)}
    try:
        res["analyze_headless"] = str(config.analyze_headless)
    except FileNotFoundError as e:
        res["status"] = "error"
        res["error"] = str(e)
    props = config.ghidra_home / "Ghidra" / "application.properties"
    if props.exists():
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                res["ghidra_version"] = line.split("=", 1)[1]
    return res


def _mcp_health(args: dict) -> dict:
    from .. import server as srv
    from ..cache import get_cache_stats
    res = _check_connection(args)
    res.update({
        "python": sys.version.split()[0], "platform": platform.platform(),
        "project_dir": str(config.project_dir), "binaries_dir": str(config.binaries_dir),
        "default_project": config.default_project,
        "projects": sorted(p.name for p in config.project_dir.glob("*") if (p / f"{p.name}.gpr").exists())
        if config.project_dir.exists() else [],
        "timeouts": {"analysis": config.analysis_timeout, "decompile": config.decompile_timeout},
        "endpoint_count": len(srv.TOOLS),
    })
    try:
        res["cache"] = get_cache_stats()
    except Exception as e:  # noqa: BLE001
        res["cache"] = {"error": str(e)}
    try:
        from ..bridge import get_backend
        b = get_backend()
        res["bridge_mode"] = b.mode_description if b else "subprocess"
    except Exception:  # noqa: BLE001
        res["bridge_mode"] = "subprocess"
    return res


def _mcp_schema(args: dict) -> dict:
    from .. import server as srv
    from .framework import REGISTRY
    name = args.get("tool")
    tools = [t for t in srv.TOOLS if not name or t.name == name]
    return {"total": len(tools), "tools": [
        {"name": t.name, "description": t.description, "input_schema": t.inputSchema,
         "category": "parity" if t.name in REGISTRY else "core"} for t in tools]}


register(
    JTool(name="convert_number", mode="local", local=_convert_number,
          description="Convert a number between bases (hex/dec/bin/oct, signed/unsigned, byte order) at a given byte size.",
          properties={"text": _p("Number: 0x1F, 31, 0b11111, 1Fh, -1"),
                      "size": _p("Size in bytes (1,2,4,8); auto if omitted", I)},
          required=["text"]),
    JTool(name="check_connection", mode="local", local=_check_connection,
          description="Cheap liveness probe: server kind, Ghidra install/version and tool count."),
    JTool(name="mcp_health", mode="local", local=_mcp_health,
          description="Server health: Ghidra install, projects, timeouts, cache stats, bridge mode and endpoint count."),
    JTool(name="mcp_schema", mode="local", local=_mcp_schema,
          description="Machine-readable schema of every tool (optionally one tool) with input schemas.",
          properties={"tool": _p("Only this tool name")}),
)
