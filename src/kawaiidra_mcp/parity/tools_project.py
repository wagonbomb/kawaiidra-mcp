"""Phase 15 — Project & program lifecycle, session state and script execution."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ..config import config
from .framework import JTool, register

S = {"type": "string"}
I = {"type": "integer"}
B = {"type": "boolean"}


def _p(desc: str, base: dict = S, **extra) -> dict:
    return {**base, "description": desc, **extra}


# ---------------------------------------------------------------------------
# Session state: a "current" project/program so binary_name may be omitted.
# server.handle_call_tool calls apply_session() before validating arguments.
# ---------------------------------------------------------------------------

SESSION: dict = {"project": None, "program": None, "open": []}


def apply_session(arguments: dict, schema: dict | None) -> dict:
    props = (schema or {}).get("properties", {})
    if "binary_name" in props and not arguments.get("binary_name") and SESSION["program"]:
        arguments = {**arguments, "binary_name": SESSION["program"]}
    if "project_name" in props and not arguments.get("project_name") and SESSION["project"]:
        arguments = {**arguments, "project_name": SESSION["project"]}
    return arguments


def _projects() -> list[str]:
    if not config.project_dir.exists():
        return []
    return sorted(p.name for p in config.project_dir.iterdir() if (p / f"{p.name}.gpr").exists())


def _binaries(project: str) -> list[str]:
    from .. import server as srv
    return srv.get_analyzed_binaries(project)


def _open_project(args: dict) -> dict:
    name = args.get("path") or args.get("name")
    if not name:
        return {"error": "path (project name or .gpr path) is required"}
    p = Path(name)
    if p.suffix == ".gpr":
        if p.parent.parent.resolve() != config.project_dir.resolve():
            return {"error": f"Only projects under {config.project_dir} are supported (got {p})"}
        name = p.stem
    if name not in _projects():
        return {"error": f"Project not found: {name}", "available": _projects()}
    SESSION.update(project=name, program=None, open=[])
    res = {"success": True, "project": name, "programs": _binaries(name)}
    if args.get("program"):
        res.update(_open_program({"path": args["program"]}))
    return res


def _close_project(args: dict) -> dict:
    old = SESSION["project"]
    SESSION.update(project=None, program=None, open=[])
    return {"success": True, "closed": old, "default_project": config.default_project}


def _open_program(args: dict) -> dict:
    name = args.get("path") or args.get("program") or args.get("name")
    project = args.get("project_name") or SESSION["project"] or config.default_project
    if not name:
        return {"error": "path (program name) is required"}
    name = name.rsplit("/", 1)[-1]
    if name not in _binaries(project):
        if args.get("auto_analyze") or args.get("file_path"):
            from .. import server as srv  # noqa: F401  (import via analyze_binary tool instead)
        return {"error": f"Program not found in project '{project}': {name}", "available": _binaries(project)}
    SESSION["project"] = project
    SESSION["program"] = name
    if name not in SESSION["open"]:
        SESSION["open"].append(name)
    return {"success": True, "current_program": name, "project": project}


def _switch_program(args: dict) -> dict:
    return _open_program({"path": args.get("program") or args.get("path")})


def _close_program(args: dict) -> dict:
    name = args.get("name") or SESSION["program"]
    if name in SESSION["open"]:
        SESSION["open"].remove(name)
    if SESSION["program"] == name:
        SESSION["program"] = SESSION["open"][-1] if SESSION["open"] else None
    return {"success": True, "closed": name, "current_program": SESSION["program"],
            "note": "Headless mode saves every mutation immediately; save=false cannot discard past edits."}


def _list_open_programs(args: dict) -> dict:
    project = SESSION["project"] or config.default_project
    return {"project": project, "current_program": SESSION["program"], "open_programs": SESSION["open"],
            "available_programs": _binaries(project)}


def _save(args: dict) -> dict:
    return {"success": True, "saved": True,
            "note": "Kawaiidra runs each mutation in its own headless session and saves it on completion; nothing is pending."}


def _exit_ghidra(args: dict) -> dict:
    stopped = False
    try:
        from ..bridge import get_backend
        b = get_backend()
        if b is not None and getattr(b, "_bridge", None) is not None:
            b._bridge.stop()
            stopped = True
    except Exception:  # noqa: BLE001
        pass
    SESSION.update(project=None, program=None, open=[])
    return {"success": True, "bridge_stopped": stopped,
            "note": "No long-running Ghidra process in headless mode; session state cleared."}


def _delete_project(args: dict) -> dict:
    return {"error": "use delete_project (core tool)"}


register(
    JTool(name="open_project", mode="local", local=_open_project,
          description="Make a project the session's current project (subsequent calls may omit project_name). Optionally also open a program.",
          properties={"path": _p("Project name or projects/<name>/<name>.gpr"), "program": _p("Program to make current")},
          required=["path"]),
    JTool(name="close_project", mode="local", local=_close_project,
          description="Clear the session's current project/program (falls back to the default project)."),
    JTool(name="open_program", mode="local", local=_open_program,
          description="Make an analyzed program the session's current program so later calls may omit binary_name. Use analyze_binary to import new files.",
          properties={"path": _p("Program name (or /folder/name)"), "project_name": _p("Project (default: current)")},
          required=["path"]),
    JTool(name="switch_program", mode="local", local=_switch_program,
          description="Switch the session's current program.",
          properties={"program": _p("Program name")}, required=["program"]),
    JTool(name="close_program", mode="local", local=_close_program,
          description="Remove a program from the session's open list (changes are already saved in headless mode).",
          properties={"name": _p("Program name (default current)"), "save": _p("Ignored: mutations are saved immediately", B)}),
    JTool(name="list_open_programs", mode="local", local=_list_open_programs,
          description="List the session's open programs, the current program and all programs available in the project."),
    JTool(name="save_program", mode="local", local=_save,
          description="Save the current program (no-op: headless mutations are saved when each call completes).",
          properties={"program": _p("Program name")}),
    JTool(name="save_all_programs", mode="local", local=_save,
          description="Save all open programs (no-op: headless mutations are saved when each call completes)."),
    JTool(name="exit_ghidra", mode="local", local=_exit_ghidra,
          description="Shut down: stop the in-process JPype bridge if running and clear session state."),
)


# ---------------------------------------------------------------------------
# Project-file tools (jythonRun, no program loaded)
# ---------------------------------------------------------------------------

register(
    JTool(
        name="create_project",
        description="Create a new, empty Ghidra project under the kawaiidra projects directory.",
        properties={"name": _p("Project name")},
        required=["name"],
        mode="project",
        body='''
        name = arg("name")
        if os.path.exists(os.path.join(project_dir(name), name + ".gpr")):
            raise Fail("Project already exists: " + name)
        gp = open_project(name, create=True)
        return {"success": True, "project": name, "path": project_dir(name)}
        ''',
    ),
    JTool(
        name="get_project_info",
        description="Info about a project: location, folders, files with content type, sizes and modification times.",
        mode="project",
        body='''
        gp = open_project()
        pd = gp.getProjectData()
        folders = []
        stack = [pd.getRootFolder()]
        while stack:
            fo = stack.pop()
            folders.append(_s(fo.getPathname()))
            stack.extend(list(fo.getFolders()))
        files = []
        for df in walk_files(gp):
            files.append({"path": _s(df.getPathname()), "type": _s(df.getContentType()),
                          "version": df.getVersion(), "read_only": df.isReadOnly(),
                          "modified": df.getLastModifiedTime()})
        loc = gp.getProject().getProjectLocator()
        return {"project": ARGS.get("project_name"), "location": _s(loc.getLocation()),
                "project_dir": _s(loc.getProjectDir()), "folders": sorted(folders), "files": files,
                "file_count": len(files)}
        ''',
    ),
    JTool(
        name="list_project_files",
        description="List project files and folders (optionally under one folder) with content types.",
        properties={"folder": _p("Folder path (default /)")},
        mode="project",
        body='''
        gp = open_project()
        pd = gp.getProjectData()
        fo = pd.getFolder(arg("folder", "/"))
        if fo is None:
            raise Fail("Folder not found: " + arg("folder"))
        return {"folder": _s(fo.getPathname()),
                "folders": [_s(x.getPathname()) for x in fo.getFolders()],
                "files": [{"name": _s(df.getName()), "path": _s(df.getPathname()), "type": _s(df.getContentType())}
                          for df in fo.getFiles()]}
        ''',
    ),
    JTool(
        name="create_folder",
        description="Create a folder (with parents) in the project.",
        properties={"path": _p("Folder path, e.g. /firmware/v2")},
        required=["path"],
        mode="project",
        body='''
        gp = open_project()
        fo = gp.getProjectData().getRootFolder()
        for part in [x for x in arg("path").split("/") if x]:
            nxt = fo.getFolder(part)
            fo = nxt if nxt is not None else fo.createFolder(part)
        return {"success": True, "folder": _s(fo.getPathname())}
        ''',
    ),
    JTool(
        name="move_file",
        description="Move a program file to another project folder (created if needed), preserving its analysis and documentation.",
        properties={"filePath": _p("File name or /path"), "destFolder": _p("Destination folder path")},
        required=["filePath", "destFolder"],
        mode="project",
        body='''
        gp = open_project()
        df = find_domain_file(gp, arg("filePath"))
        if df.isChanged():
            raise Fail("File has unsaved changes")
        fo = gp.getProjectData().getRootFolder()
        for part in [x for x in arg("destFolder").split("/") if x]:
            nxt = fo.getFolder(part)
            fo = nxt if nxt is not None else fo.createFolder(part)
        old = _s(df.getPathname())
        moved = df.moveTo(fo)
        return {"success": True, "old_path": old, "new_path": _s(moved.getPathname())}
        ''',
    ),
    JTool(
        name="move_folder",
        description="Move a project folder (and everything under it) into another folder.",
        properties={"sourcePath": _p("Folder to move"), "destPath": _p("Destination parent folder")},
        required=["sourcePath", "destPath"],
        mode="project",
        body='''
        gp = open_project()
        pd = gp.getProjectData()
        src = pd.getFolder(arg("sourcePath"))
        dst = pd.getFolder(arg("destPath"))
        if src is None or dst is None:
            raise Fail("Folder not found")
        if _s(dst.getPathname()).startswith(_s(src.getPathname())):
            raise Fail("Cannot move a folder into itself or a descendant")
        moved = src.moveTo(dst)
        return {"success": True, "new_path": _s(moved.getPathname())}
        ''',
    ),
    JTool(
        name="delete_file",
        description="Delete a file from the project (permanent).",
        properties={"filePath": _p("File name or /path")},
        required=["filePath"],
        mode="project",
        body='''
        gp = open_project()
        df = find_domain_file(gp, arg("filePath"))
        path = _s(df.getPathname())
        df.delete()
        return {"success": True, "deleted": path}
        ''',
    ),
    JTool(
        name="export_program",
        description="Export a program to a Ghidra Zip File (.gzf) — portable, includes all analysis and annotations.",
        properties={"program_name": _p("Program name or /path"), "output_dir": _p("Directory (default: exports dir)"),
                    "output_name": _p("File name (default <program>.gzf)")},
        required=["program_name"],
        mode="project",
        body='''
        from java.io import File
        gp = open_project()
        df = find_domain_file(gp, arg("program_name"))
        out_dir = arg("output_dir") or ARGS.get("_exports_dir") or "."
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        name = arg("output_name") or (df.getName() + ".gzf")
        out = os.path.join(out_dir, name)
        if os.path.exists(out):
            os.remove(out)
        df.packFile(File(out), MONITOR)
        return {"success": True, "program": _s(df.getPathname()), "output": out, "size": os.path.getsize(out)}
        ''',
    ),
    JTool(
        name="import_program",
        description="Import a Ghidra Zip File (.gzf) into the project as a new program under target_folder.",
        properties={"gzf_path": _p("Path to the .gzf"), "target_folder": _p("Folder (default /)"),
                    "target_name": _p("Program name (default from file)"), "overwrite": _p("Replace existing (default false)", B)},
        required=["gzf_path"],
        mode="project",
        body='''
        from java.io import File
        gp = open_project()
        src = arg("gzf_path")
        if not os.path.exists(src):
            raise Fail("File not found: " + src)
        fo = gp.getProjectData().getRootFolder()
        for part in [x for x in (arg("target_folder") or "/").split("/") if x]:
            nxt = fo.getFolder(part)
            fo = nxt if nxt is not None else fo.createFolder(part)
        name = arg("target_name") or os.path.basename(src).rsplit(".gzf", 1)[0]
        existing = fo.getFile(name)
        if existing is not None:
            if not arg_bool("overwrite"):
                raise Fail("Program already exists: " + name + " (pass overwrite=true)")
            existing.delete()
        df = fo.createFile(name, File(src), MONITOR)
        return {"success": True, "path": _s(df.getPathname()), "type": _s(df.getContentType())}
        ''',
    ),
    JTool(
        name="archive_project",
        description="Archive the whole project to a Ghidra-native .gar file (restorable in the Ghidra GUI via File > Restore Project, or with restore_project).",
        properties={"output_dir": _p("Directory (default: exports dir)"), "output_name": _p("File name (default <project>.gar)")},
        mode="project",
        timeout=1800,
        body='''
        from java.io import File
        import java.lang
        gp = open_project()
        out_dir = arg("output_dir") or ARGS.get("_exports_dir") or "."
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        out = os.path.join(out_dir, arg("output_name") or (ARGS["project_name"] + ".gar"))
        if os.path.exists(out):
            os.remove(out)
        cls = java.lang.Class.forName("ghidra.app.plugin.core.archive.ArchiveTask")
        ctor = cls.getDeclaredConstructors()[0]
        ctor.setAccessible(True)
        task = ctor.newInstance([gp.getProject(), File(out)])
        task.run(MONITOR)
        if not os.path.exists(out):
            raise Fail("Archive was not written")
        return {"success": True, "archive": out, "size": os.path.getsize(out)}
        ''',
    ),
    JTool(
        name="restore_project",
        description="Restore a .gar archive into a new project (projects/<project_name>). The restored project is not made current; use open_project.",
        properties={"gar_path": _p("Path to .gar"), "project_name": _p("Name for the restored project")},
        required=["gar_path", "project_name"],
        mode="project",
        timeout=1800,
        body='''
        from java.io import File
        import java.lang
        name = ARGS["project_name"]
        pdir = project_dir(name)
        if os.path.exists(os.path.join(pdir, name + ".gpr")):
            raise Fail("Project already exists: " + name)
        if not os.path.exists(arg("gar_path")):
            raise Fail("Archive not found: " + arg("gar_path"))
        if not os.path.isdir(pdir):
            os.makedirs(pdir)
        cls = java.lang.Class.forName("ghidra.app.plugin.core.archive.RestoreTask")
        ctor = cls.getDeclaredConstructors()[0]
        ctor.setAccessible(True)
        task = ctor.newInstance([ProjectLocator(pdir, name), File(arg("gar_path")), None])
        try:
            task.run(MONITOR)
        except (Exception, Throwable) as e:
            if not os.path.exists(os.path.join(pdir, name + ".gpr")):
                raise
        if not os.path.exists(os.path.join(pdir, name + ".gpr")):
            raise Fail("Restore failed")
        gp = open_project(name)
        return {"success": True, "project": name, "files": [_s(df.getPathname()) for df in walk_files(gp)]}
        ''',
    ),
)


def _run_ghidra_script(args: dict) -> dict:
    """Run a saved Ghidra script (user_scripts dir or Ghidra's script dirs) against a program."""
    import uuid
    from .. import server as srv
    from .framework import _run, parse_result

    name = args.get("script_name") or ""
    binary = args.get("binary_name")
    project = args.get("project_name") or config.default_project
    script_args = args.get("args") or []
    if isinstance(script_args, str):
        script_args = script_args.split()
    search = [config.user_scripts_dir, config.scripts_dir]
    path = None
    for d in search:
        cand = Path(d) / name
        if cand.exists():
            path = cand
            break
    tmp = None
    if path is None:
        # Ghidra's own scripts are resolved by analyzeHeadless from its bundled script dirs
        script_dir = None
    else:
        tmp = config.scripts_dir / f"MCPRun_{uuid.uuid4().hex[:8]}_{path.name}"
        config.scripts_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, tmp)
        name = tmp.name
        script_dir = str(config.scripts_dir)
    cmd = [str(config.get_project_path(project)), project, "-process", binary, "-noanalysis"]
    if script_dir:
        cmd += ["-scriptPath", script_dir]
    cmd += ["-postScript", name] + [str(a) for a in script_args]
    if args.get("read_only", True):
        cmd.append("-readOnly")
    try:
        stdout, stderr, code = _run(cmd, config.analyze_headless, int(args.get("timeout_seconds") or config.analysis_timeout))
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()
    lines = [l for l in stdout.splitlines() if " (GhidraScript) " in l or "SCRIPT" in l.upper() or l.startswith(name)]
    res = {"script": args.get("script_name"), "exit_code": code}
    if "=== MCP_RESULT_JSON ===" in stdout:
        res["result"] = parse_result(stdout)
    if args.get("capture_output", True):
        out = [l.split("> ", 1)[-1] for l in stdout.splitlines() if "(GhidraScript)" in l or "INFO  " not in l]
        res["output"] = "\n".join(out)[-8000:]
    if "ERROR" in stdout and "Script not found" in stdout or "Unable to find script" in stdout:
        res["error"] = f"Script not found: {args.get('script_name')}"
    if code != 0 and "error" not in res:
        res["error"] = (stderr or stdout)[-1500:]
    return res


register(
    JTool(name="run_ghidra_script", mode="local", local=_run_ghidra_script, needs_binary=True,
          description="Run a saved Ghidra script by file name (kawaiidra user scripts via save_script, or any script bundled with Ghidra, e.g. 'CountAndSaveStrings.java') against a program, with arguments and captured output.",
          properties={"script_name": _p("Script file name, e.g. MyScript.py or AsciiToBinaryScript.java"),
                      "args": {"type": "array", "items": {"type": "string"}, "description": "Script arguments"},
                      "timeout_seconds": _p("Timeout (default analysis timeout)", I),
                      "capture_output": _p("Return script output (default true)", B),
                      "read_only": _p("Discard program changes (default true)", B),
                      "project_name": _p("Project name (optional)")},
          required=["script_name"]),
)
