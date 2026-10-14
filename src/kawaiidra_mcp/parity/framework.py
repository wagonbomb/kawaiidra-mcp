"""Declarative Jython tool framework.

Each tool is a ``JTool``: an MCP schema plus a Jython function body. The body
runs inside ``def _mcp_main():`` with these globals available:

* ``ARGS``  - the tool arguments (decoded from base64 JSON, never string-spliced)
* the helpers defined in ``prelude.PROGRAM_PRELUDE`` / ``prelude.PROJECT_PRELUDE``

The body returns a JSON-serialisable dict. Returning ``{"error": "..."}`` marks
the call as failed.

Modes:
    read     - analyzeHeadless -process <binary> -readOnly
    write    - analyzeHeadless -process <binary> (changes are saved)
    project  - support/jythonRun with an initialised Ghidra Application and no
               program loaded (project file ops, multi-program tools)
    local    - pure Python handler, no Ghidra process
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import textwrap
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import mcp.types as types

from ..config import config
from .prelude import PROGRAM_PRELUDE, PROJECT_PRELUDE

RESULT_START = "=== MCP_RESULT_JSON ==="
RESULT_END = "=== MCP_RESULT_END ==="

BINARY_PROP = {"binary_name": {"type": "string", "description": "Name of the analyzed binary"}}
PROJECT_PROP = {"project_name": {"type": "string", "description": "Project name (optional)"}}


@dataclass
class JTool:
    name: str
    description: str
    properties: dict = field(default_factory=dict)
    required: list = field(default_factory=list)
    body: str = ""
    mode: str = "read"
    timeout: Optional[int] = None
    local: Optional[Callable[[dict], Any]] = None
    needs_binary: Optional[bool] = None
    # Module-level Jython (helper defs) inserted before the body function
    helpers: str = ""
    # Gate for tools that execute arbitrary code or touch remote services
    phase: str = ""

    def __post_init__(self):
        if self.needs_binary is None:
            self.needs_binary = self.mode in ("read", "write")

    def schema(self) -> dict:
        props: dict = {}
        req = list(self.required)
        if self.needs_binary:
            props.update(BINARY_PROP)
            if "binary_name" not in req:
                req.insert(0, "binary_name")
        props.update(self.properties)
        if self.mode != "local" and "project_name" not in props:
            props.update(PROJECT_PROP)
        return {"type": "object", "properties": props, "required": req}

    def to_mcp(self) -> types.Tool:
        return types.Tool(name=self.name, description=self.description,
                          inputSchema=self.schema())


REGISTRY: dict[str, JTool] = {}

# Extra environment for Ghidra subprocesses (e.g. Ghidra Server credentials,
# kept out of generated script files).
EXTRA_ENV: dict[str, str] = {}


def register(*tools: JTool) -> None:
    for t in tools:
        if t.name in REGISTRY:
            raise ValueError(f"duplicate parity tool: {t.name}")
        REGISTRY[t.name] = t


# ---------------------------------------------------------------------------
# Script assembly
# ---------------------------------------------------------------------------

def build_script(tool: JTool, args: dict) -> str:
    payload = base64.b64encode(json.dumps(args).encode("utf-8")).decode("ascii")
    prelude = PROJECT_PRELUDE if tool.mode == "project" else PROGRAM_PRELUDE
    body = textwrap.indent(textwrap.dedent(tool.body).strip("\n"), "    ")
    return (
        "# @category MCP\n# @runtime Jython\n"
        + prelude
        + f"\nARGS = json.loads(base64.b64decode('{payload}').decode('utf-8'))\n\n"
        + textwrap.dedent(tool.helpers).strip("\n") + "\n\n"
        + "def _mcp_main():\n"
        + body
        + "\n\n_mcp_emit(_mcp_main)\n"
    )


def parse_result(stdout: str) -> dict:
    if RESULT_START in stdout:
        part = stdout.split(RESULT_START, 1)[1].split(RESULT_END, 1)[0]
        try:
            return json.loads(part.strip())
        except json.JSONDecodeError as e:
            return {"error": f"Failed to parse script output: {e}"}
    return {"error": "No result from Ghidra script", "raw": stdout[-3000:]}


# ---------------------------------------------------------------------------
# Process execution
# ---------------------------------------------------------------------------

def _run(cmd_args: list[str], executable: Path, timeout: int) -> tuple[str, str, int]:
    from .. import server as srv  # lazy: avoid import cycle

    if any(a is None for a in cmd_args):
        return "", "Error: missing required argument", 1
    try:
        if sys.platform == "win32" and str(executable).lower().endswith(".bat"):
            safe = [srv._quote_windows_arg(srv._get_win32_short_path(a)) for a in cmd_args]
            exe = srv._get_win32_short_path(str(executable))
            cmd: Any = f'"{exe}" ' + " ".join(safe)
            shell = True
        else:
            cmd = [str(executable)] + cmd_args
            shell = False
        srv.log(f"Running: {cmd}")
        env = {**os.environ, **EXTRA_ENV} if EXTRA_ENV else None
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, shell=shell, stdin=subprocess.DEVNULL, env=env,
                           cwd=str(config.project_dir), encoding="utf-8", errors="replace")
        return r.stdout or "", r.stderr or "", r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", 1
    except Exception as e:  # noqa: BLE001
        return "", str(e), 1


def jython_run_executable() -> Path:
    name = "jythonRun.bat" if sys.platform == "win32" else "jythonRun"
    for cand in (config.ghidra_home / "support" / name,
                 config.ghidra_home / "libexec" / "support" / name):
        if cand.exists():
            return cand
    raise FileNotFoundError(f"{name} not found under {config.ghidra_home}")


def execute(tool: JTool, args: dict) -> dict:
    """Run a tool and return its result dict."""
    if tool.mode == "local":
        return tool.local(args)  # type: ignore[misc]

    project_name = args.get("project_name") or config.default_project
    timeout = tool.timeout or config.decompile_timeout
    script_name = f"MCP_{tool.name}_{uuid.uuid4().hex[:8]}.py"
    script_dir = config.scripts_dir
    script_dir.mkdir(parents=True, exist_ok=True)
    script_path = script_dir / script_name

    if tool.mode == "project":
        args = dict(args)
        args.setdefault("project_name", project_name)
        args["_projects_dir"] = str(config.project_dir)
        args["_binaries_dir"] = str(config.binaries_dir)
        args["_exports_dir"] = str(config.exports_dir) if hasattr(config, "exports_dir") else ""
    script_path.write_text(build_script(tool, args), encoding="utf-8")

    try:
        if tool.mode == "project":
            stdout, stderr, code = _run([str(script_path)], jython_run_executable(), timeout)
        else:
            cmd = [
                str(config.get_project_path(project_name)), project_name,
                "-process", args.get("binary_name"),
                "-noanalysis",
                "-scriptPath", str(script_dir),
                "-postScript", script_name,
            ]
            if tool.mode == "read":
                cmd.append("-readOnly")
            try:
                exe = config.analyze_headless
            except FileNotFoundError as e:
                return {"error": str(e)}
            stdout, stderr, code = _run(cmd, exe, timeout)
    finally:
        if not os.environ.get("KAWAIIDRA_KEEP_SCRIPTS"):
            try:
                script_path.unlink()
            except OSError:
                pass

    result = parse_result(stdout)
    if "raw" in result:
        hint = _diagnose(stdout + "\n" + stderr)
        if hint:
            result["error"] = hint
        result["stderr"] = stderr[-1500:]
    return result


def _diagnose(output: str) -> str:
    if "Unable to lock project" in output or "LockException" in output:
        return "Project is locked (open in Ghidra GUI or another process)."
    if "ERROR REPORT: Import failed" in output or "No program found" in output or \
            "not found in project" in output.lower():
        return "Binary not found in project. Use list_analyzed_binaries."
    if "timed out" in output:
        return output.strip().splitlines()[-1]
    return ""


def format_result(result: Any) -> str:
    if isinstance(result, str):
        return result
    text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
    if isinstance(result, dict) and result.get("error"):
        return "Error: " + str(result["error"]) + "\n" + text
    return text


async def handle(name: str, args: dict) -> list[types.TextContent]:
    import asyncio

    tool = REGISTRY[name]
    result = await asyncio.to_thread(execute, tool, args)
    return [types.TextContent(type="text", text=format_result(result))]
