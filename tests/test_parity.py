"""Offline tests for the parity tool framework (no Ghidra process)."""

import ast
import base64
import json
import re

import pytest

from kawaiidra_mcp import server
from kawaiidra_mcp.parity import REGISTRY
from kawaiidra_mcp.parity.framework import build_script, parse_result, format_result
from kawaiidra_mcp.parity.prelude import PROGRAM_PRELUDE, PROJECT_PRELUDE


def test_registry_tools_are_listed_once():
    names = [t.name for t in server.TOOLS]
    assert len(names) == len(set(names))
    for name in REGISTRY:
        assert name in names


@pytest.mark.parametrize("name", sorted(REGISTRY))
def test_schema_well_formed(name):
    tool = REGISTRY[name]
    schema = tool.schema()
    assert schema["type"] == "object"
    for req in schema["required"]:
        assert req in schema["properties"], f"{name}: required {req} missing from properties"
    if tool.needs_binary:
        assert "binary_name" in schema["required"]
    assert tool.description


@pytest.mark.parametrize("name", sorted(n for n, t in REGISTRY.items() if t.mode != "local"))
def test_script_compiles_as_python2_subset(name):
    """Scripts are Jython 2.7; py3 can still parse them if we avoid py2-only syntax."""
    tool = REGISTRY[name]
    script = build_script(tool, {"binary_name": "x", "q": "it's \"quoted\""})
    src = script.replace("basestring", "str").replace("unicode(", "str(").replace("long(", "int(")
    ast.parse(src)
    assert not re.search(r"(?<![A-Za-z0-9_])f[\"']", tool.body)


def test_args_are_base64_not_spliced():
    tool = REGISTRY["get_property"]
    evil = "'); import os; os.system('x') #"
    script = build_script(tool, {"binary_name": "b", "map": evil, "address": "0"})
    assert evil not in script
    payload = re.search(r"b64decode\('([^']+)'\)", script).group(1)
    assert json.loads(base64.b64decode(payload))["map"] == evil


def test_parse_result_and_format():
    out = "noise\n=== MCP_RESULT_JSON ===\n{\"a\": 1}\n=== MCP_RESULT_END ===\n"
    assert parse_result(out) == {"a": 1}
    assert "raw" in parse_result("nothing")
    assert format_result({"error": "boom"}).startswith("Error: boom")


def test_preludes_have_no_py3_only_syntax():
    for src in (PROGRAM_PRELUDE, PROJECT_PRELUDE):
        assert not re.search(r"(?<![A-Za-z0-9_])f[\"']", src)
        assert "nonlocal" not in src


@pytest.mark.asyncio
async def test_convert_number_local():
    out = await server.handle_call_tool("convert_number", {"text": "0xFFFFFFFE", "size": 4})
    data = json.loads(out[0].text)
    assert data["signed"] == -2 and data["unsigned"] == 0xFFFFFFFE
    assert data["bytes_le"] == "fe ff ff ff"


@pytest.mark.asyncio
async def test_missing_required_arg_rejected_before_ghidra():
    out = await server.handle_call_tool("get_property", {"binary_name": "b"})
    assert "missing required" in out[0].text


@pytest.mark.asyncio
async def test_mcp_schema_lists_everything():
    out = await server.handle_call_tool("mcp_schema", {})
    data = json.loads(out[0].text)
    assert data["total"] == len(server.TOOLS)


@pytest.mark.parametrize("name", sorted(n for n, t in REGISTRY.items() if t.mode != "local"))
def test_jython_excepts_catch_java_throwables(name):
    """Jython's `except Exception` misses Java exceptions; bodies must use (Exception, Throwable)."""
    tool = REGISTRY[name]
    for src in (tool.body, tool.helpers):
        assert not re.search(r"except Exception\s*(as \w+)?:", src), name


def _gui_tools():
    return sorted(n for n, t in REGISTRY.items() if getattr(t, "gui_code", None))


@pytest.mark.parametrize("name", _gui_tools())
def test_gui_scripts_parse(name):
    from kawaiidra_mcp.parity.tools_gui import build_gui_script
    src = build_gui_script(REGISTRY[name].gui_code, {"address": "0x1000"})
    ast.parse(src.replace("unicode(", "str("))
    assert not re.search(r"except Exception\s*(as \w+)?:", REGISTRY[name].gui_code), name


@pytest.mark.asyncio
async def test_gui_tool_reports_bridge_unavailable(monkeypatch):
    from kawaiidra_mcp.bridge import gui_context
    gb = gui_context.get_gui_bridge()
    monkeypatch.setattr(type(gb), "is_connected", property(lambda self: False))
    monkeypatch.setattr(gb, "connect", lambda: False)
    out = await server.handle_call_tool("debugger_status", {})
    assert "GUI bridge not connected" in out[0].text


@pytest.mark.asyncio
async def test_gui_tool_round_trip_with_fake_bridge(monkeypatch):
    from kawaiidra_mcp.bridge import gui_context
    gb = gui_context.get_gui_bridge()
    seen = {}

    class FakeBridge:
        def remote_exec(self, script):
            seen["script"] = script

        def remote_eval(self, expr):
            assert expr == "_mcp_out"
            return json.dumps({"address": "00401000", "program": "x.exe"})

    monkeypatch.setattr(type(gb), "is_connected", property(lambda self: True))
    monkeypatch.setattr(gb, "_bridge", FakeBridge(), raising=False)
    out = await server.handle_call_tool("get_ui_cursor", {"type": "all"})
    assert json.loads(out[0].text)["address"] == "00401000"
    assert 'ARGS = json.loads(' in seen["script"] and "currentAddress" in seen["script"]


@pytest.mark.asyncio
async def test_session_fills_binary_name():
    from kawaiidra_mcp.parity.tools_project import SESSION, apply_session
    SESSION.update(project="p1", program="bin1", open=["bin1"])
    try:
        args = apply_session({}, {"properties": {"binary_name": {}, "project_name": {}}})
        assert args == {"binary_name": "bin1", "project_name": "p1"}
        assert apply_session({"binary_name": "x"}, {"properties": {"binary_name": {}}})["binary_name"] == "x"
    finally:
        SESSION.update(project=None, program=None, open=[])
