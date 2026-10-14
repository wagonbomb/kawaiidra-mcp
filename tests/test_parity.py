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
