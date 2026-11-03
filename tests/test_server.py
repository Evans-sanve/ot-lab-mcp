"""Testy serwera MCP: w pamięci (szybkie) oraz przez prawdziwe stdio (końcowa pewność)."""

import asyncio
import sys

import pytest
from mcp import Client, StdioServerParameters

from ot_mcp.server import mcp_server

TOOLS = {"list_assets", "get_modbus_events", "detect_anomalies", "map_to_attack_ics"}


def run(coro):
    return asyncio.run(coro)


async def _call(name, arguments=None):
    async with Client(mcp_server) as client:
        return await client.call_tool(name, arguments or {})


def call(name, arguments=None):
    return run(_call(name, arguments))


async def _list_tools():
    async with Client(mcp_server) as client:
        return (await client.list_tools()).tools


@pytest.fixture(scope="module")
def tools():
    return run(_list_tools())


# --- definicje narzędzi ----------------------------------------------------------------------


def test_server_exposes_exactly_the_four_mvp_tools(tools):
    assert {t.name for t in tools} == TOOLS


def test_all_tools_are_declared_read_only_and_closed_world(tools):
    # Zasada projektu nr 2: serwer nic nie zmienia i nie wychodzi do sieci. Klient (Claude)
    # widzi to w adnotacjach i może pominąć pytanie o zgodę.
    for tool in tools:
        assert tool.annotations.read_only_hint is True, tool.name
        assert tool.annotations.destructive_hint is False, tool.name
        assert tool.annotations.open_world_hint is False, tool.name


def test_every_tool_and_parameter_is_documented(tools):
    for tool in tools:
        assert tool.description and len(tool.description) > 30, tool.name
        for pname, schema in tool.input_schema.get("properties", {}).items():
            assert schema.get("description"), f"{tool.name}.{pname} bez opisu"


def test_no_tool_accepts_a_file_path(tools):
    # Zasada projektu nr 3: żadnych ścieżek od użytkownika.
    banned = ("path", "file", "dir", "url")
    for tool in tools:
        for pname in tool.input_schema.get("properties", {}):
            assert not any(word in pname.lower() for word in banned), f"{tool.name}.{pname}"


def test_enum_parameters_advertise_allowed_values(tools):
    schema = next(t for t in tools if t.name == "list_assets").input_schema
    # wartości enuma leżą w $defs (pole używa $ref), więc patrzymy na cały schemat
    assert "level_1_control" in str(schema)
    assert "engineering_workstation" in str(schema)


def test_server_has_instructions_describing_the_workflow():
    instructions = mcp_server._lowlevel_server.instructions
    assert "synthetic" in instructions.lower()
    for name in TOOLS:
        assert name in instructions


# --- wywołania -------------------------------------------------------------------------------


def test_list_assets_over_mcp():
    result = call("list_assets", {"device_type": "plc"})
    assert result.is_error is False
    assert result.structured_content["count"] == 3


def test_get_modbus_events_over_mcp():
    result = call("get_modbus_events", {"hours": 1, "src": "JUMP-01", "function_code": 8})
    assert result.structured_content["total_matching"] == 2


def test_detect_then_map_flow_like_claude_would_do_it():
    detected = call("detect_anomalies", {"hours": 6}).structured_content
    assert detected["anomaly_count"] >= 4
    top = detected["anomalies"][0]
    assert top["severity"] == "critical"
    mapped = call("map_to_attack_ics", {"anomaly_id": top["anomaly_id"]}).structured_content
    assert mapped["techniques"][0]["technique_id"] == "T0836"


def test_tool_error_message_reaches_the_model():
    # Zwykły ValueError byłby dla Claude'a tylko "Error executing tool"; ToolError przenosi treść.
    result = call("map_to_attack_ics", {"anomaly_id": "R1:NOBODY->NOWHERE"})
    assert result.is_error is True
    assert "detect_anomalies" in result.content[0].text


def test_bad_enum_value_is_rejected_with_readable_message():
    result = call("list_assets", {"zone": "level_9_moon"})
    assert result.is_error is True
    assert "level_1_control" in result.content[0].text


@pytest.mark.parametrize("hours", [0, 500])
def test_out_of_range_hours_is_rejected(hours):
    result = call("detect_anomalies", {"hours": hours})
    assert result.is_error is True
    assert "hours" in result.content[0].text


# --- prawdziwy transport stdio ---------------------------------------------------------------


def test_real_stdio_process_serves_tools():
    """Uruchamia serwer jako osobny proces (tak jak zrobi to Claude Desktop/Code)."""

    async def scenario():
        params = StdioServerParameters(command=sys.executable, args=["-m", "ot_mcp"])
        async with Client(params, read_timeout_seconds=60) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            result = await client.call_tool("list_assets", {})
            return names, result

    names, result = run(scenario())
    assert names == TOOLS
    assert result.structured_content["count"] == 13
