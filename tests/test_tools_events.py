"""Testy narzędzia get_modbus_events (logika bez warstwy MCP)."""

import json
from datetime import timedelta

import pytest

from ot_mcp.data_loader import load_lab
from ot_mcp.tools.events import get_modbus_events

ATTACKER_IP = "172.16.40.10"


@pytest.fixture(scope="module")
def lab():
    return load_lab()


def test_default_window_is_last_6_hours(lab):
    result = get_modbus_events(lab, limit=1000)
    start = lab.reference_time - timedelta(hours=6)
    expected = [e for e in lab.events if e.timestamp >= start]
    assert result["window_hours"] == 6
    assert result["total_matching"] == len(expected)


def test_window_is_counted_from_dataset_reference_time_not_the_clock(lab):
    result = get_modbus_events(lab, hours=1, limit=1000)
    start = lab.reference_time - timedelta(hours=1)
    assert result["events"], "w ostatniej godzinie powinny być zdarzenia"
    assert all(e["timestamp"] >= start.strftime("%Y-%m-%dT%H:%M:%SZ") for e in result["events"])
    assert result["reference_time"] == "2026-11-03T12:00:00Z"


def test_events_are_in_chronological_order(lab):
    stamps = [e["timestamp"] for e in get_modbus_events(lab, hours=12, limit=1000)["events"]]
    assert stamps == sorted(stamps)


def test_filter_by_source_asset_id_equals_filter_by_ip(lab):
    by_id = get_modbus_events(lab, hours=12, src="JUMP-01", limit=1000)
    by_ip = get_modbus_events(lab, hours=12, src=ATTACKER_IP, limit=1000)
    assert by_id["events"] == by_ip["events"]
    assert by_id["total_matching"] > 20


def test_filter_by_destination(lab):
    result = get_modbus_events(lab, hours=12, dst="PLC-02", limit=1000)
    assert result["total_matching"] > 0
    assert {e["dst_asset"] for e in result["events"]} == {"PLC-02"}


def test_filter_by_function_code(lab):
    result = get_modbus_events(lab, hours=12, function_code=43, limit=1000)
    assert result["total_matching"] >= 40
    assert {e["function_code"] for e in result["events"]} == {43}


def test_filters_combine_with_and(lab):
    result = get_modbus_events(lab, hours=1, src="JUMP-01", function_code=8, limit=1000)
    assert result["total_matching"] == 2
    assert {e["function_code"] for e in result["events"]} == {8}


def test_event_is_enriched_with_names_and_flags(lab):
    event = get_modbus_events(lab, hours=12, src="JUMP-01", function_code=43, limit=1)["events"][0]
    assert event["src_asset"] == "JUMP-01"
    assert "Device Identification" in event["function_name"]
    assert event["is_write"] is False
    write = get_modbus_events(lab, hours=12, src="JUMP-01", function_code=6, limit=1)["events"][0]
    assert write["is_write"] is True


def test_event_for_unknown_destination_has_no_asset_name(lab):
    # cel skanu, który nie istnieje w laboratorium (np. 192.168.10.30)
    result = get_modbus_events(lab, hours=12, dst="192.168.10.30", limit=10)
    assert result["total_matching"] == 1
    assert result["events"][0]["dst_asset"] is None


def test_limit_keeps_newest_events_and_flags_truncation(lab):
    everything = get_modbus_events(lab, hours=12, limit=1000)
    limited = get_modbus_events(lab, hours=12, limit=5)
    assert limited["returned"] == 5
    assert limited["truncated"] is True
    assert limited["total_matching"] == everything["total_matching"]
    assert limited["events"] == everything["events"][-5:]
    assert everything["truncated"] is False


def test_result_is_json_serializable(lab):
    json.dumps(get_modbus_events(lab))


@pytest.mark.parametrize("hours", [0, -1, 169])
def test_invalid_hours_rejected(lab, hours):
    with pytest.raises(ValueError, match="hours"):
        get_modbus_events(lab, hours=hours)


@pytest.mark.parametrize("limit", [0, -5, 1001])
def test_invalid_limit_rejected(lab, limit):
    with pytest.raises(ValueError, match="limit"):
        get_modbus_events(lab, limit=limit)


@pytest.mark.parametrize("code", [0, 128])
def test_invalid_function_code_rejected(lab, code):
    with pytest.raises(ValueError, match="function_code"):
        get_modbus_events(lab, function_code=code)


def test_unknown_asset_rejected(lab):
    with pytest.raises(ValueError, match="GHOST-99"):
        get_modbus_events(lab, src="GHOST-99")


def test_malformed_ip_rejected(lab):
    with pytest.raises(ValueError, match="dst"):
        get_modbus_events(lab, dst="999.1.1.1")
