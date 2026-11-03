"""Testy narzędzia list_assets (logika bez warstwy MCP)."""

import json

import pytest

from ot_mcp.data_loader import load_lab
from ot_mcp.tools.assets import list_assets


@pytest.fixture(scope="module")
def lab():
    return load_lab()


def ids(result):
    return {a["asset_id"] for a in result["assets"]}


def test_no_filter_returns_all_assets(lab):
    result = list_assets(lab)
    assert result["count"] == 13 == len(result["assets"])


def test_asset_entry_has_fields_claude_needs(lab):
    plc = next(a for a in list_assets(lab)["assets"] if a["asset_id"] == "PLC-02")
    assert plc["ip"] == "192.168.10.12"
    assert plc["vendor"] == "Acme Controls"
    assert plc["firmware"] == "1.9.0"
    assert plc["zone"] == "level_1_control"
    assert plc["purdue_level"] == 1


def test_result_is_json_serializable(lab):
    json.dumps(list_assets(lab))


def test_filter_by_device_type(lab):
    assert ids(list_assets(lab, device_type="plc")) == {"PLC-01", "PLC-02", "PLC-03"}


def test_filter_by_zone(lab):
    assert ids(list_assets(lab, zone="level_3_5_dmz")) == {"FW-01", "JUMP-01"}


def test_filters_combine_with_and(lab):
    assert ids(list_assets(lab, zone="level_1_control", device_type="switch")) == {"SW-CTRL-01"}


def test_filters_with_no_match_give_empty_list(lab):
    result = list_assets(lab, zone="level_4_enterprise", device_type="plc")
    assert result == {"count": 0, "assets": []}


def test_unknown_zone_lists_valid_values(lab):
    with pytest.raises(ValueError, match="level_1_control"):
        list_assets(lab, zone="level_9_moon")


def test_unknown_device_type_lists_valid_values(lab):
    with pytest.raises(ValueError, match="plc"):
        list_assets(lab, device_type="toaster")
