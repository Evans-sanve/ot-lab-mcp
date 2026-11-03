"""Testy mapowania anomalii na MITRE ATT&CK for ICS."""

import json
import re

import pytest

from ot_mcp.attack_ics import TECHNIQUES, techniques_for_anomaly, techniques_for_rule
from ot_mcp.data_loader import load_lab
from ot_mcp.detection.rules import ALL_RULES
from ot_mcp.tools.anomalies import detect_anomalies
from ot_mcp.tools.attack_mapping import map_to_attack_ics

RULE_IDS = ["R1", "R2", "R3", "R4"]


@pytest.fixture(scope="module")
def lab():
    return load_lab()


def ids(mappings):
    return {m.technique_id for m in mappings}


# --- katalog technik -------------------------------------------------------------------------


def test_catalog_ids_have_valid_format_and_metadata():
    assert TECHNIQUES, "katalog nie może być pusty"
    for tid, tech in TECHNIQUES.items():
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), tid
        assert tech.technique_id == tid
        assert tech.name and tech.tactics
        # adres podtechnik ma postać /techniques/T1692/001/
        assert tech.url == f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def test_every_rule_in_the_engine_has_a_mapping():
    assert len(ALL_RULES) == len(RULE_IDS)
    for rule_id in RULE_IDS:
        assert techniques_for_rule(rule_id), rule_id


def test_all_mapped_techniques_exist_in_catalog():
    for rule_id in RULE_IDS:
        for mapping in techniques_for_rule(rule_id):
            assert mapping.technique_id in TECHNIQUES


# --- mapowanie reguł i anomalii --------------------------------------------------------------


def test_rule_level_mappings():
    assert ids(techniques_for_rule("R1")) == {"T1692.001"}
    assert ids(techniques_for_rule("R2")) == {"T0846"}
    assert ids(techniques_for_rule("R4")) == {"T0836"}
    assert ids(techniques_for_rule("R3")) == {"T0814", "T0888"}


@pytest.mark.parametrize(
    ("function_code", "expected"),
    [(8, {"T0814"}), (17, {"T0888"}), (43, {"T0888"})],
)
def test_r3_mapping_depends_on_function_code(function_code, expected):
    anomaly = {"rule_id": "R3", "details": {"function_code": function_code}}
    assert ids(techniques_for_anomaly(anomaly)) == expected


def test_r3_unknown_function_code_has_no_confident_mapping():
    # lepiej uczciwie powiedzieć „brak mapowania" niż zgadywać technikę
    anomaly = {"rule_id": "R3", "details": {"function_code": 90}}
    assert techniques_for_anomaly(anomaly) == []


def test_denial_of_service_mapping_is_medium_confidence():
    [mapping] = techniques_for_anomaly({"rule_id": "R3", "details": {"function_code": 8}})
    assert mapping.confidence == "medium"


def test_unknown_rule_raises():
    with pytest.raises(ValueError, match="R1"):
        techniques_for_rule("R9")


# --- narzędzie map_to_attack_ics -------------------------------------------------------------


def test_tool_maps_anomaly_by_id(lab):
    result = map_to_attack_ics(lab, anomaly_id="R1:JUMP-01->PLC-02")
    assert result["anomaly"]["rule_id"] == "R1"
    [tech] = result["techniques"]
    assert tech["technique_id"] == "T1692.001"
    assert tech["name"] == "Unauthorized Message: Command Message"
    assert "Impair Process Control" in tech["tactics"]
    assert tech["url"].startswith("https://attack.mitre.org/")
    assert tech["confidence"] in {"high", "medium"}
    assert tech["rationale"]


def test_tool_maps_every_detected_anomaly(lab):
    for anomaly in detect_anomalies(lab, hours=12)["anomalies"]:
        result = map_to_attack_ics(lab, anomaly_id=anomaly["anomaly_id"])
        assert result["techniques"], anomaly["anomaly_id"]


def test_tool_distinguishes_function_codes_within_r3(lab):
    fc8 = map_to_attack_ics(lab, anomaly_id="R3:JUMP-01:FC8")
    fc43 = map_to_attack_ics(lab, anomaly_id="R3:JUMP-01:FC43")
    assert [t["technique_id"] for t in fc8["techniques"]] == ["T0814"]
    assert [t["technique_id"] for t in fc43["techniques"]] == ["T0888"]


def test_tool_maps_whole_rule(lab):
    result = map_to_attack_ics(lab, rule_id="R3")
    assert result["anomaly"] is None
    assert {t["technique_id"] for t in result["techniques"]} == {"T0814", "T0888"}
    assert all(t["applies_to"] for t in result["techniques"])


def test_tool_unknown_anomaly_suggests_detect_anomalies(lab):
    with pytest.raises(ValueError, match="detect_anomalies"):
        map_to_attack_ics(lab, anomaly_id="R1:NOBODY->NOWHERE")


def test_tool_unknown_rule_lists_valid_rules(lab):
    with pytest.raises(ValueError, match="R4"):
        map_to_attack_ics(lab, rule_id="R9")


def test_tool_requires_exactly_one_argument(lab):
    with pytest.raises(ValueError, match="anomaly_id"):
        map_to_attack_ics(lab)
    with pytest.raises(ValueError, match="anomaly_id"):
        map_to_attack_ics(lab, anomaly_id="R1:JUMP-01->PLC-02", rule_id="R1")


def test_tool_result_is_json_serializable_and_cites_source(lab):
    result = map_to_attack_ics(lab, rule_id="R2")
    json.dumps(result)
    assert "attack.mitre.org" in result["source"]
