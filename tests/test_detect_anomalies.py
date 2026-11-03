"""Testy narzędzia detect_anomalies na pełnym scenariuszu z data/."""

import json

import pytest

from ot_mcp.data_loader import Lab, load_lab
from ot_mcp.tools.anomalies import detect_anomalies

ATTACKER_IP = "172.16.40.10"


@pytest.fixture(scope="module")
def lab():
    return load_lab()


def by_rule(result):
    grouped = {}
    for anomaly in result["anomalies"]:
        grouped.setdefault(anomaly["rule_id"], []).append(anomaly)
    return grouped


def test_scenario_phase_1_scan_is_detected(lab):
    [scan] = by_rule(detect_anomalies(lab, hours=12))["R2"]
    assert scan["src_asset"] == "JUMP-01"
    assert len(scan["targets"]) >= 40


def test_scenario_phase_2_unauthorized_and_out_of_range_writes_are_detected(lab):
    rules = by_rule(detect_anomalies(lab, hours=12))
    [unauthorized] = rules["R1"]
    assert (unauthorized["src_asset"], unauthorized["targets"]) == ("JUMP-01", ["PLC-02"])
    assert unauthorized["event_count"] == 4
    [out_of_range] = rules["R4"]
    assert out_of_range["severity"] == "critical"
    assert set(out_of_range["details"]["observed_values"]) == {9999, 65535}


def test_scenario_phase_3_diagnostic_function_code_is_detected(lab):
    codes = {a["details"]["function_code"] for a in by_rule(detect_anomalies(lab, hours=12))["R3"]}
    assert 8 in codes


def test_no_false_positives_on_baseline_traffic(lab):
    # te same dane, ale bez zdarzeń atakującego: spokojny zakład nie może dawać alarmów
    baseline = [e for e in lab.events if str(e.src_ip) != ATTACKER_IP]
    calm = Lab(lab.assets, baseline, lab.policy, lab.reference_time)
    assert detect_anomalies(calm, hours=12)["anomalies"] == []


def test_every_anomaly_originates_from_the_attacker(lab):
    anomalies = detect_anomalies(lab, hours=12)["anomalies"]
    assert {a["src_asset"] for a in anomalies} == {"JUMP-01"}


def test_short_window_only_sees_recent_phase(lab):
    result = detect_anomalies(lab, hours=1)
    assert set(by_rule(result)) == {"R3"}
    assert {a["details"]["function_code"] for a in result["anomalies"]} == {8}


def test_window_of_two_hours_includes_scan_and_writes(lab):
    assert set(by_rule(detect_anomalies(lab, hours=2))) == {"R1", "R2", "R3", "R4"}


def test_default_window_covers_whole_attack(lab):
    default = detect_anomalies(lab)
    full = detect_anomalies(lab, hours=12)
    assert [a["anomaly_id"] for a in default["anomalies"]] == [
        a["anomaly_id"] for a in full["anomalies"]
    ]


def test_anomalies_are_sorted_most_severe_first(lab):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    severities = [order[a["severity"]] for a in detect_anomalies(lab, hours=12)["anomalies"]]
    assert severities == sorted(severities)
    assert detect_anomalies(lab, hours=12)["anomalies"][0]["severity"] == "critical"


def test_anomaly_ids_are_unique_and_evidence_exists(lab):
    result = detect_anomalies(lab, hours=12)
    ids = [a["anomaly_id"] for a in result["anomalies"]]
    assert len(ids) == len(set(ids))
    known = {e.event_id for e in lab.events}
    for anomaly in result["anomalies"]:
        assert anomaly["evidence_event_ids"], anomaly["anomaly_id"]
        assert set(anomaly["evidence_event_ids"]) <= known


def test_result_summary_fields(lab):
    result = detect_anomalies(lab, hours=12)
    assert result["window_hours"] == 12
    assert result["events_analyzed"] == len(lab.events)
    assert result["anomaly_count"] == len(result["anomalies"])


def test_result_is_json_serializable(lab):
    json.dumps(detect_anomalies(lab, hours=12))


@pytest.mark.parametrize("hours", [0, -3, 169])
def test_invalid_hours_rejected(lab, hours):
    with pytest.raises(ValueError, match="hours"):
        detect_anomalies(lab, hours=hours)
