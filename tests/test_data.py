"""Testy wygenerowanych plików JSON: poprawność, spójność i zawarty w nich scenariusz ataku."""

import ipaddress
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest

from ot_mcp.models import AssetsFile, EventsFile, PolicyFile

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# Host w DMZ, z którego w danych wychodzi cały atak (patrz scripts/generate_data.py).
ATTACKER_IP = "172.16.40.10"


def _load(name):
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def assets():
    return AssetsFile.model_validate(_load("assets.json"))


@pytest.fixture(scope="module")
def events():
    return EventsFile.model_validate(_load("modbus_events.json"))


@pytest.fixture(scope="module")
def policy():
    return PolicyFile.model_validate(_load("policy.json"))


# --- aktywa ---------------------------------------------------------------------------------


def test_assets_have_unique_ids_and_ips(assets):
    ids = [a.asset_id for a in assets.assets]
    ips = [str(a.ip) for a in assets.assets]
    assert len(ids) == len(set(ids))
    assert len(ips) == len(set(ips))


def test_assets_cover_required_device_types(assets):
    types = {a.device_type for a in assets.assets}
    assert {"plc", "hmi", "switch", "engineering_workstation"} <= types


def test_assets_span_multiple_purdue_zones(assets):
    levels = {a.purdue_level for a in assets.assets}
    assert {1, 2, 3, 3.5} <= levels


def test_assets_use_only_private_addresses_and_invalid_hostnames(assets):
    for asset in assets.assets:
        assert ipaddress.ip_address(asset.ip).is_private
        # .invalid to zarezerwowana TLD (RFC 2606): nazwa nigdy nie wskaże prawdziwego hosta.
        assert asset.hostname.endswith(".invalid")


def test_attacker_is_in_dmz(assets):
    attacker = next(a for a in assets.assets if str(a.ip) == ATTACKER_IP)
    assert attacker.purdue_level == 3.5


# --- zdarzenia ------------------------------------------------------------------------------


def test_events_are_sorted_with_unique_ids(events):
    stamps = [e.timestamp for e in events.events]
    assert stamps == sorted(stamps)
    ids = [e.event_id for e in events.events]
    assert len(ids) == len(set(ids))


def test_events_fall_in_window_before_reference_time(events):
    newest = events.events[-1].timestamp
    oldest = events.events[0].timestamp
    assert newest <= events.reference_time
    assert events.reference_time - oldest <= timedelta(hours=13)


def test_events_have_a_few_hundred_records(events):
    assert 200 <= len(events.events) <= 1500


def test_event_sources_are_known_assets(assets, events):
    known = {str(a.ip) for a in assets.assets}
    assert {str(e.src_ip) for e in events.events} <= known


def test_event_destinations_are_private(events):
    for event in events.events:
        assert ipaddress.ip_address(event.dst_ip).is_private


# --- polityka -------------------------------------------------------------------------------


def test_policy_references_existing_assets(assets, policy):
    ids = {a.asset_id for a in assets.assets}
    assert set(policy.authorized_writers) <= ids
    for writers in policy.authorized_writers.values():
        assert set(writers) <= ids
    assert set(policy.register_limits) <= ids


# --- wbudowany scenariusz ataku -------------------------------------------------------------
# Test zna prawdę o danych (kto jest atakującym), ale same dane nie mają pola "złośliwe":
# to zadanie reguł detekcji, a nie czytania etykiety.


def test_attacker_activity_is_confined_to_last_hours(events):
    own = [e for e in events.events if str(e.src_ip) == ATTACKER_IP]
    assert own, "w danych musi być aktywność atakującego"
    assert min(e.timestamp for e in own) >= events.reference_time - timedelta(hours=3)


def test_scenario_phase_1_network_scan(events):
    probes = [e for e in events.events if str(e.src_ip) == ATTACKER_IP]
    targets = {str(e.dst_ip) for e in probes}
    assert len(targets) >= 20


def test_scenario_phase_2_unauthorized_writes(events, policy, assets):
    id_by_ip = {str(a.ip): a.asset_id for a in assets.assets}
    writes = [e for e in events.events if str(e.src_ip) == ATTACKER_IP and e.is_write]
    assert len(writes) >= 2
    for write in writes:
        target = id_by_ip[str(write.dst_ip)]
        assert "JUMP-01" not in policy.authorized_writers.get(target, [])
    # co najmniej jeden zapis ma wartość poza dozwolonym zakresem rejestru
    out_of_range = 0
    for write in writes:
        limit = policy.register_limits[id_by_ip[str(write.dst_ip)]][write.register_address]
        if not limit.min <= write.value <= limit.max:
            out_of_range += 1
    assert out_of_range >= 1


def test_scenario_phase_3_unusual_function_code(events, policy):
    codes = {e.function_code for e in events.events if str(e.src_ip) == ATTACKER_IP}
    assert codes - set(policy.common_function_codes), "brak nietypowego kodu funkcji"


def test_baseline_traffic_uses_only_common_function_codes(events, policy):
    baseline = [e for e in events.events if str(e.src_ip) != ATTACKER_IP]
    used = Counter(e.function_code for e in baseline)
    assert set(used) <= set(policy.common_function_codes)


def test_baseline_writes_come_only_from_authorized_hosts(events, policy, assets):
    id_by_ip = {str(a.ip): a.asset_id for a in assets.assets}
    for event in events.events:
        if str(event.src_ip) == ATTACKER_IP or not event.is_write:
            continue
        src = id_by_ip[str(event.src_ip)]
        dst = id_by_ip[str(event.dst_ip)]
        assert src in policy.authorized_writers[dst]
        limit = policy.register_limits[dst][event.register_address]
        assert limit.min <= event.value <= limit.max
