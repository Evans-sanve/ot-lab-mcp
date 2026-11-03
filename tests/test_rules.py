"""Testy reguł detekcji na małym, ręcznie zbudowanym laboratorium.

Każda reguła ma przypadek pozytywny (alarm) i negatywny (cisza), żeby widać było, co ją
uruchamia, a czego nie. Reguły dostają listę zdarzeń, więc nie potrzebują plików JSON.
"""

import itertools
from datetime import datetime, timedelta, timezone

from ot_mcp.data_loader import Lab
from ot_mcp.detection.rules import (
    network_scan,
    out_of_range_write,
    unauthorized_write,
    unusual_function_code,
)
from ot_mcp.models import Asset, Meta, ModbusEvent, PolicyFile, RegisterLimit, Zone

BASE = datetime(2026, 11, 3, 10, 0, 0, tzinfo=timezone.utc)
IP = {
    "HMI-X": "192.168.20.21",
    "JUMP-X": "172.16.40.10",
    "PLC-X": "192.168.10.12",
    "PLC-Y": "192.168.10.13",
}
_ids = itertools.count(1)


def _asset(aid, dtype, zone):
    return Asset(
        asset_id=aid, hostname=f"{aid.lower()}.ot-lab.invalid", device_type=dtype, ip=IP[aid],
        vendor="Acme", model="M", firmware="1", zone=zone,
    )


def make_lab(events=()):
    meta = Meta(synthetic=True, generator="test", seed=0)
    policy = PolicyFile(
        meta=meta,
        common_function_codes=[1, 2, 3, 4, 5, 6, 15, 16],
        authorized_writers={"PLC-X": ["HMI-X"]},  # PLC-Y: nikt nie ma prawa pisać
        register_limits={"PLC-X": {0: RegisterLimit(name="valve_pct", min=0, max=100)}},
    )
    assets = [
        _asset("HMI-X", "hmi", Zone.L2_SUPERVISORY),
        _asset("JUMP-X", "jump_host", Zone.DMZ),
        _asset("PLC-X", "plc", Zone.L1_CONTROL),
        _asset("PLC-Y", "plc", Zone.L1_CONTROL),
    ]
    return Lab(assets, list(events), policy, BASE + timedelta(hours=1))


def ev(src, dst, fc=3, seconds=0, **kw):
    return ModbusEvent(
        event_id=f"evt-{next(_ids):06d}",
        timestamp=BASE + timedelta(seconds=seconds),
        src_ip=IP.get(src, src),
        dst_ip=IP.get(dst, dst),
        src_port=50000,
        unit_id=1,
        function_code=fc,
        status=kw.pop("status", "ok"),
        **kw,
    )


# --- R1: zapis z nieautoryzowanego hosta -----------------------------------------------------


def test_r1_flags_write_from_unauthorized_host():
    events = [ev("JUMP-X", "PLC-X", fc=6, register_address=0, value=50)]
    [a] = unauthorized_write(make_lab(events), events)
    assert a.rule_id == "R1"
    assert a.severity == "high"
    assert a.src_asset == "JUMP-X"
    assert a.targets == ["PLC-X"]
    assert a.evidence_event_ids == [events[0].event_id]


def test_r1_ignores_write_from_authorized_host():
    events = [ev("HMI-X", "PLC-X", fc=6, register_address=0, value=50)]
    assert unauthorized_write(make_lab(events), events) == []


def test_r1_ignores_reads_from_unauthorized_host():
    events = [ev("JUMP-X", "PLC-X", fc=3, register_address=0, quantity=2)]
    assert unauthorized_write(make_lab(events), events) == []


def test_r1_groups_writes_of_the_same_pair_into_one_anomaly():
    events = [
        ev("JUMP-X", "PLC-X", fc=6, seconds=0, register_address=0, value=1),
        ev("JUMP-X", "PLC-X", fc=16, seconds=30, register_address=0, quantity=2, value=2),
    ]
    [a] = unauthorized_write(make_lab(events), events)
    assert a.event_count == 2
    assert a.first_seen < a.last_seen


def test_r1_flags_write_to_asset_that_nobody_may_write_to():
    # PLC-Y nie ma wpisu w authorized_writers, więc żaden zapis nie jest autoryzowany
    events = [ev("HMI-X", "PLC-Y", fc=6, register_address=0, value=1)]
    [a] = unauthorized_write(make_lab(events), events)
    assert a.targets == ["PLC-Y"]


def test_r1_ignores_write_to_destination_outside_the_lab():
    events = [ev("JUMP-X", "192.168.99.99", fc=6, register_address=0, value=1)]
    assert unauthorized_write(make_lab(events), events) == []


# --- R2: skan sieci --------------------------------------------------------------------------


def _probes(count, spacing=3, **kw):
    return [
        ev("JUMP-X", f"192.168.10.{i}", fc=43, seconds=i * spacing, sub_function=14, **kw)
        for i in range(1, count + 1)
    ]


def test_r2_flags_burst_of_probes_to_many_targets():
    events = _probes(12)
    [a] = network_scan(make_lab(events), events)
    assert a.rule_id == "R2"
    assert a.severity == "medium"
    assert len(a.targets) == 12
    assert a.event_count == 12
    assert a.src_asset == "JUMP-X"


def test_r2_ignores_too_few_targets():
    events = _probes(9)
    assert network_scan(make_lab(events), events) == []


def test_r2_ignores_many_events_to_a_single_target():
    # zwykłe cykliczne odpytywanie: dużo zdarzeń, ale jeden cel
    events = [ev("HMI-X", "PLC-X", fc=3, seconds=i * 3) for i in range(50)]
    assert network_scan(make_lab(events), events) == []


def test_r2_ignores_slow_polling_of_many_targets():
    # 12 różnych celów, ale co 10 minut: to nie jest seria (burst)
    events = _probes(12, spacing=600)
    assert network_scan(make_lab(events), events) == []


def test_r2_reports_how_many_probes_timed_out():
    events = _probes(10)[:-3] + _probes(10, status="timeout")[-3:]
    [a] = network_scan(make_lab(events), events)
    assert a.details["timed_out"] == 3


def test_r2_two_separate_bursts_give_two_anomalies():
    first = _probes(10)
    second = [
        ev("JUMP-X", f"192.168.20.{i}", fc=43, seconds=7200 + i * 3, sub_function=14)
        for i in range(1, 11)
    ]
    anomalies = network_scan(make_lab(first + second), first + second)
    assert len(anomalies) == 2
    assert len({a.anomaly_id for a in anomalies}) == 2


# --- R3: nietypowy kod funkcji ---------------------------------------------------------------


def test_r3_flags_diagnostics_function_code():
    events = [ev("JUMP-X", "PLC-X", fc=8, sub_function=1)]
    [a] = unusual_function_code(make_lab(events), events)
    assert a.rule_id == "R3"
    assert a.severity == "high"
    assert a.details["function_code"] == 8


def test_r3_ignores_common_function_codes():
    events = [ev("HMI-X", "PLC-X", fc=fc) for fc in (1, 2, 3, 4, 5, 6, 15, 16)]
    assert unusual_function_code(make_lab(events), events) == []


def test_r3_groups_by_source_and_function_code():
    events = [
        ev("JUMP-X", "PLC-X", fc=43, seconds=1, sub_function=14),
        ev("JUMP-X", "PLC-Y", fc=43, seconds=2, sub_function=14),
        ev("JUMP-X", "PLC-X", fc=17, seconds=3),
    ]
    anomalies = unusual_function_code(make_lab(events), events)
    by_code = {a.details["function_code"]: a for a in anomalies}
    assert set(by_code) == {17, 43}
    assert by_code[43].targets == ["PLC-X", "PLC-Y"]
    assert by_code[43].event_count == 2


def test_r3_unknown_vendor_code_is_flagged_as_medium():
    events = [ev("JUMP-X", "PLC-X", fc=90)]
    [a] = unusual_function_code(make_lab(events), events)
    assert a.severity == "medium"


# --- R4: wartość zapisu poza dozwolonym zakresem ---------------------------------------------


def test_r4_flags_value_above_register_limit():
    events = [ev("HMI-X", "PLC-X", fc=6, register_address=0, value=9999)]
    [a] = out_of_range_write(make_lab(events), events)
    assert a.rule_id == "R4"
    assert a.severity == "critical"
    assert a.details["allowed_range"] == [0, 100]
    assert a.details["observed_values"] == [9999]


def test_r4_range_boundaries_are_inclusive():
    ok = [ev("HMI-X", "PLC-X", fc=6, register_address=0, value=v) for v in (0, 100)]
    assert out_of_range_write(make_lab(ok), ok) == []
    bad = [ev("HMI-X", "PLC-X", fc=6, register_address=0, value=101)]
    assert len(out_of_range_write(make_lab(bad), bad)) == 1


def test_r4_ignores_register_without_defined_limit():
    events = [ev("HMI-X", "PLC-X", fc=6, register_address=7, value=60000)]
    assert out_of_range_write(make_lab(events), events) == []


def test_r4_ignores_reads_and_writes_without_value():
    events = [
        ev("HMI-X", "PLC-X", fc=3, register_address=0, value=9999),
        ev("HMI-X", "PLC-X", fc=6, register_address=0),
    ]
    assert out_of_range_write(make_lab(events), events) == []


def test_r4_applies_to_authorized_hosts_too():
    # HMI-X ma prawo pisać, ale wartość i tak jest niebezpieczna: R1 milczy, R4 alarmuje
    events = [ev("HMI-X", "PLC-X", fc=6, register_address=0, value=500)]
    lab = make_lab(events)
    assert unauthorized_write(lab, events) == []
    assert len(out_of_range_write(lab, events)) == 1
