"""Reguły detekcji anomalii w ruchu Modbus.

Każda reguła to osobna, czysta funkcja: dostaje laboratorium (polityka, urządzenia) i listę
zdarzeń z okna czasowego, a zwraca listę anomalii. Dzięki temu da się ją testować na kilku
ręcznie zbudowanych zdarzeniach, bez plików JSON.

Identyfikatory reguł (R1-R4) są używane dalej przez map_to_attack_ics.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import timedelta
from ipaddress import IPv4Address

from ot_mcp.data_loader import Lab
from ot_mcp.modbus import function_name
from ot_mcp.models import Anomaly, ModbusEvent, Severity

MAX_EVIDENCE = 50  # tyle id zdarzeń dołączamy do jednej anomalii (reszta w event_count)

# R2: ile różnych celów w jednej „serii" uznajemy za skan i jak długa przerwa kończy serię
SCAN_MIN_TARGETS = 10
SCAN_MAX_GAP = timedelta(minutes=5)

# R3: opisy i waga najczęstszych nietypowych kodów funkcji; reszta dostaje wagę „medium"
_FC_SEVERITY: dict[int, Severity] = {8: "high"}
_FC_HINT = {
    8: "Modbus diagnostics: can restart communications or force listen-only mode (DoS risk)",
    17: "Report Server ID: device fingerprinting",
    43: "Read Device Identification: device fingerprinting",
}


def _label(lab: Lab, ip) -> str:
    """Nazwa urządzenia (asset_id), a gdy nie jest znane, jego adres IP."""
    asset = lab.asset_by_ip(str(ip))
    return asset.asset_id if asset else str(ip)


def _anomaly(
    lab: Lab,
    *,
    rule_id: str,
    key: str,
    title: str,
    severity: Severity,
    description: str,
    events: Sequence[ModbusEvent],
    details: dict | None = None,
) -> Anomaly:
    """Składa anomalię z grupy zdarzeń o wspólnym nadawcy."""
    ordered = sorted(events, key=lambda e: e.timestamp)
    src_ip = ordered[0].src_ip
    src = lab.asset_by_ip(str(src_ip))
    # cele posortowane numerycznie po IP (a nie alfabetycznie jako tekst)
    dst_ips: list[IPv4Address] = sorted({e.dst_ip for e in ordered})
    return Anomaly(
        anomaly_id=f"{rule_id}:{key}",
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        src_ip=src_ip,
        src_asset=src.asset_id if src else None,
        targets=[_label(lab, ip) for ip in dst_ips],
        first_seen=ordered[0].timestamp,
        last_seen=ordered[-1].timestamp,
        event_count=len(ordered),
        evidence_event_ids=[e.event_id for e in ordered[:MAX_EVIDENCE]],
        details=details or {},
    )


def unauthorized_write(lab: Lab, events: Sequence[ModbusEvent]) -> list[Anomaly]:
    """R1: zapis do urządzenia z hosta, którego polityka nie wymienia jako uprawnionego."""
    groups: dict[tuple, list[ModbusEvent]] = defaultdict(list)
    for e in events:
        dst = lab.asset_by_ip(str(e.dst_ip))
        if not e.is_write or dst is None:
            continue  # cel spoza laboratorium nie podlega naszej polityce
        src = lab.asset_by_ip(str(e.src_ip))
        allowed = lab.policy.authorized_writers.get(dst.asset_id, [])
        if src is None or src.asset_id not in allowed:
            groups[(e.src_ip, e.dst_ip)].append(e)

    result = []
    for (src_ip, dst_ip), group in groups.items():
        src, dst = _label(lab, src_ip), _label(lab, dst_ip)
        allowed = lab.policy.authorized_writers.get(dst, [])
        result.append(
            _anomaly(
                lab,
                rule_id="R1",
                key=f"{src}->{dst}",
                title="Write from unauthorized host",
                severity="high",
                description=(
                    f"{src} sent {len(group)} write request(s) to {dst}, but is not an "
                    f"authorized writer for it (authorized: {allowed or 'nobody'})."
                ),
                events=group,
                details={"authorized_writers": allowed},
            )
        )
    return result


def network_scan(
    lab: Lab,
    events: Sequence[ModbusEvent],
    *,
    min_targets: int = SCAN_MIN_TARGETS,
    max_gap: timedelta = SCAN_MAX_GAP,
) -> list[Anomaly]:
    """R2: jeden host kontaktuje wiele różnych celów w krótkiej serii (skan sieci).

    Ograniczenie: bardzo powolny skan (rzadziej niż jedna sonda na `max_gap`) nie zostanie
    wykryty. To świadomy kompromis prostych reguł, do rozwinięcia w kolejnych wersjach.
    """
    by_src: dict[IPv4Address, list[ModbusEvent]] = defaultdict(list)
    for e in events:
        by_src[e.src_ip].append(e)

    result = []
    for src_ip, src_events in by_src.items():
        src_events.sort(key=lambda e: e.timestamp)
        # dzielimy zdarzenia nadawcy na serie: nowa seria zaczyna się po przerwie > max_gap
        bursts: list[list[ModbusEvent]] = [[src_events[0]]]
        for e in src_events[1:]:
            if e.timestamp - bursts[-1][-1].timestamp > max_gap:
                bursts.append([])
            bursts[-1].append(e)

        for burst in bursts:
            targets = {e.dst_ip for e in burst}
            if len(targets) < min_targets:
                continue
            src = _label(lab, src_ip)
            timed_out = sum(1 for e in burst if e.status == "timeout")
            stamp = burst[0].timestamp.strftime("%Y-%m-%dT%H:%MZ")
            result.append(
                _anomaly(
                    lab,
                    rule_id="R2",
                    key=f"{src}@{stamp}",
                    title="Network scan",
                    severity="medium",
                    description=(
                        f"{src} contacted {len(targets)} different hosts within a short burst "
                        f"({len(burst)} requests, {timed_out} timed out): typical of a scan."
                    ),
                    events=burst,
                    details={
                        "unique_targets": len(targets),
                        "timed_out": timed_out,
                        "function_codes": sorted({e.function_code for e in burst}),
                    },
                )
            )
    return result


def unusual_function_code(lab: Lab, events: Sequence[ModbusEvent]) -> list[Anomaly]:
    """R3: kod funkcji spoza listy spodziewanej w normalnym ruchu (policy.common_function_codes)."""
    common = set(lab.policy.common_function_codes)
    groups: dict[tuple, list[ModbusEvent]] = defaultdict(list)
    for e in events:
        if e.function_code not in common:
            groups[(e.src_ip, e.function_code)].append(e)

    result = []
    for (src_ip, fc), group in groups.items():
        src = _label(lab, src_ip)
        hint = _FC_HINT.get(fc, "Function code outside the lab baseline")
        result.append(
            _anomaly(
                lab,
                rule_id="R3",
                key=f"{src}:FC{fc}",
                title="Unusual Modbus function code",
                severity=_FC_SEVERITY.get(fc, "medium"),
                description=(
                    f"{src} used function code {fc} ({function_name(fc)}) {len(group)} time(s). "
                    f"{hint}."
                ),
                events=group,
                details={"function_code": fc, "function_name": function_name(fc)},
            )
        )
    return result


def out_of_range_write(lab: Lab, events: Sequence[ModbusEvent]) -> list[Anomaly]:
    """R4: zapisywana wartość leży poza zakresem dozwolonym dla rejestru (policy.register_limits).

    Dotyczy także hostów uprawnionych: niebezpieczna wartość jest niebezpieczna niezależnie od
    nadawcy. Dla zapisu wielu rejestrów (FC 15/16) znamy tylko pierwszą wartość.
    """
    groups: dict[tuple, list[ModbusEvent]] = defaultdict(list)
    limits_of = {}
    for e in events:
        if not e.is_write or e.value is None or e.register_address is None:
            continue
        dst = lab.asset_by_ip(str(e.dst_ip))
        if dst is None:
            continue
        limit = lab.policy.register_limits.get(dst.asset_id, {}).get(e.register_address)
        if limit is None or limit.min <= e.value <= limit.max:
            continue
        key = (e.src_ip, e.dst_ip, e.register_address)
        groups[key].append(e)
        limits_of[key] = limit

    result = []
    for key, group in groups.items():
        src_ip, dst_ip, register = key
        src, dst, limit = _label(lab, src_ip), _label(lab, dst_ip), limits_of[key]
        values = sorted({e.value for e in group})
        result.append(
            _anomaly(
                lab,
                rule_id="R4",
                key=f"{src}->{dst}:reg{register}",
                title="Write outside allowed register range",
                severity="critical",
                description=(
                    f"{src} wrote {values} to register {register} ({limit.name}) of {dst}; "
                    f"allowed range is {limit.min}..{limit.max}."
                ),
                events=group,
                details={
                    "register_address": register,
                    "register_name": limit.name,
                    "allowed_range": [limit.min, limit.max],
                    "observed_values": values,
                },
            )
        )
    return result


Rule = Callable[[Lab, Sequence[ModbusEvent]], list[Anomaly]]

# Kolejność uruchamiania. Dodanie nowej reguły = napisanie funkcji i dopisanie jej tutaj.
ALL_RULES: tuple[Rule, ...] = (
    unauthorized_write,
    network_scan,
    unusual_function_code,
    out_of_range_write,
)
