"""Narzędzie get_modbus_events: zdarzenia Modbus z okna czasowego, z filtrami."""

from __future__ import annotations

import ipaddress
from datetime import timedelta

from ot_mcp.data_loader import Lab
from ot_mcp.modbus import function_name
from ot_mcp.models import ModbusEvent

MAX_HOURS = 168  # tydzień; dane i tak obejmują ok. 12 godzin
MAX_LIMIT = 1000


def _resolve_endpoint(lab: Lab, value: str, param: str) -> str:
    """Zamienia asset_id (np. "PLC-02") albo adres IP na znormalizowany adres IP."""
    asset = lab.asset_by_id(value)
    if asset is not None:
        return str(asset.ip)
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        raise ValueError(
            f"{param}: {value!r} to ani znane asset_id, ani poprawny adres IPv4"
        ) from None


def _describe(lab: Lab, event: ModbusEvent) -> dict:
    """Zdarzenie wzbogacone o informacje, które ułatwiają Claude'owi analizę."""
    src = lab.asset_by_ip(str(event.src_ip))
    dst = lab.asset_by_ip(str(event.dst_ip))
    data = event.model_dump(mode="json", exclude_none=True)
    data.update(
        function_name=function_name(event.function_code),
        is_write=event.is_write,
        src_asset=src.asset_id if src else None,
        dst_asset=dst.asset_id if dst else None,
    )
    return data


def get_modbus_events(
    lab: Lab,
    hours: float = 6,
    src: str | None = None,
    dst: str | None = None,
    function_code: int | None = None,
    limit: int = 200,
) -> dict:
    """Zwraca zdarzenia Modbus z ostatnich `hours` godzin (liczonych od czasu odniesienia danych).

    Filtry łączą się przez AND. Gdy wyników jest więcej niż `limit`, zwracamy NAJNOWSZE
    `limit` zdarzeń (posortowane chronologicznie) i ustawiamy `truncated`.
    """
    if not 0 < hours <= MAX_HOURS:
        raise ValueError(f"hours: musi być w zakresie (0, {MAX_HOURS}], podano {hours}")
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit: musi być w zakresie [1, {MAX_LIMIT}], podano {limit}")
    if function_code is not None and not 1 <= function_code <= 127:
        raise ValueError(f"function_code: musi być w zakresie [1, 127], podano {function_code}")

    src_ip = _resolve_endpoint(lab, src, "src") if src is not None else None
    dst_ip = _resolve_endpoint(lab, dst, "dst") if dst is not None else None

    start = lab.reference_time - timedelta(hours=hours)
    matching = [
        e
        for e in lab.events
        if start <= e.timestamp <= lab.reference_time
        and (src_ip is None or str(e.src_ip) == src_ip)
        and (dst_ip is None or str(e.dst_ip) == dst_ip)
        and (function_code is None or e.function_code == function_code)
    ]
    matching.sort(key=lambda e: e.timestamp)
    shown = matching[-limit:]
    return {
        "reference_time": lab.reference_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_hours": hours,
        "total_matching": len(matching),
        "returned": len(shown),
        "truncated": len(matching) > len(shown),
        "events": [_describe(lab, e) for e in shown],
    }
