"""Narzędzie list_assets: inwentarz urządzeń laboratorium."""

from __future__ import annotations

from typing import get_args

from ot_mcp.data_loader import Lab
from ot_mcp.models import DeviceType, Zone


def list_assets(lab: Lab, zone: str | None = None, device_type: str | None = None) -> dict:
    """Zwraca listę urządzeń, opcjonalnie przefiltrowaną po strefie Purdue i typie.

    Logika jest w zwykłej funkcji (bez zależności od MCP), dzięki czemu testujemy ją wprost.
    Rejestracja jako narzędzie MCP jest w server.py.
    """
    valid_zones = [z.value for z in Zone]
    valid_types = list(get_args(DeviceType))
    # Walidujemy wejście sami, żeby błąd mówił Claude'owi, jakie wartości są dozwolone.
    if zone is not None and zone not in valid_zones:
        raise ValueError(f"zone: nieznana strefa {zone!r}; dozwolone: {valid_zones}")
    if device_type is not None and device_type not in valid_types:
        raise ValueError(f"device_type: nieznany typ {device_type!r}; dozwolone: {valid_types}")

    selected = [
        a
        for a in lab.assets
        if (zone is None or a.zone.value == zone)
        and (device_type is None or a.device_type == device_type)
    ]
    return {"count": len(selected), "assets": [a.model_dump(mode="json") for a in selected]}
