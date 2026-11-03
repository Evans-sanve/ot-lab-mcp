"""Wczytywanie danych laboratorium z plików JSON.

Loader waliduje pliki (modele Pydantic) oraz spójność między nimi. Uszkodzone dane kończą się
od razu czytelnym `DataLoadError`, a nie dziwnym wynikiem w środku analizy.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ValidationError

from ot_mcp.models import Asset, AssetsFile, EventsFile, ModbusEvent, PolicyFile

# Ścieżka do danych jest stała (repo_root/data). Nie przyjmujemy jej od użytkownika narzędzi:
# zasada projektu nr 3 (brak ścieżek od użytkownika).
DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"


class DataLoadError(Exception):
    """Dane laboratorium są brakujące, uszkodzone lub niespójne."""


class Lab:
    """Całe wczytane laboratorium: urządzenia, zdarzenia, polityka i „teraz" zbioru danych."""

    def __init__(
        self,
        assets: list[Asset],
        events: list[ModbusEvent],
        policy: PolicyFile,
        reference_time: datetime,
    ):
        self.assets = assets
        self.events = events
        self.policy = policy
        self.reference_time = reference_time
        # indeksy do szybkiego wyszukiwania (urządzeń jest niewiele, ale zapytań dużo)
        self._by_id = {a.asset_id: a for a in assets}
        self._by_ip = {str(a.ip): a for a in assets}

    def asset_by_id(self, asset_id: str) -> Asset | None:
        return self._by_id.get(asset_id)

    def asset_by_ip(self, ip: str) -> Asset | None:
        return self._by_ip.get(str(ip))


def _read(data_dir: Path, name: str, model: type[BaseModel]):
    """Czyta jeden plik JSON i waliduje go modelem; każdy błąd opakowuje w DataLoadError."""
    path = data_dir / name
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DataLoadError(f"{name}: brak pliku w {data_dir}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise DataLoadError(f"{name}: nie można wczytać pliku JSON ({exc})") from exc
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise DataLoadError(f"{name}: nieprawidłowe dane ({exc})") from exc


def _duplicates(values: list[str]) -> list[str]:
    return [v for v, n in Counter(values).items() if n > 1]


def _check_consistency(
    assets: list[Asset], events: list[ModbusEvent], policy: PolicyFile
) -> None:
    """Sprawdza zależności między plikami, których pojedynczy model nie widzi."""
    if dup := _duplicates([a.asset_id for a in assets]):
        raise DataLoadError(f"assets.json: powtórzone asset_id: {dup}")
    if dup := _duplicates([str(a.ip) for a in assets]):
        raise DataLoadError(f"assets.json: powtórzone adresy IP: {dup}")
    if dup := _duplicates([e.event_id for e in events]):
        raise DataLoadError(f"modbus_events.json: powtórzone event_id: {dup[:5]}")

    ids = {a.asset_id for a in assets}
    ips = {str(a.ip) for a in assets}

    # polityka może wspominać tylko o urządzeniach, które istnieją
    referenced = set(policy.authorized_writers) | set(policy.register_limits)
    for writers in policy.authorized_writers.values():
        referenced |= set(writers)
    if unknown := referenced - ids:
        raise DataLoadError(f"policy.json: odwołanie do nieznanych urządzeń: {sorted(unknown)}")

    # nadawca zdarzenia musi być znanym urządzeniem (cel może być nieistniejący, np. w skanie)
    if unknown_src := {str(e.src_ip) for e in events} - ips:
        raise DataLoadError(
            f"modbus_events.json: zdarzenia od nieznanych adresów: {sorted(unknown_src)}"
        )


def load_lab(data_dir: Path | None = None) -> Lab:
    """Wczytuje i waliduje komplet danych z katalogu (domyślnie `data/` w repozytorium)."""
    directory = Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR
    assets_file = _read(directory, "assets.json", AssetsFile)
    events_file = _read(directory, "modbus_events.json", EventsFile)
    policy = _read(directory, "policy.json", PolicyFile)
    _check_consistency(assets_file.assets, events_file.events, policy)
    return Lab(assets_file.assets, events_file.events, policy, events_file.reference_time)


@lru_cache(maxsize=1)
def get_lab() -> Lab:
    """Wczytuje domyślne dane raz na proces; kolejne wywołania zwracają ten sam obiekt."""
    return load_lab()
