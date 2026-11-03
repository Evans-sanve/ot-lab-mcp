"""Modele danych (Pydantic).

Modele robią dwie rzeczy: walidują pliki JSON przy wczytaniu (zły wpis = błąd od razu, a nie
dziwne zachowanie w połowie analizy) oraz definiują dokładny kształt tego, co dostaje Claude.
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
)

from ot_mcp.modbus import WRITE_FUNCTION_CODES


def _require_private_ipv4(value: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
    """Zasada projektu: tylko adresy prywatne/dokumentacyjne, nigdy publiczne."""
    if not value.is_private:
        raise ValueError(f"adres {value} nie jest prywatny; dane muszą być syntetyczne")
    return value


PrivateIPv4 = Annotated[ipaddress.IPv4Address, AfterValidator(_require_private_ipv4)]


class _Strict(BaseModel):
    """Baza: nieznane pole w JSON to błąd (łapie literówki), a modele są niemutowalne."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Zone(str, Enum):
    """Strefa sieci wg modelu Purdue (z DMZ między poziomem 3 a 4)."""

    L0_PROCESS = "level_0_process"
    L1_CONTROL = "level_1_control"
    L2_SUPERVISORY = "level_2_supervisory"
    L3_OPERATIONS = "level_3_operations"
    DMZ = "level_3_5_dmz"
    L4_ENTERPRISE = "level_4_enterprise"

    @property
    def purdue_level(self) -> float:
        return _PURDUE_LEVELS[self]


_PURDUE_LEVELS = {
    Zone.L0_PROCESS: 0,
    Zone.L1_CONTROL: 1,
    Zone.L2_SUPERVISORY: 2,
    Zone.L3_OPERATIONS: 3,
    Zone.DMZ: 3.5,
    Zone.L4_ENTERPRISE: 4,
}

DeviceType = Literal[
    "plc",
    "rtu",
    "hmi",
    "switch",
    "engineering_workstation",
    "historian",
    "jump_host",
    "firewall",
    "workstation",
]


class Meta(_Strict):
    """Metadane każdego pliku z danymi. `synthetic` musi być True, inaczej plik jest odrzucany."""

    synthetic: Literal[True]
    generator: str
    seed: int
    note: str = ""


class Asset(_Strict):
    """Fikcyjne urządzenie w laboratorium."""

    asset_id: str
    hostname: str
    device_type: DeviceType
    ip: PrivateIPv4
    vendor: str
    model: str
    firmware: str
    zone: Zone

    @computed_field  # trafia do model_dump, więc Claude widzi poziom Purdue
    @property
    def purdue_level(self) -> float:
        return self.zone.purdue_level


class ModbusEvent(_Strict):
    """Pojedyncza transakcja Modbus/TCP (żądanie od klienta do serwera)."""

    event_id: str
    timestamp: AwareDatetime
    src_ip: PrivateIPv4
    dst_ip: PrivateIPv4
    src_port: int = Field(ge=1, le=65535)
    dst_port: int = Field(default=502, ge=1, le=65535)
    unit_id: int = Field(ge=0, le=255)
    function_code: int = Field(ge=1, le=127)
    # nazwa `register` koliduje z atrybutem klasy bazowej pydantic, stąd `register_address`
    register_address: int | None = Field(default=None, ge=0, le=65535)
    quantity: int | None = Field(default=None, ge=1, le=2000)
    sub_function: int | None = Field(default=None, ge=0, le=65535)
    value: int | None = Field(default=None, ge=0, le=65535)
    status: Literal["ok", "exception", "timeout"]

    @property
    def is_write(self) -> bool:
        return self.function_code in WRITE_FUNCTION_CODES


class RegisterLimit(_Strict):
    """Dozwolony zakres wartości zapisywanych do rejestru."""

    name: str
    min: int
    max: int


Severity = Literal["critical", "high", "medium", "low"]
# kolejność sortowania: im mniejsza liczba, tym poważniejsza anomalia
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Anomaly(_Strict):
    """Podejrzane zachowanie wykryte przez regułę wraz z dowodami (id zdarzeń)."""

    anomaly_id: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    src_ip: PrivateIPv4
    src_asset: str | None
    targets: list[str]  # asset_id albo adres IP, jeśli cel nie jest znanym urządzeniem
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    event_count: int
    evidence_event_ids: list[str]  # przycięte do MAX_EVIDENCE; pełna liczba w event_count
    details: dict[str, Any] = Field(default_factory=dict)


class AssetsFile(_Strict):
    meta: Meta
    assets: list[Asset]


class EventsFile(_Strict):
    """`reference_time` to umowne „teraz"; okna „ostatnie N godzin" liczymy od niego."""

    meta: Meta
    reference_time: AwareDatetime
    events: list[ModbusEvent]


class PolicyFile(_Strict):
    """Polityka laboratorium: co jest normalne. Reguły detekcji porównują ruch z tym wzorcem."""

    meta: Meta
    # kody funkcji spodziewane w normalnym ruchu; inne uznajemy za nietypowe
    common_function_codes: list[int]
    # urządzenie docelowe -> asset_id hostów, którym wolno do niego pisać
    authorized_writers: dict[str, list[str]]
    # urządzenie docelowe -> rejestr -> dozwolony zakres zapisu
    register_limits: dict[str, dict[int, RegisterLimit]]
