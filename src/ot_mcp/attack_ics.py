"""Mapowanie anomalii na techniki MITRE ATT&CK for ICS.

Identyfikatory i nazwy poniżej zostały zweryfikowane na attack.mitre.org (macierz ICS oraz
strony poszczególnych technik) w dniu VERIFIED_ON, a nie wpisane z pamięci. Przy okazji
okazało się, że w aktualnej macierzy nie ma starszego T0855 „Unauthorized Command Message":
odpowiada mu T1692.001 (podtechnika „Command Message" techniki „Unauthorized Message").
Numeracja ATT&CK się zmienia, więc przy aktualizacji danych sprawdź katalog ponownie.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

VERIFIED_ON = "2026-11-03"
SOURCE = (
    "MITRE ATT&CK for ICS (https://attack.mitre.org/matrices/ics/); "
    f"technique IDs verified on {VERIFIED_ON}"
)

Confidence = Literal["high", "medium"]


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        # podtechniki mają adres w postaci /techniques/T1692/001/
        return f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/"


@dataclass(frozen=True)
class Mapping:
    """Powiązanie wzorca zachowania z techniką wraz z uzasadnieniem i pewnością.

    confidence: "high" = opis techniki wprost pasuje do zachowania;
    "medium" = pasuje przez skutek, a nie przez dosłowny opis (patrz rationale).
    """

    technique_id: str
    confidence: Confidence
    rationale: str
    applies_to: str


TECHNIQUES: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        Technique("T1692.001", "Unauthorized Message: Command Message",
                  ("Evasion", "Impair Process Control")),
        Technique("T0846", "Remote System Discovery", ("Discovery",)),
        Technique("T0888", "Remote System Information Discovery", ("Discovery",)),
        Technique("T0814", "Denial of Service", ("Inhibit Response Function",)),
        Technique("T0836", "Modify Parameter", ("Impair Process Control",)),
    )
}

_R1 = Mapping(
    "T1692.001", "high",
    "Write commands were sent to a controller by a host that is not authorized to control it. "
    "The technique page cites Modbus register writes against PLCs (INCONTROLLER).",
    "unauthorized writes (R1)",
)
_R2 = Mapping(
    "T0846", "high",
    "One host enumerated many other systems by IP address in a short burst.",
    "network scan (R2)",
)
_R4 = Mapping(
    "T0836", "high",
    "A register value that sets device behavior was written outside its allowed range. "
    "The technique page cites Modbus holding register writes.",
    "out-of-range register write (R4)",
)
_R3_INFO = Mapping(
    "T0888", "high",
    "Read Device Identification / Report Server ID collect model and configuration of a remote "
    "device. The technique page cites a Modbus device-ID request.",
    "function codes 17, 43 (R3)",
)
_R3_DOS = Mapping(
    "T0814", "medium",
    "Modbus diagnostics (restart communications, listen-only mode) can leave a device not "
    "responding to its master. The technique page describes the effect but does not mention "
    "Modbus, hence medium confidence. Device Restart/Shutdown (T0816) was rejected: FC 8 "
    "restarts the communication stack, not the device.",
    "function code 8 (R3)",
)

_R3_BY_FUNCTION_CODE = {8: _R3_DOS, 17: _R3_INFO, 43: _R3_INFO}

_BY_RULE: dict[str, list[Mapping]] = {
    "R1": [_R1],
    "R2": [_R2],
    "R3": [_R3_DOS, _R3_INFO],
    "R4": [_R4],
}


def techniques_for_rule(rule_id: str) -> list[Mapping]:
    """Wszystkie techniki, na które reguła może się mapować."""
    if rule_id not in _BY_RULE:
        raise ValueError(f"rule_id: nieznana reguła {rule_id!r}; dozwolone: {sorted(_BY_RULE)}")
    return list(_BY_RULE[rule_id])


def techniques_for_anomaly(anomaly: dict) -> list[Mapping]:
    """Techniki dla konkretnej anomalii (dla R3 zależnie od kodu funkcji).

    Zwraca pustą listę, gdy nie mamy pewnego mapowania: uczciwe „brak" jest lepsze od zgadywania.
    """
    rule_id = anomaly["rule_id"]
    if rule_id == "R3":
        mapping = _R3_BY_FUNCTION_CODE.get(anomaly["details"].get("function_code"))
        return [mapping] if mapping else []
    return techniques_for_rule(rule_id)
