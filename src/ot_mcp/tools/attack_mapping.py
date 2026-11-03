"""Narzędzie map_to_attack_ics: tłumaczy anomalię (lub regułę) na techniki MITRE ATT&CK for ICS."""

from __future__ import annotations

from ot_mcp.attack_ics import (
    SOURCE,
    TECHNIQUES,
    Mapping,
    techniques_for_anomaly,
    techniques_for_rule,
)
from ot_mcp.data_loader import Lab
from ot_mcp.tools.anomalies import detect_anomalies
from ot_mcp.tools.events import MAX_HOURS


def _describe(mapping: Mapping) -> dict:
    technique = TECHNIQUES[mapping.technique_id]
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactics": list(technique.tactics),
        "url": technique.url,
        "confidence": mapping.confidence,
        "rationale": mapping.rationale,
        "applies_to": mapping.applies_to,
    }


def map_to_attack_ics(lab: Lab, anomaly_id: str | None = None, rule_id: str | None = None) -> dict:
    """Mapuje anomalię (`anomaly_id` z detect_anomalies) albo całą regułę (`rule_id`) na techniki.

    Podaj dokładnie jeden z parametrów.
    """
    if (anomaly_id is None) == (rule_id is None):
        raise ValueError("podaj dokładnie jeden z parametrów: anomaly_id albo rule_id")

    if rule_id is not None:
        mappings = techniques_for_rule(rule_id)
        return {"anomaly": None, "rule_id": rule_id, "techniques": [_describe(m) for m in mappings],
                "source": SOURCE}

    # Anomalię szukamy w pełnym zbiorze danych, żeby identyfikator działał niezależnie od tego,
    # z jakim oknem czasowym wywołano wcześniej detect_anomalies.
    found = next(
        (a for a in detect_anomalies(lab, hours=MAX_HOURS)["anomalies"]
         if a["anomaly_id"] == anomaly_id),
        None,
    )
    if found is None:
        raise ValueError(
            f"anomaly_id: nie znaleziono anomalii {anomaly_id!r}. "
            "Najpierw uruchom detect_anomalies i użyj anomaly_id z jej wyniku."
        )

    mappings = techniques_for_anomaly(found)
    result = {
        "anomaly": {k: found[k] for k in ("anomaly_id", "rule_id", "title", "severity")},
        "techniques": [_describe(m) for m in mappings],
        "source": SOURCE,
    }
    if not mappings:
        result["note"] = "No confident ATT&CK mapping for this anomaly; analyst review recommended."
    return result
