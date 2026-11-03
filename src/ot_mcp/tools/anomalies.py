"""Narzędzie detect_anomalies: uruchamia reguły detekcji na zdarzeniach z okna czasowego."""

from __future__ import annotations

from datetime import timedelta

from ot_mcp.data_loader import Lab
from ot_mcp.detection.rules import ALL_RULES
from ot_mcp.models import SEVERITY_ORDER
from ot_mcp.tools.events import MAX_HOURS


def detect_anomalies(lab: Lab, hours: float = 6) -> dict:
    """Wykrywa podejrzane zachowania w zdarzeniach z ostatnich `hours` godzin.

    Okno liczymy od czasu odniesienia danych (tak samo jak w get_modbus_events).
    Wynik jest posortowany od najpoważniejszej anomalii.
    """
    if not 0 < hours <= MAX_HOURS:
        raise ValueError(f"hours: musi być w zakresie (0, {MAX_HOURS}], podano {hours}")

    start = lab.reference_time - timedelta(hours=hours)
    window = [e for e in lab.events if start <= e.timestamp <= lab.reference_time]

    anomalies = [a for rule in ALL_RULES for a in rule(lab, window)]
    anomalies.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))

    return {
        "reference_time": lab.reference_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_hours": hours,
        "events_analyzed": len(window),
        "anomaly_count": len(anomalies),
        "anomalies": [a.model_dump(mode="json") for a in anomalies],
    }
