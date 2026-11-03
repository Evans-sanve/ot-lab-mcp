"""Generator syntetycznych danych laboratorium OT.

Uruchomienie:  uv run python scripts/generate_data.py

Wynik (data/assets.json, data/modbus_events.json, data/policy.json) jest deterministyczny:
stały seed daje zawsze te same pliki, więc testy i demo są powtarzalne, a w repo widać, skąd
dane się wzięły. Wszystko jest fikcyjne: producenci, modele, adresy (tylko zakresy prywatne).

Scenariusz: spokojny ruch bazowy z ostatnich 12 godzin + atak z hosta w DMZ w trzech fazach
(skan -> nieautoryzowane zapisy -> nietypowe kody funkcji). W danych nie ma pola „złośliwe":
rozpoznanie ataku ma być zadaniem reguł detekcji.
"""

from __future__ import annotations

import ipaddress
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ot_mcp.models import Asset, Meta, PolicyFile, RegisterLimit, Zone

SEED = 1337
# Umowne „teraz" zbioru danych. Okna „ostatnie N godzin" liczymy od tej chwili, nie od zegara.
REFERENCE_TIME = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
BASELINE_HOURS = 12
DATA_DIR = Path(__file__).resolve().parents[1] / "data"

NOTE = "Fully synthetic lab data. No real systems, vendors, addresses or customer data."
META = Meta(synthetic=True, generator="scripts/generate_data.py", seed=SEED, note=NOTE)


def build_assets() -> list[Asset]:
    """Mała sieć: poziomy Purdue 0-4 plus DMZ. Hostnamy w TLD .invalid (RFC 2606)."""

    def asset(aid, dtype, ip, vendor, model, firmware, zone):
        return Asset(
            asset_id=aid,
            hostname=f"{aid.lower()}.ot-lab.invalid",
            device_type=dtype,
            ip=ip,
            vendor=vendor,
            model=model,
            firmware=firmware,
            zone=zone,
        )

    return [
        asset("RTU-01", "rtu", "192.168.5.21", "Globex Automation", "GX-RTU-10", "3.0.2", Zone.L0_PROCESS),
        asset("PLC-01", "plc", "192.168.10.11", "Acme Controls", "AC-300", "2.4.1", Zone.L1_CONTROL),
        # PLC-02 celowo ma starszy firmware (realistyczny dług techniczny w OT)
        asset("PLC-02", "plc", "192.168.10.12", "Acme Controls", "AC-300", "1.9.0", Zone.L1_CONTROL),
        asset("PLC-03", "plc", "192.168.10.13", "Acme Controls", "AC-500", "2.4.1", Zone.L1_CONTROL),
        asset("SW-CTRL-01", "switch", "192.168.10.2", "Vandelay Networks", "VN-24M", "5.2.0", Zone.L1_CONTROL),
        asset("HMI-01", "hmi", "192.168.20.21", "Globex Automation", "GX-Panel-12", "4.1.3", Zone.L2_SUPERVISORY),
        asset("HMI-02", "hmi", "192.168.20.22", "Globex Automation", "GX-Panel-12", "4.1.3", Zone.L2_SUPERVISORY),
        asset("SW-SUP-01", "switch", "192.168.20.2", "Vandelay Networks", "VN-24M", "5.2.0", Zone.L2_SUPERVISORY),
        asset(
            "ENG-WS-01", "engineering_workstation", "192.168.30.31", "Generic PC",
            "Lab Engineering Workstation", "OS build 1.0", Zone.L3_OPERATIONS,
        ),
        asset("HIST-01", "historian", "192.168.30.41", "Initech Industrial", "InitechHistorian", "8.0.1", Zone.L3_OPERATIONS),
        asset("FW-01", "firewall", "172.16.40.1", "Vandelay Networks", "VN-FW-2", "7.1.4", Zone.DMZ),
        asset("JUMP-01", "jump_host", "172.16.40.10", "Generic PC", "Lab Jump Host", "OS build 1.0", Zone.DMZ),
        asset("IT-WS-17", "workstation", "10.10.4.17", "Generic PC", "Lab Office Workstation", "OS build 1.0", Zone.L4_ENTERPRISE),
    ]


def build_policy() -> PolicyFile:
    """Wzorzec „normalnego" zachowania, z którym porównują reguły detekcji."""
    return PolicyFile(
        meta=META,
        common_function_codes=[1, 2, 3, 4, 5, 6, 15, 16],
        authorized_writers={
            "PLC-01": ["HMI-01", "ENG-WS-01"],
            "PLC-02": ["HMI-02", "ENG-WS-01"],
            "PLC-03": ["ENG-WS-01"],
        },
        register_limits={
            "PLC-01": {
                0: RegisterLimit(name="pump_speed_setpoint_rpm", min=0, max=1500),
                1: RegisterLimit(name="flow_setpoint_lpm", min=0, max=500),
            },
            "PLC-02": {
                0: RegisterLimit(name="valve_position_pct", min=0, max=100),
                1: RegisterLimit(name="dosing_rate_ml_min", min=0, max=250),
            },
            "PLC-03": {
                0: RegisterLimit(name="boiler_temp_setpoint_c", min=20, max=90),
            },
        },
    )


class EventBuilder:
    """Zbiera zdarzenia jako słowniki; id nadaje dopiero po posortowaniu po czasie."""

    def __init__(self, assets: list[Asset], rng: random.Random):
        self.ip = {a.asset_id: str(a.ip) for a in assets}
        self.rng = rng
        self.rows: list[dict] = []

    def add(self, ts: datetime, src: str, dst: str, function_code: int, status: str = "ok", **extra):
        # `dst` to asset_id albo surowy adres IP (np. w skanie, gdzie część celów nie istnieje)
        self.rows.append(
            {
                "timestamp": ts.replace(microsecond=0),
                "src_ip": self.ip[src],
                "dst_ip": self.ip.get(dst, dst),
                "src_port": self.rng.randint(49152, 65535),
                "dst_port": 502,
                "unit_id": 1,
                "function_code": function_code,
                "status": status,
                **extra,
            }
        )

    def poll(self, src: str, dst: str, function_code: int, register: int, quantity: int, every_min: int):
        """Cykliczne odpytywanie (HMI/historian czytają sterownik) z drobnym jitterem czasu."""
        t = REFERENCE_TIME - timedelta(hours=BASELINE_HOURS) + timedelta(
            seconds=self.rng.randint(0, every_min * 60)
        )
        while t < REFERENCE_TIME - timedelta(seconds=30):
            jitter = timedelta(seconds=self.rng.randint(-15, 15))
            ts = min(t + jitter, REFERENCE_TIME - timedelta(seconds=1))
            self.add(ts, src, dst, function_code, register_address=register, quantity=quantity)
            t += timedelta(minutes=every_min)

    def finalize(self) -> list[dict]:
        rows = sorted(self.rows, key=lambda r: r["timestamp"])
        for i, row in enumerate(rows, start=1):
            row["event_id"] = f"evt-{i:06d}"
        return rows


def _ago(minutes: float) -> datetime:
    return REFERENCE_TIME - timedelta(minutes=minutes)


def build_events(assets: list[Asset], rng: random.Random) -> list[dict]:
    b = EventBuilder(assets, rng)

    # --- ruch bazowy: odczyty cykliczne -----------------------------------------------------
    b.poll("HMI-01", "PLC-01", 3, register=0, quantity=4, every_min=10)
    b.poll("HMI-01", "PLC-02", 3, register=0, quantity=2, every_min=10)
    b.poll("HMI-02", "PLC-02", 3, register=0, quantity=2, every_min=10)
    b.poll("HMI-02", "PLC-03", 3, register=0, quantity=1, every_min=10)
    for plc in ("PLC-01", "PLC-02", "PLC-03"):
        b.poll("HIST-01", plc, 4, register=10, quantity=8, every_min=15)
    b.poll("HIST-01", "RTU-01", 4, register=0, quantity=8, every_min=15)

    # --- ruch bazowy: autoryzowane zapisy (w zakresach z polityki) --------------------------
    for hours_ago in (11, 7, 3):  # operator zmienia obroty pompy z HMI-01
        b.add(_ago(hours_ago * 60 + rng.randint(0, 30)), "HMI-01", "PLC-01", 6,
              register_address=0, value=rng.randint(800, 1200))
    # okno serwisowe stacji inżynierskiej, ok. 9 h temu
    b.add(_ago(9 * 60), "ENG-WS-01", "PLC-02", 6, register_address=1, value=120)
    b.add(_ago(9 * 60 - 5), "ENG-WS-01", "PLC-02", 16, register_address=0, quantity=2, value=50)
    b.add(_ago(9 * 60 - 10), "ENG-WS-01", "PLC-03", 6, register_address=0, value=60)

    # --- atak, faza 1 (ok. 110 min temu): skan podsieci sterowników z hosta w DMZ ------------
    t = _ago(110)
    subnet = ipaddress.ip_network("192.168.10.0/24")
    existing = {b.ip[p] for p in ("PLC-01", "PLC-02", "PLC-03")}
    for host in list(subnet.hosts())[:40]:  # 192.168.10.1 - .40
        ip = str(host)
        # FC 43 / MEI 14 = odczyt identyfikacji urządzenia; istnieją tylko 3 sterowniki
        b.add(t, "JUMP-01", ip, 43, status="ok" if ip in existing else "timeout", sub_function=14)
        t += timedelta(seconds=rng.randint(2, 4))
    t += timedelta(seconds=30)
    for plc in ("PLC-01", "PLC-02", "PLC-03"):  # FC 17 = Report Server ID u znalezionych celów
        b.add(t, "JUMP-01", plc, 17)
        t += timedelta(seconds=rng.randint(2, 4))

    # --- atak, faza 2 (ok. 75 min temu): zapisy do PLC-02 z nieautoryzowanego hosta ---------
    t = _ago(75)
    b.add(t, "JUMP-01", "PLC-02", 6, register_address=0, value=100)  # w zakresie, ale nieautoryzowany
    b.add(t + timedelta(seconds=40), "JUMP-01", "PLC-02", 6, register_address=1, value=9999)  # poza zakresem
    b.add(t + timedelta(seconds=80), "JUMP-01", "PLC-02", 6, register_address=0, value=0)
    b.add(t + timedelta(seconds=120), "JUMP-01", "PLC-02", 16, register_address=1, quantity=2, value=65535)

    # --- atak, faza 3 (ok. 30 min temu): diagnostyka Modbus (FC 8) przeciw PLC-02 -----------
    t = _ago(30)
    b.add(t, "JUMP-01", "PLC-02", 8, sub_function=1)  # Restart Communications Option
    b.add(t + timedelta(seconds=60), "JUMP-01", "PLC-02", 8, status="timeout", sub_function=4)  # Force Listen Only

    return b.finalize()


def _dump_asset(asset: Asset) -> dict:
    # purdue_level jest polem wyliczanym; w pliku go nie zapisujemy (model go odtworzy)
    return asset.model_dump(mode="json", exclude={"purdue_level"})


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"zapisano {path.relative_to(DATA_DIR.parent)}")


def main() -> None:
    rng = random.Random(SEED)
    assets = build_assets()
    policy = build_policy()
    rows = build_events(assets, rng)
    meta = META.model_dump(mode="json")

    DATA_DIR.mkdir(exist_ok=True)
    _write(
        DATA_DIR / "assets.json",
        json.dumps({"meta": meta, "assets": [_dump_asset(a) for a in assets]}, indent=2) + "\n",
    )
    _write(DATA_DIR / "policy.json", json.dumps(policy.model_dump(mode="json"), indent=2) + "\n")

    # zdarzenia: jedno na linię, żeby plik był zwarty i dobrze wyglądał w diffach
    events = []
    for row in rows:
        stamp = row["timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")
        row = {"event_id": row["event_id"], **row, "timestamp": stamp}
        events.append("    " + json.dumps(row))
    ref = REFERENCE_TIME.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = (
        "{\n"
        f'  "meta": {json.dumps(meta)},\n'
        f'  "reference_time": "{ref}",\n'
        '  "events": [\n' + ",\n".join(events) + "\n  ]\n}\n"
    )
    _write(DATA_DIR / "modbus_events.json", text)
    print(f"zdarzeń: {len(rows)}, urządzeń: {len(assets)}")


if __name__ == "__main__":
    main()
