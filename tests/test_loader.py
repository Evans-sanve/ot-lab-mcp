"""Testy loadera: poprawne wczytanie oraz czytelne błędy dla uszkodzonych danych."""

import json
import shutil
from pathlib import Path

import pytest

from ot_mcp.data_loader import DataLoadError, get_lab, load_lab

REAL_DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture
def data_dir(tmp_path):
    """Kopia prawdziwych danych w katalogu tymczasowym, którą test może bezpiecznie psuć."""
    target = tmp_path / "data"
    shutil.copytree(REAL_DATA, target)
    return target


def _edit(path: Path, change):
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_load_default_data():
    lab = load_lab()
    assert len(lab.assets) == 13
    assert len(lab.events) > 200
    assert lab.reference_time.year == 2026


def test_lookup_asset_by_id_and_ip():
    lab = load_lab()
    plc = lab.asset_by_id("PLC-02")
    assert plc is not None and str(plc.ip) == "192.168.10.12"
    assert lab.asset_by_ip("192.168.10.12") == plc
    assert lab.asset_by_id("NOPE") is None
    assert lab.asset_by_ip("192.168.99.99") is None


def test_get_lab_is_cached():
    assert get_lab() is get_lab()


def test_missing_file_gives_clear_error(data_dir):
    (data_dir / "policy.json").unlink()
    with pytest.raises(DataLoadError, match="policy.json"):
        load_lab(data_dir)


def test_invalid_json_gives_clear_error(data_dir):
    (data_dir / "assets.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(DataLoadError, match="assets.json"):
        load_lab(data_dir)


def test_non_synthetic_data_is_rejected(data_dir):
    _edit(data_dir / "assets.json", lambda d: d["meta"].update(synthetic=False))
    with pytest.raises(DataLoadError, match="assets.json"):
        load_lab(data_dir)


def test_duplicate_asset_ids_are_rejected(data_dir):
    def dup(doc):
        doc["assets"].append(dict(doc["assets"][0], ip="192.168.77.77"))

    _edit(data_dir / "assets.json", dup)
    with pytest.raises(DataLoadError, match="asset_id"):
        load_lab(data_dir)


def test_duplicate_ips_are_rejected(data_dir):
    def dup(doc):
        doc["assets"].append(dict(doc["assets"][0], asset_id="OTHER-01"))

    _edit(data_dir / "assets.json", dup)
    with pytest.raises(DataLoadError, match="IP"):
        load_lab(data_dir)


def test_policy_with_unknown_asset_is_rejected(data_dir):
    _edit(data_dir / "policy.json", lambda d: d["authorized_writers"].update({"GHOST-99": []}))
    with pytest.raises(DataLoadError, match="GHOST-99"):
        load_lab(data_dir)


def test_event_from_unknown_source_is_rejected(data_dir):
    _edit(
        data_dir / "modbus_events.json",
        lambda d: d["events"][0].update(src_ip="192.168.99.99"),
    )
    with pytest.raises(DataLoadError, match="192.168.99.99"):
        load_lab(data_dir)


def test_duplicate_event_ids_are_rejected(data_dir):
    _edit(
        data_dir / "modbus_events.json",
        lambda d: d["events"][1].update(event_id=d["events"][0]["event_id"]),
    )
    with pytest.raises(DataLoadError, match="event_id"):
        load_lab(data_dir)
