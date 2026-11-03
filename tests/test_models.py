"""Testy modeli danych: sprawdzają, że zły wpis jest odrzucany już na wejściu."""

import pytest
from pydantic import ValidationError

from ot_mcp.models import Asset, Meta, ModbusEvent, Zone

ASSET = {
    "asset_id": "PLC-01",
    "hostname": "plc-01.ot-lab.invalid",
    "device_type": "plc",
    "ip": "192.168.10.11",
    "vendor": "Acme Controls",
    "model": "AC-300",
    "firmware": "2.1.0",
    "zone": "level_1_control",
}

EVENT = {
    "event_id": "evt-000001",
    "timestamp": "2026-11-03T10:00:00Z",
    "src_ip": "192.168.20.21",
    "dst_ip": "192.168.10.11",
    "src_port": 50000,
    "dst_port": 502,
    "unit_id": 1,
    "function_code": 3,
    "register_address": 0,
    "quantity": 4,
    "status": "ok",
}


def test_asset_valid():
    asset = Asset.model_validate(ASSET)
    assert asset.zone is Zone.L1_CONTROL
    assert asset.purdue_level == 1


def test_asset_rejects_public_ip():
    # Zasada projektu: tylko adresy prywatne, żeby nic nie wskazywało na prawdziwy host.
    with pytest.raises(ValidationError):
        Asset.model_validate({**ASSET, "ip": "8.8.8.8"})


def test_asset_rejects_unknown_device_type():
    with pytest.raises(ValidationError):
        Asset.model_validate({**ASSET, "device_type": "toaster"})


def test_asset_rejects_unknown_field():
    # extra="forbid": literówka w JSON ma być błędem, a nie cicho ignorowanym polem.
    with pytest.raises(ValidationError):
        Asset.model_validate({**ASSET, "firmwre": "oops"})


def test_dmz_is_level_3_5():
    assert Zone.DMZ.purdue_level == 3.5


def test_purdue_level_appears_in_serialized_output():
    # Claude dostaje model_dump, więc poziom Purdue musi tam być.
    dumped = Asset.model_validate(ASSET).model_dump(mode="json")
    assert dumped["purdue_level"] == 1
    assert dumped["ip"] == "192.168.10.11"


def test_event_valid_read_is_not_write():
    event = ModbusEvent.model_validate(EVENT)
    assert event.is_write is False


@pytest.mark.parametrize("fc", [5, 6, 15, 16])
def test_event_write_function_codes(fc):
    assert ModbusEvent.model_validate({**EVENT, "function_code": fc}).is_write is True


def test_event_requires_timezone():
    with pytest.raises(ValidationError):
        ModbusEvent.model_validate({**EVENT, "timestamp": "2026-11-03T10:00:00"})


@pytest.mark.parametrize("fc", [0, 128, -1])
def test_event_function_code_bounds(fc):
    with pytest.raises(ValidationError):
        ModbusEvent.model_validate({**EVENT, "function_code": fc})


def test_event_value_must_fit_16_bits():
    with pytest.raises(ValidationError):
        ModbusEvent.model_validate({**EVENT, "function_code": 6, "value": 70000})


def test_meta_must_declare_data_as_synthetic():
    with pytest.raises(ValidationError):
        Meta.model_validate({"synthetic": False, "generator": "x", "seed": 1})
