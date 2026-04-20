"""Tests for the device-class wire-to-name lookup."""

from __future__ import annotations

from pigsydust import (
    DeviceClass,
    PixieAdvert,
    StatusByteFlags,
    device_class_lookup,
    device_class_name,
)
from pigsydust.notification import DeviceStatus


def test_switch_g2_wire_halving() -> None:
    """The canonical path: wire (22, 12) → SWITCH_G2 (key 44024)."""
    assert device_class_lookup(22, 12) is DeviceClass.SWITCH_G2
    assert device_class_name(22, 12) == "SWITCH_G2"


def test_acf_rs8_shortcut_any_type() -> None:
    """wire stype == 0x39 maps to ACF_RS8 regardless of wire type."""
    for wire_type in (0, 22, 54, 180):
        assert device_class_lookup(wire_type, 0x39) is DeviceClass.ACF_RS8
        assert device_class_name(wire_type, 0x39) == "ACF_RS8"


def test_switch_alias_both_keys_resolve_to_switch() -> None:
    """Both (44, 2) and (44, 22) carry the SWITCH name per the spec."""
    # (44, 2) is wire (22, 1).
    assert device_class_name(22, 1) == "SWITCH"
    # (44, 22) is wire (22, 11); aliases to the same canonical name.
    assert device_class_name(22, 11) == "SWITCH"


def test_unknown_wire_bytes_returns_none() -> None:
    """Wire values outside the table and not ACF_RS8 return ``None``."""
    assert device_class_lookup(0xFF, 0xFE) is None
    assert device_class_name(0xFF, 0xFE) is None


def test_raw_bytes_fallback() -> None:
    """If the halved lookup misses, fall back to raw wire bytes.

    SONOS is spec-canonical (180, 2) → key 180002. If some future device
    published those values unhalved on the wire (wire 180, 2 instead of
    wire 90, 1), the defensive raw fallback catches it.
    """
    assert device_class_lookup(180, 2) is DeviceClass.SONOS


def test_pixie_advert_device_class_name_property() -> None:
    """PixieAdvert exposes device_class_name derived from wire bytes."""
    advert = PixieAdvert(
        mac=b"\x00\x00\xaa\xbb\xcc\x01",
        type=22,
        stype=12,
        status_byte=0x45,
        status_flags=StatusByteFlags.from_byte(0x45),
        mesh_address=1,
        network_id=b"\x1a\xe7\x1d\x19",
        raw=b"",
    )
    assert advert.device_class_name == "SWITCH_G2"


def test_device_status_device_class_name_property() -> None:
    """DeviceStatus.device_class_name is derived when type+stype present."""
    ds = DeviceStatus(
        address=1,
        is_on=True,
        mac=b"\x00\x00\xaa\xbb\xcc\x01",
        type=22,
        stype=12,
    )
    assert ds.device_class_name == "SWITCH_G2"


def test_device_status_device_class_name_none_when_missing() -> None:
    """Without type/stype (e.g. 0xdc broadcast rows) the property is None."""
    ds = DeviceStatus(
        address=1,
        is_on=True,
        mac=b"\x00\x00\xaa\xbb\xcc\x01",
    )
    assert ds.device_class_name is None
