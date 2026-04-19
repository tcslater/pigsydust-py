"""Tests for the Pixie manufacturer-data advertisement parser."""

from __future__ import annotations

from pigsydust.advert import (
    PixieAdvert,
    StatusByteFlags,
    parse_pixie_advert,
)


# Wall-switch advert blob — (type, stype) = (0x16, 0x0c), status 0x45.
WALL_SWITCH_BLOB = bytes.fromhex(
    "11027d265d4d160c457d001ae71d19000000000000000000000000"
)


def _make_blob(
    *,
    mac_tail: bytes = bytes([0x4D, 0x5D, 0x26, 0x7D]),
    type_byte: int = 0x16,
    stype_byte: int = 0x0c,
    status_byte: int = 0x45,
    network_id: bytes = bytes.fromhex("1ae71d19"),
) -> bytes:
    """Build a 27-byte manufacturer-data blob.

    ``mac_tail`` is the four MSB-to-LSB octets of the MAC suffix; the
    blob stores them in reverse at offsets 2..5.
    """
    blob = bytearray(27)
    blob[0] = 0x11
    blob[1] = 0x02
    blob[2] = mac_tail[3]
    blob[3] = mac_tail[2]
    blob[4] = mac_tail[1]
    blob[5] = mac_tail[0]
    blob[6] = type_byte
    blob[7] = stype_byte
    blob[8] = status_byte
    blob[9] = mac_tail[3]  # mesh address = MAC[5]
    blob[10] = 0x00
    blob[11:15] = network_id
    return bytes(blob)


def test_status_byte_flags_0x45():
    """0x45 = online + no alarm + version 17."""
    flags = StatusByteFlags.from_byte(0x45)
    assert flags.online is True
    assert flags.alarm_dev is False
    assert flags.version == 0x11


def test_status_byte_flags_0x47():
    """0x47 = online + alarmDev + version 17."""
    flags = StatusByteFlags.from_byte(0x47)
    assert flags.online is True
    assert flags.alarm_dev is True
    assert flags.version == 0x11


def test_status_byte_flags_extremes():
    assert StatusByteFlags.from_byte(0x00) == StatusByteFlags(False, False, 0)
    assert StatusByteFlags.from_byte(0xFF) == StatusByteFlags(True, True, 0x3F)


def test_parse_wall_switch_blob():
    """Round-trip the wall-switch fixture."""
    result = parse_pixie_advert({0x0211: WALL_SWITCH_BLOB})

    assert result is not None
    assert isinstance(result, PixieAdvert)
    assert result.type == 0x16
    assert result.stype == 0x0c
    assert result.status_byte == 0x45
    assert result.status_flags.online is True
    assert result.status_flags.alarm_dev is False
    assert result.status_flags.version == 17
    assert result.mac == bytes([0, 0, 0x4D, 0x5D, 0x26, 0x7D])
    assert result.mesh_address == 0x7D
    assert result.network_id == bytes.fromhex("1ae71d19")
    assert result.raw == WALL_SWITCH_BLOB


def test_parse_synthetic_blob_round_trip():
    blob = _make_blob(
        mac_tail=bytes([0x4D, 0x5B, 0x28, 0x90]),
        status_byte=0x47,
    )
    result = parse_pixie_advert({0x0211: blob})

    assert result is not None
    assert result.mac == bytes([0, 0, 0x4D, 0x5B, 0x28, 0x90])
    assert result.mesh_address == 0x90
    assert result.status_flags.alarm_dev is True


def test_parse_missing_manufacturer_id():
    assert parse_pixie_advert({0x1234: b"\x00" * 20}) is None


def test_parse_empty_manufacturer_data():
    assert parse_pixie_advert({}) is None


def test_parse_none_manufacturer_data():
    assert parse_pixie_advert(None) is None


def test_parse_short_blob_rejected():
    """Blob must be at least 15 bytes (through the network_id field)."""
    assert parse_pixie_advert({0x0211: b"\x00" * 14}) is None
