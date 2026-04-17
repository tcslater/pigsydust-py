"""Tests for the Pixie manufacturer-data advertisement parser."""

from __future__ import annotations

import pytest

from pigsydust.advert import (
    MajorTypeFlags,
    PixieAdvert,
    parse_pixie_advert,
)


def _make_blob(
    major: int = 0x45, minor: int = 0x0011, mac_tail: bytes = b"\x12\x34\x56\x78"
) -> bytes:
    """Build a 17-byte Skytone manufacturer-data blob.

    Layout (offsets based on observed wall-switch adverts):
      0..1   header / padding (not parsed)
      2..5   MAC octets 2..5, reversed into mac[5..2]
      6..13  padding
      14     majorType (packed flags)
      15..16 minorType (16-bit BE device class)
    """
    blob = bytearray(17)
    blob[2] = mac_tail[3]
    blob[3] = mac_tail[2]
    blob[4] = mac_tail[1]
    blob[5] = mac_tail[0]
    blob[14] = major
    blob[15] = (minor >> 8) & 0xFF
    blob[16] = minor & 0xFF
    return bytes(blob)


def test_major_type_flags_0x45():
    """0x45 = online + no alarm + version 17 (the common wall-switch value)."""
    flags = MajorTypeFlags.from_byte(0x45)
    assert flags.online is True
    assert flags.alarm_dev is False
    assert flags.version == 0x11  # 17


def test_major_type_flags_0x47():
    """0x47 = online + alarmDev + version 17 (transient wall-switch value)."""
    flags = MajorTypeFlags.from_byte(0x47)
    assert flags.online is True
    assert flags.alarm_dev is True
    assert flags.version == 0x11


def test_major_type_flags_extremes():
    assert MajorTypeFlags.from_byte(0x00) == MajorTypeFlags(False, False, 0)
    assert MajorTypeFlags.from_byte(0xFF) == MajorTypeFlags(True, True, 0x3F)


def test_parse_pixie_advert_happy_path():
    blob = _make_blob(major=0x45, minor=0x0011, mac_tail=bytes([0x4D, 0x5B, 0x28, 0x30]))
    manuf = {0x0211: blob}

    result = parse_pixie_advert(manuf)

    assert result is not None
    assert isinstance(result, PixieAdvert)
    assert result.major_type == 0x45
    assert result.major_type_flags.online is True
    assert result.major_type_flags.alarm_dev is False
    assert result.major_type_flags.version == 17
    assert result.minor_type == 0x0011
    # MAC: mac[0..1] = 0, mac[2] = blob[5], mac[3] = blob[4], mac[4] = blob[3], mac[5] = blob[2]
    assert result.mac == bytes([0, 0, 0x4D, 0x5B, 0x28, 0x30])
    assert result.raw == blob


def test_parse_missing_manufacturer_id():
    assert parse_pixie_advert({0x1234: b"\x00" * 20}) is None


def test_parse_empty_manufacturer_data():
    assert parse_pixie_advert({}) is None


def test_parse_none_manufacturer_data():
    assert parse_pixie_advert(None) is None


def test_parse_short_blob_rejected():
    """Blob must be at least 17 bytes to have minor_type at [15..16]."""
    assert parse_pixie_advert({0x0211: b"\x00" * 16}) is None


def test_parse_minor_type_big_endian():
    """Bytes 15..16 are interpreted big-endian."""
    blob = _make_blob(minor=0xABCD)
    assert blob[15] == 0xAB
    assert blob[16] == 0xCD
    result = parse_pixie_advert({0x0211: blob})
    assert result is not None
    assert result.minor_type == 0xABCD
