"""Tests for notification parsing."""

import struct

from pigsydust.crypto import command_nonce, derive_session_key, encrypt
from pigsydust.notification import (
    DeviceStatus,
    Notification,
    decrypt_notification,
    parse_device_status,
    parse_device_status_broadcast,
    parse_notification_wire,
)


def _make_session():
    """Create a test session key and gateway MAC."""
    rand_a = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    rand_b = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    sk = derive_session_key("Smart Light", "12345678", rand_a, rand_b)
    gw_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    return sk, gw_mac


def test_parse_notification_wire():
    raw = bytearray(20)
    raw[0:3] = b"\x01\x02\x03"  # sno
    struct.pack_into("<H", raw, 3, 0x0005)  # src_addr
    raw[5:7] = b"\xAA\xBB"  # tag
    raw[7:20] = bytes(range(13))  # ciphertext

    sno, src, tag, ct = parse_notification_wire(bytes(raw))
    assert sno == b"\x01\x02\x03"
    assert src == 0x0005
    assert tag == b"\xAA\xBB"
    assert len(ct) == 13


def test_parse_notification_wire_wrong_length():
    try:
        parse_notification_wire(b"\x00" * 10)
        assert False, "expected ValueError"
    except ValueError:
        pass


# --- 0xDB (unicast poll response) ---

def test_parse_device_status_0xdb():
    payload = bytearray(10)
    payload[0] = 0x00  # padding
    payload[1] = 0x16  # type (wire-halved)
    payload[2] = 0x0C  # stype (wire-halved)
    payload[3] = 0x47  # status_byte — online + alarmDev + version 0x11
    payload[4] = 0xFF  # mac[5]
    payload[5] = 0xEE  # mac[4]
    payload[6] = 0xDD  # mac[3]
    payload[7] = 0xCC  # mac[2]
    payload[8] = 0x05  # routing_metric
    payload[9] = 0x01  # on_state = ON

    n = Notification(source=0x007D, opcode=0xDB, vendor=0x0211, payload=bytes(payload))
    ds = parse_device_status(n)

    assert ds.address == 0x007D
    assert ds.is_on is True
    assert ds.type == 0x16
    assert ds.stype == 0x0C
    assert ds.status_byte == 0x47
    assert ds.status_flags is not None
    assert ds.status_flags.online is True
    assert ds.status_flags.alarm_dev is True
    assert ds.status_flags.version == 0x11
    assert ds.mac[5] == 0xFF
    assert ds.mac[4] == 0xEE


def test_parse_device_status_0xdb_off():
    payload = bytearray(10)
    payload[1] = 0x16  # type
    payload[2] = 0x0C  # stype
    payload[3] = 0x45  # status_byte — online, no alarmDev, version 0x11
    payload[9] = 0x00  # OFF

    n = Notification(source=0x0002, opcode=0xDB, vendor=0x0211, payload=bytes(payload))
    ds = parse_device_status(n)

    assert ds.address == 0x0002
    assert ds.is_on is False
    assert ds.status_byte == 0x45
    assert ds.status_flags is not None
    assert ds.status_flags.alarm_dev is False
    assert ds.status_flags.online is True


# --- 0xDC (broadcast status, two devices packed) ---

def test_parse_device_status_broadcast():
    """0xDC payload with two devices packed."""
    payload = bytes.fromhex("5ec20080fb6b00800000")
    n = Notification(source=0, opcode=0xDC, vendor=0x0211, payload=payload)
    statuses = parse_device_status_broadcast(n)

    assert len(statuses) == 2
    assert statuses[0].address == 0x5E
    assert statuses[1].address == 0xFB


def test_parse_device_status_broadcast_all_devices():
    """All 20 device addresses are extracted from 10 broadcast notifications."""
    payloads = [
        "5ec20080fb6b00800000",
        "5156008009cc00800000",
        "2f8a649030ed00b00000",
        "90bc00b0e4ed64a00000",
        "7dd500b0010000800000",
        "29000090d00000a00000",
        "3a0000807f0000850000",
        "72000090270000800000",
        "66000085b70000800000",
        "36000080400000950000",
    ]
    expected_addrs = {
        94, 251, 81, 9, 47, 48, 144, 228, 125, 1,
        41, 208, 58, 127, 114, 39, 102, 183, 54, 64,
    }

    found = set()
    for hex_payload in payloads:
        n = Notification(source=0, opcode=0xDC, vendor=0x0211, payload=bytes.fromhex(hex_payload))
        for ds in parse_device_status_broadcast(n):
            found.add(ds.address)

    assert found == expected_addrs


def test_parse_device_status_broadcast_with_brightness():
    """Non-zero brightness on slot 0, zero brightness on slot 1."""
    payload = bytes.fromhex("2f8a649030ed00b00000")
    n = Notification(source=0, opcode=0xDC, vendor=0x0211, payload=payload)
    statuses = parse_device_status_broadcast(n)

    first, second = statuses
    assert first.address == 0x2F
    assert first.is_on is True  # brightness=0x64
    assert second.address == 0x30
    assert second.is_on is False  # brightness=0x00
