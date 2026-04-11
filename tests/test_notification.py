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
    payload[1] = 0x16  # product_rev
    payload[2] = 0x0C  # product_class
    payload[3] = 0x47  # device_type = gateway
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
    assert ds.device_type == 0x47
    assert ds.mac[5] == 0xFF
    assert ds.mac[4] == 0xEE


def test_parse_device_status_0xdb_off():
    payload = bytearray(10)
    payload[3] = 0x45  # leaf
    payload[9] = 0x00  # OFF

    n = Notification(source=0x0002, opcode=0xDB, vendor=0x0211, payload=bytes(payload))
    ds = parse_device_status(n)

    assert ds.address == 0x0002
    assert ds.is_on is False
    assert ds.device_type == 0x45


# --- 0xDC (broadcast status, two devices packed) ---

def test_parse_device_status_broadcast():
    """Test parsing a real 0xDC payload with two devices."""
    # Laundry (addr=0x5E) and Verandah (addr=0xFB)
    payload = bytes.fromhex("5ec20080fb6b00800000")
    n = Notification(source=0, opcode=0xDC, vendor=0x0211, payload=payload)
    statuses = parse_device_status_broadcast(n)

    assert len(statuses) == 2
    assert statuses[0].address == 0x5E  # Laundry
    assert statuses[1].address == 0xFB  # Verandah


def test_parse_device_status_broadcast_all_devices():
    """Verify all 20 devices are extracted from 10 notifications."""
    payloads = [
        "5ec20080fb6b00800000",  # Laundry(94), Verandah(251)
        "5156008009cc00800000",  # Back door(81), Mud Room(9)
        "2f8a649030ed00b00000",  # Kitchen(47), Flood Light(48)
        "90bc00b0e4ed64a00000",  # Dining(144), Store Room(228)
        "7dd500b0010000800000",  # Lounge(125), Bridge(1)
        "29000090d00000a00000",  # Toilet Basin(41), Entrance(208)
        "3a0000807f0000850000",  # Bed Outside(58), Alex down(127)
        "72000090270000800000",  # Front door(114), Bathroom(39)
        "66000085b70000800000",  # Alex Loft(102), Toilet(183)
        "36000080400000950000",  # Bedroom(54), Alex outside(64)
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
    """Kitchen has brightness=0x64 (100), should be ON."""
    # Kitchen(47) metric=0x8A brightness=0x64, Flood Light(48) metric=0xED brightness=0x00
    payload = bytes.fromhex("2f8a649030ed00b00000")
    n = Notification(source=0, opcode=0xDC, vendor=0x0211, payload=payload)
    statuses = parse_device_status_broadcast(n)

    kitchen = statuses[0]
    flood = statuses[1]
    assert kitchen.address == 0x2F  # 47
    assert kitchen.is_on is True  # brightness=0x64
    assert flood.address == 0x30  # 48
    assert flood.is_on is False  # brightness=0x00
