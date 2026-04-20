"""Tests for command builders — verify wire format."""

import struct

from pigsydust.command import query_status, set_utc, status_poll, turn_off, turn_on
from pigsydust.const import (
    ADDR_BROADCAST,
    OP_ON_OFF,
    OP_STATUS_POLL,
    OP_STATUS_QUERY,
    OP_TYPE_CLIENT,
    VENDOR_SKYTONE,
    VENDOR_SKYTONE_ALT,
)


def _wire_opcode(opcode: int) -> int:
    return (OP_TYPE_CLIENT << 6) | (opcode & 0x3F)


def test_turn_on():
    buf = turn_on(0x0001)
    assert len(buf) == 15
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == 0x0001
    assert buf[2] == _wire_opcode(OP_ON_OFF)
    vendor = struct.unpack_from("<H", buf, 3)[0]
    assert vendor == VENDOR_SKYTONE
    assert buf[5] == 0x01  # ON


def test_turn_off():
    buf = turn_off(0x0003)
    assert len(buf) == 15
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == 0x0003
    assert buf[5] == 0x00  # OFF


def test_turn_on_broadcast():
    buf = turn_on(ADDR_BROADCAST)
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == ADDR_BROADCAST


def test_query_status():
    buf = query_status()
    assert len(buf) == 10
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == ADDR_BROADCAST
    assert buf[2] == _wire_opcode(OP_STATUS_QUERY)


def test_status_poll():
    buf = status_poll(0x00E4)
    assert len(buf) == 7
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == 0x00E4
    assert buf[2] == _wire_opcode(OP_STATUS_POLL)
    vendor = struct.unpack_from("<H", buf, 3)[0]
    assert vendor == VENDOR_SKYTONE_ALT
    assert buf[5:7] == b"\x10\x00"


def test_set_utc():
    now = 1700000000.0
    buf = set_utc(now)
    assert len(buf) == 15
    dst = struct.unpack_from("<H", buf, 0)[0]
    assert dst == ADDR_BROADCAST
    ts = struct.unpack_from("<I", buf, 5)[0]
    assert ts == 1700000000
    assert buf[9] == 0x00  # timezone byte must be zero
