"""Command builders for the Telink BLE mesh protocol."""

from __future__ import annotations

import struct
import time

from .const import (
    ADDR_BROADCAST,
    OP_ON_OFF,
    OP_STATUS_POLL,
    OP_STATUS_QUERY,
    OP_TYPE_CLIENT,
    VENDOR_SKYTONE,
    VENDOR_SKYTONE_ALT,
)


def _encode(
    dst: int, opcode: int, vendor: int, data: bytes, length: int
) -> bytes:
    """Serialize a command to its plaintext byte representation.

    Format: ``dst(2 LE) || opcode(1) || vendor(2 LE) || data(N) || zero_pad``
    """
    buf = bytearray(length)
    struct.pack_into("<H", buf, 0, dst)
    buf[2] = (OP_TYPE_CLIENT << 6) | (opcode & 0x3F)
    struct.pack_into("<H", buf, 3, vendor)
    buf[5 : 5 + len(data)] = data
    return bytes(buf)


def turn_on(addr: int) -> bytes:
    """Build a turn-on command (opcode 0xED, 15-byte plaintext)."""
    return _encode(addr, OP_ON_OFF, VENDOR_SKYTONE, b"\x01", 15)


def turn_off(addr: int) -> bytes:
    """Build a turn-off command (opcode 0xED, 15-byte plaintext)."""
    return _encode(addr, OP_ON_OFF, VENDOR_SKYTONE, b"\x00", 15)


def query_status() -> bytes:
    """Build a broadcast status query (opcode 0xC5, 10-byte plaintext)."""
    return _encode(
        ADDR_BROADCAST,
        OP_STATUS_QUERY,
        VENDOR_SKYTONE,
        b"\x00\x00\xd7\x69\x00",
        10,
    )


def status_poll(dst: int) -> bytes:
    """Build a unicast status poll (opcode 0xDA, 7-byte plaintext).

    Vendor is :data:`VENDOR_SKYTONE_ALT` (0x0211), not the usual
    :data:`VENDOR_SKYTONE`. The target responds with a 0xDB unicast
    status notification carrying its MAC, device class, and on/off state.
    """
    return _encode(dst, OP_STATUS_POLL, VENDOR_SKYTONE_ALT, b"\x10\x00", 7)


def set_utc(now: float | None = None) -> bytes:
    """Build a time sync broadcast (opcode 0xC5, 15-byte plaintext).

    *now* is a Unix timestamp; defaults to the current time.
    """
    if now is None:
        now = time.time()
    data = struct.pack("<I", int(now)) + b"\x00"  # tz byte must be 0x00
    return _encode(ADDR_BROADCAST, OP_STATUS_QUERY, VENDOR_SKYTONE, data, 15)


def led_set_blue(addr: int, on: bool) -> bytes:
    """Build an LED blue channel command (opcode 0xFF, 15-byte plaintext).

    The blue channel is binary on/off (no PWM dimming).
    Each packet must update exactly one channel — orange bytes are zeroed.
    """
    level = 0x12 if on else 0x00
    return _encode(addr, 0xFF, VENDOR_SKYTONE, bytes([0xA0, level, 0x00, 0x00]), 15)


def led_set_orange(addr: int, level: int) -> bytes:
    """Build an LED orange channel command (opcode 0xFF, 15-byte plaintext).

    *level* is brightness 0-15 (0 = off).
    Each packet must update exactly one channel — blue bytes are zeroed.
    """
    return _encode(addr, 0xFF, VENDOR_SKYTONE, bytes([0x00, 0x00, 0xFF, level & 0x0F]), 15)


def find_me(addr: int, start: bool = True) -> bytes:
    """Build a find-me LED flash command (opcode 0xF5, 15-byte plaintext).

    When *start* is True, the device blinks for 15 seconds using the
    currently configured LED colour. When False, blinking stops.
    """
    if start:
        data = bytes([0x03, 0x0F])  # mode=blink, duration=15s
    else:
        data = bytes([0x00, 0x00])
    return _encode(addr, 0xF5, VENDOR_SKYTONE, data, 15)


def led_set_purple(addr: int, orange_level: int) -> bytes:
    """Build a combined LED command for purple (both channels on).

    This lights both blue and orange simultaneously, producing purple.
    WARNING: this latches the firmware into an undefined state.  Use
    :func:`led_reset_sequence` to clear it before sending single-channel
    commands again.
    """
    return _encode(
        addr, 0xFF, VENDOR_SKYTONE,
        bytes([0xA0, 0x12, 0xFF, orange_level & 0x0F]), 15,
    )
