"""Notification parsing for the Telink BLE mesh protocol."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .const import OP_STATUS_BROADCAST_RESP, OP_STATUS_POLL_RESP
from .crypto import decrypt, notification_nonce


@dataclass
class DeviceStatus:
    """Decoded status of a mesh device."""

    address: int
    is_on: bool
    device_type: int
    mac: bytes


@dataclass
class Notification:
    """A decoded mesh notification."""

    source: int
    opcode: int
    vendor: int
    payload: bytes


def parse_notification_wire(raw: bytes) -> tuple[bytes, int, bytes, bytes]:
    """Extract fields from a raw 20-byte notification packet.

    Returns ``(sno, src_addr, tag, ciphertext)``.
    """
    if len(raw) != 20:
        raise ValueError(f"notification must be 20 bytes, got {len(raw)}")
    sno = raw[0:3]
    src_addr = struct.unpack_from("<H", raw, 3)[0]
    tag = raw[5:7]
    ciphertext = raw[7:20]
    return sno, src_addr, tag, ciphertext


def decrypt_notification(
    sk: bytes, gw_mac: bytes, raw: bytes
) -> Notification:
    """Decrypt a raw 20-byte notification and return a :class:`Notification`."""
    sno, src_addr, tag, ciphertext = parse_notification_wire(raw)
    nonce = notification_nonce(gw_mac, sno, src_addr)
    plaintext = decrypt(sk, nonce, tag, ciphertext)

    if len(plaintext) < 3:
        raise ValueError(f"notification plaintext too short ({len(plaintext)} bytes)")

    return Notification(
        source=src_addr,
        opcode=plaintext[0],
        vendor=struct.unpack_from("<H", plaintext, 1)[0],
        payload=plaintext[3:],
    )


def parse_device_status(n: Notification) -> DeviceStatus:
    """Extract a :class:`DeviceStatus` from a 0xDB notification.

    0xDB is a unicast status poll response with ``src_addr`` set in the
    wire header.  Payload format (10 bytes after opcode+vendor)::

        padding(1) || product_rev(1) || product_class(1) || device_type(1) ||
        mac[5:4:3:2](4) || routing_metric(1) || on_off(1)
    """
    if n.opcode != OP_STATUS_POLL_RESP:
        raise ValueError(f"expected opcode 0xDB, got 0x{n.opcode:02X}")
    if len(n.payload) < 10:
        raise ValueError(f"status payload too short ({len(n.payload)} bytes)")

    mac = bytearray(6)
    mac[5] = n.payload[4]
    mac[4] = n.payload[5]
    mac[3] = n.payload[6]
    mac[2] = n.payload[7]

    return DeviceStatus(
        address=n.source,
        is_on=n.payload[9] != 0,
        device_type=n.payload[3],
        mac=bytes(mac),
    )


def parse_device_status_broadcast(n: Notification) -> list[DeviceStatus]:
    """Extract device statuses from a 0xDC broadcast notification.

    0xDC is the burst response to a 0xC5 status query.  Wire ``src_addr``
    is 0 (broadcast); the actual device addresses are embedded in the
    payload which packs **two** device statuses per notification.

    Payload layout (10 bytes after opcode+vendor)::

        dev_a_addr(1) || dev_a_metric(1) || dev_a_brightness(1) || dev_a_flags(1) ||
        dev_b_addr(1) || dev_b_metric(1) || dev_b_brightness(1) || dev_b_flags(1) ||
        padding(2)

    The on/off state is inferred from the brightness byte (0x00 = off,
    non-zero = on).  This is tentative and may need refinement.
    """
    if n.opcode != OP_STATUS_BROADCAST_RESP:
        raise ValueError(f"expected opcode 0xDC, got 0x{n.opcode:02X}")
    if len(n.payload) < 8:
        raise ValueError(f"broadcast payload too short ({len(n.payload)} bytes)")

    results = []
    for offset in (0, 4):
        addr = n.payload[offset]
        if addr == 0:
            continue  # skip empty slot
        brightness = n.payload[offset + 2]
        flags = n.payload[offset + 3]

        results.append(DeviceStatus(
            address=addr,
            is_on=brightness != 0,
            device_type=flags,
            mac=bytes(6),  # not available in 0xDC format
        ))

    return results
