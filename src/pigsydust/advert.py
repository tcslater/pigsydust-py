"""Parser for the SAL Pixie BLE manufacturer-data advertisement.

The manufacturer blob (company ID 0x0211) carries the mesh device's MAC,
a wire-level ``(type, stype)`` device-class identifier, a packed status
byte (online / alarmDev / firmware version), and a 4-byte mesh network
identifier.

Layout verified against live BLE scans and decrypted ``0xdb`` status
responses (see ``ha-pigsydust/PLAN.md`` Stage 0).
"""

from __future__ import annotations

from dataclasses import dataclass

from .const import MANUFACTURER_ID


@dataclass(frozen=True)
class StatusByteFlags:
    """Decoded bit layout of the packed status byte (advert byte[8]).

    Bit layout::

        bit 0    -> online flag
        bit 1    -> alarmDev flag (participates in an alarm group/scene)
        bits 2-7 -> 6-bit firmware version

    The same byte appears at offset 3 of a decrypted ``0xdb`` status
    response payload.
    """

    online: bool
    alarm_dev: bool
    version: int

    @classmethod
    def from_byte(cls, b: int) -> StatusByteFlags:
        return cls(
            online=bool(b & 0x01),
            alarm_dev=bool((b >> 1) & 0x01),
            version=b >> 2,
        )


@dataclass(frozen=True)
class PixieAdvert:
    """Parsed fields from a Pixie manufacturer-data advertisement.

    The blob layout (after the ``0x0211`` company ID is stripped by the
    BLE stack) is::

        [0..1]   echo of company ID (constant ``11 02``)
        [2..5]   MAC octets [5..2] in reverse — combine with ``00:21:`` for full MAC
        [6]      type — wire-level device class identifier
        [7]      stype — wire-level device class sub-identifier
        [8]      packed status byte (online / alarmDev / version)
        [9]      mesh device address (= MAC[5])
        [10]     reserved (always ``0x00``)
        [11..14] mesh network identifier (constant per home network)
        [15..]   zero padding

    For wall switches, ``(type, stype) = (0x16, 0x0c) = (22, 12)`` and the
    network identifier is mesh-specific. ``(type, stype)`` are the same
    fields ``bt_struct``'s ``dataParse`` fun=0x1b decodes from a ``0xdb``
    response; they are *not* the same as the values returned by the
    Dart-internal ``getTypeStype()`` enum.
    """

    mac: bytes
    type: int
    stype: int
    status_byte: int
    status_flags: StatusByteFlags
    mesh_address: int
    network_id: bytes
    raw: bytes


def parse_pixie_advert(
    manufacturer_data: dict[int, bytes] | None,
) -> PixieAdvert | None:
    """Extract :class:`PixieAdvert` from a BLE manufacturer-data dict.

    Returns ``None`` if the manufacturer ID isn't present or the blob is
    too short to hold the network identifier (bytes [11..14]).
    """
    if manufacturer_data is None:
        return None
    data = manufacturer_data.get(MANUFACTURER_ID)
    if data is None or len(data) < 15:
        return None

    mac = bytes([0, 0, data[5], data[4], data[3], data[2]])
    status = data[8]

    return PixieAdvert(
        mac=mac,
        type=data[6],
        stype=data[7],
        status_byte=status,
        status_flags=StatusByteFlags.from_byte(status),
        mesh_address=data[9],
        network_id=bytes(data[11:15]),
        raw=bytes(data),
    )
