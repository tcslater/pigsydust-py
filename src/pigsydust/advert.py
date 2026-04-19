"""Parser for the SAL Pixie BLE manufacturer-data advertisement.

See ``docs/PROTOCOL-REFERENCE.md`` for the wire layout.
"""

from __future__ import annotations

from dataclasses import dataclass

from .const import MANUFACTURER_ID


@dataclass(frozen=True)
class StatusByteFlags:
    """Decoded bit layout of the packed status byte (advert byte[8])."""

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
    """Parsed fields from a Pixie manufacturer-data advertisement."""

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
