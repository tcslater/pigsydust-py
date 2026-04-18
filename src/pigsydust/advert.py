"""Parser for the SAL Pixie BLE manufacturer-data advertisement.

The manufacturer blob (company ID 0x0211) carries the mesh device's MAC,
a packed flag byte the Pixie app labels ``majorType`` (online /
alarmDev / firmware version), and a 16-bit value the app labels
``minjorType`` (sic) that almost certainly identifies the device class
(wall switch vs dimmer vs RGB strip etc.).

See ``ha-pigsydust/PLAN.md`` Stage 0 for the disassembly that
established this layout.
"""

from __future__ import annotations

from dataclasses import dataclass

from .const import MANUFACTURER_ID
from .device_class import DeviceClass


@dataclass(frozen=True)
class MajorTypeFlags:
    """Decoded bit layout of the ``majorType`` byte (byte[14] of the blob).

    Per disassembly of ``bt_struct.framework``::

        bit 0    -> online flag
        bit 1    -> alarmDev flag (participates in an alarm group/scene)
        bits 2-7 -> 6-bit firmware version

    The Pixie app's name ``majorType`` is misleading — this is *not* a
    device-class enum.  Device class lives in :attr:`PixieAdvert.minor_type`.
    """

    online: bool
    alarm_dev: bool
    version: int

    @classmethod
    def from_byte(cls, b: int) -> MajorTypeFlags:
        return cls(
            online=bool(b & 0x01),
            alarm_dev=bool((b >> 1) & 0x01),
            version=b >> 2,
        )


@dataclass(frozen=True)
class PixieAdvert:
    """Parsed fields from a Pixie manufacturer-data advertisement."""

    mac: bytes
    major_type: int
    major_type_flags: MajorTypeFlags
    minor_type: int
    raw: bytes
    device_class: DeviceClass | None = None


def parse_pixie_advert(
    manufacturer_data: dict[int, bytes] | None,
) -> PixieAdvert | None:
    """Extract :class:`PixieAdvert` from a BLE manufacturer-data dict.

    Returns ``None`` if the manufacturer ID isn't present or the blob is
    too short to hold ``minorType`` (bytes[15..16]).  Callers that only
    need the MAC can accept a shorter blob by reading
    :attr:`PixieAdvert.mac` after a successful parse; this helper
    deliberately requires the full fixed-offset range so that every
    field on the returned object is well-defined.
    """
    if manufacturer_data is None:
        return None
    data = manufacturer_data.get(MANUFACTURER_ID)
    if data is None or len(data) < 17:
        return None

    # MAC layout: the blob carries four MAC octets at bytes 2..5 in the
    # order {mac[5], mac[4], mac[3], mac[2]}.  mac[0] and mac[1] are
    # always 0 for Pixie devices.
    mac = bytes([0, 0, data[5], data[4], data[3], data[2]])

    major = data[14]
    minor = int.from_bytes(data[15:17], "big")

    return PixieAdvert(
        mac=mac,
        major_type=major,
        major_type_flags=MajorTypeFlags.from_byte(major),
        minor_type=minor,
        raw=bytes(data),
        device_class=DeviceClass.from_minor_type(minor),
    )
