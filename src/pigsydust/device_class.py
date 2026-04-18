"""Pixie device-class enum (``minjorType`` in the SAL Pixie app's terms).

The 16-bit big-endian value at bytes ``[15..16]`` of the manufacturer-data
blob identifies the hardware class — wall switch vs dimmer vs RGB strip
etc.  The mapping below was extracted from ``libapp.so`` (SAL PIXIE
Android v2.15.2375) with `blutter
<https://github.com/worawit/blutter>`_; see
``scripts/extract_devicetype_table.py`` and
``scripts/devicetype_table.txt`` for the regeneration workflow when SAL
ships a new app release.

Identifiers here are the canonical, presentation-neutral protocol keys.
Human-readable names are the consumer's concern — e.g. the Home Assistant
integration maps them to localised strings via its translation files.
"""

from __future__ import annotations

from enum import IntEnum


class DeviceClass(IntEnum):
    """Pixie device class, keyed on the 16-bit BE int at advert bytes [15..16]."""

    BRIDGE = 0x0216
    BRIDGE_G2 = 0x0204
    SWITCH = 0x2C16
    DESKTOP = 0x2C18
    LAPTOP = 0x2C1A
    TSWITCH = 0x2A18
    DIMMER = 0x2E16
    DIMMER_G2 = 0x2E18
    DIMMER_G3 = 0x2E1A
    RFD = 0x281A
    STRIP_W = 0x3004
    FCS = 0x3006
    STRIP_RGB = 0x3604
    FCR = 0x3606
    POL = 0x020E
    SPO2 = 0x0410
    # SPO3 shares SPO2's encoding (0x0410) in the Dart table; IntEnum
    # would make it an alias anyway.  Callers see SPO2.name for both.
    DRC = 0x1404
    BSC = 0x1604
    FAN_CT = 0x6C1E
    FAN_ONLY = 0x0C1E
    FAN_CT9 = 0x721E
    FAN_ONLY9 = 0x121E
    VFAN_CT = 0x6A1E
    VFAN_ONLY = 0x0A1E
    BFAN_ONLY = 0x0E60
    STRIP2_RGBCCT = 0x3408
    STRIP2_RGB = 0x3608
    STRIP2_CCT = 0x3208
    RGB_X = 0x36C6
    IR36 = 0x3C02
    IR12 = 0x3C04
    SMR = 0x3C06
    TSWITCHG2 = 0x2A1A
    RFD_CT = 0x321A
    DRS = 0x3C14
    DRSM2 = 0x3C16
    DRSM3 = 0x3C18
    DM10 = 0x3060
    DALI_DT6 = 0x3062
    GDC1 = 0x1802
    GDC1_SW = 0x1804
    GDC1_SL = 0x1806
    GDC1_W = 0x1810
    GDC2 = 0x1822
    GDC1_M2 = 0x1A02
    GDC1_M2W = 0x1A04
    GDC1_M2L = 0x1A06
    RFD2 = 0x3068
    RFD2_CT = 0x3268
    RCT_W = 0x3064
    RCT_CCT = 0x3264
    RCT_RGB = 0x3664
    RCT_RGBW = 0x3464
    RCT_RGBCCT = 0x3864
    ZCL = 0x106C
    ACF_VRV = 0x0466
    ACF_DUCTED = 0x0266
    SGB = 0x021C
    SGB3 = 0x6610
    SGBX = 0x0468
    SGBX2 = 0x046A
    SGBX0 = 0x6A6A
    # DELAY (idx 80) returns (19998, 19998) from getTypeStype — a sentinel
    # that can't be expressed as (type << 8) | stype in 16 bits, so it is
    # intentionally omitted.  It cannot appear in a 16-bit advert field.

    @classmethod
    def from_minor_type(cls, value: int | None) -> DeviceClass | None:
        """Look up the device class for a 16-bit ``minor_type`` value.

        Returns ``None`` if ``value`` is ``None`` or not a known class.
        Unknown values are common — SAL periodically ships new hardware
        and the enum needs to be regenerated from a fresh app release.
        """
        if value is None:
            return None
        try:
            return cls(value)
        except ValueError:
            return None
