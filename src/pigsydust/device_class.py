"""Pixie device-class lookup.

Resolves wire ``(type, stype)`` advert bytes (offsets 6-7) — and the same
fields in a decrypted ``0xDB`` status response — to a device-class
identifier per ``docs/PROTOCOL-REFERENCE.md``.

Wire bytes are **halved** against the canonical identifier:

    canonical_type  = wire_type * 2
    canonical_stype = wire_stype * 2
    key             = canonical_type * 1000 + canonical_stype
"""

from __future__ import annotations

from enum import IntEnum


class DeviceClass(IntEnum):
    """Canonical Pixie device class, keyed by ``type * 1000 + stype``.

    Values are the post-halving spec lookup keys. Use
    :func:`device_class_lookup` / :func:`device_class_name` to resolve
    raw wire bytes.
    """

    SGBX0 = 106
    BRIDGE_G2 = 2004
    POL = 2014
    BRIDGE = 2022
    SGB = 2028
    ACF_DUCTED = 2102
    SPO3 = 4016
    ACF_VRV = 4102
    SGBX = 4104
    SGBX2 = 4106
    VFAN_ONLY = 10030
    FAN_ONLY = 12030
    BFAN_ONLY = 14096
    ZCL = 16108
    FAN_ONLY9 = 18030
    DRC = 20004
    BSC = 22004
    GDC1 = 24002
    GDC1_SW = 24004
    GDC1_SL = 24006
    GDC1_W = 24016
    GDC2 = 24034
    GDC1_M2 = 26002
    GDC1_M2W = 26004
    GDC1_M2L = 26006
    DV02 = 34048
    RFD = 40026
    RFD2_SCAN = 40104
    TSWITCH = 42024
    TSWITCHG2 = 42026
    ECL_AC = 42096
    SWITCH = 44002
    SWITCH_G2 = 44024
    SWITCH_G3 = 44026
    DIMMER = 46022
    DIMMER_G2 = 46024
    DIMMER_G3 = 46026
    STRIP_W = 48004
    FCS = 48006
    SFI_8266 = 48064
    SFI_825X = 48066
    DM10 = 48096
    DALI_DT6 = 48098
    RCT_W = 48100
    RFD2 = 48104
    STRIP2_CCT = 50008
    RFD_CT = 50026
    RCT_CCT = 50100
    RFD2_CT = 50104
    STRIP2_RGBCCT = 52008
    RCT_RGBW = 52100
    STRIP_RGB = 54004
    FCR = 54006
    STRIP2_RGB = 54008
    RCT_RGB = 54100
    RGB_X = 54198
    RCT_RGBCCT = 56100
    IR36 = 60002
    IR12 = 60004
    SMR = 60006
    DRS = 60020
    DRSM2 = 60022
    DRSM3 = 60024
    CAP = 102002
    MTW = 102004
    STC = 102006
    MTW2_AL = 102008
    MTW2_AN = 102010
    MRC = 102012
    CAP3 = 102014
    SGB3 = 102016
    SIC = 102020
    DIAL = 102040
    VFAN_CT = 106030
    FAN_CT = 108030
    FAN_CT9 = 114030
    SONOS = 180002
    # ACF_RS8 matches wire ``stype == 0x39`` (canonical stype 114) for any
    # type. Represented here with a synthetic key outside the normal
    # ``type*1000 + stype`` space so direct lookups don't collide.
    ACF_RS8 = 10000114


# Wire-identifier aliases that share a canonical name. The spec lists
# both (44, 2) and (44, 22) as ``SWITCH``; keep the enum member unique
# and route the aliased key through a separate table.
_ALIASES: dict[int, DeviceClass] = {
    44022: DeviceClass.SWITCH,
}


def device_class_lookup(wire_type: int, wire_stype: int) -> DeviceClass | None:
    """Resolve wire bytes to a :class:`DeviceClass`, or ``None`` if unknown.

    Applies the ``*2`` halving rule, then the ACF_RS8 shortcut for
    ``wire_stype == 0x39``, and finally falls back to a raw-bytes lookup.
    """
    if wire_stype == 0x39:
        return DeviceClass.ACF_RS8
    canonical = (wire_type * 2) * 1000 + wire_stype * 2
    try:
        return DeviceClass(canonical)
    except ValueError:
        pass
    if canonical in _ALIASES:
        return _ALIASES[canonical]
    raw = wire_type * 1000 + wire_stype
    try:
        return DeviceClass(raw)
    except ValueError:
        return _ALIASES.get(raw)


def device_class_name(wire_type: int, wire_stype: int) -> str | None:
    """Resolve wire bytes to a device-class identifier string, or ``None``."""
    cls = device_class_lookup(wire_type, wire_stype)
    return cls.name if cls is not None else None
