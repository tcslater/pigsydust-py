"""Extract the SAL Pixie DeviceType lookup table from a blutter dump.

Source function: pixie_sdk._dtyps()  — the int -> DeviceType decoder map.
Replaces extract_devicetype_table.py, which read getTypeStype() (the encoder)
and resolved enum names against the wrong enum class in pp.txt.

Wire encoding in fun=0x1b LightInfoReq response (vendor 0x0211):
   byte[12] = product = type / 2
   byte[13] = type    = stype / 2
   key = (byte12 * 2) * 1000 + (byte13 * 2)

Prerequisite: run blutter against the APK's libapp.so first, e.g.:
    python3 ~/src/blutter/blutter.py path/to/lib/arm64-v8a out_dir

Usage:
    python3 extract_devicetype_table_v2.py <blutter_out_dir> > devicetype_table.txt
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("blutter_out", type=Path, help="Blutter output directory")
    args = parser.parse_args()

    asm_path = args.blutter_out / "asm" / "pixie_sdk" / "pixie_sdk.dart"
    pp_path = args.blutter_out / "pp.txt"

    pp_map = _build_devicetype_address_map(pp_path.read_text())
    body = _extract_function_body(asm_path.read_text(), "_dtyps")
    pairs = _extract_pairs(body, pp_map)

    _print_table(pairs)


def _build_devicetype_address_map(pp_text: str) -> dict[int, str]:
    """Return {pp_offset: enum_name} for every DeviceType enum object in pp.txt."""
    out: dict[int, str] = {}
    pattern = re.compile(
        r"\[pp\+0x([0-9a-f]+)\] Obj!DeviceType@[0-9a-f]+ : \{\s*"
        r"Super!_Enum : \{\s*off_8: int\(0x[0-9a-f]+\),\s*off_10: \"([^\"]+)\""
    )
    for m in pattern.finditer(pp_text):
        out[int(m.group(1), 16)] = m.group(2)
    return out


def _extract_function_body(asm_text: str, fn_name: str) -> list[str]:
    lines = asm_text.splitlines()
    start = next(i for i, l in enumerate(lines) if f" {fn_name}(" in l and "static " in l)
    end = next(i for i, l in enumerate(lines[start + 1 :], start + 1) if l.startswith("  static "))
    return lines[start:end]


def _extract_pairs(body: list[str], pp_map: dict[int, str]) -> list[tuple[int, str]]:
    """Walk the disassembly comments, pairing int keys with DeviceType pp offsets."""
    re_int = re.compile(r"// 0x[0-9a-f]+: r17 = (\d+)$")
    re_enum = re.compile(r"\[pp\+0x([0-9a-f]+)\] Obj!DeviceType@")

    events: list[tuple[str, int]] = []
    for line in body:
        if (m := re_int.search(line)):
            events.append(("int", int(m.group(1))))
        elif (m := re_enum.search(line)):
            events.append(("enum", int(m.group(1), 16)))

    pairs: list[tuple[int, str]] = []
    i = 0
    while i < len(events) - 1:
        if events[i][0] == "int" and events[i + 1][0] == "enum":
            key = events[i][1]
            pp_off = events[i + 1][1]
            pairs.append((key, pp_map.get(pp_off, f"<unknown pp+0x{pp_off:x}>")))
            i += 2
        else:
            i += 1
    return pairs


def _print_table(pairs: list[tuple[int, str]]) -> None:
    print(f"# Extracted {len(pairs)} (key, DeviceType) pairs from _dtyps()")
    print("# key encoding: type * 1000 + stype")
    print("# wire bytes are HALF: wire_byte_12 = type/2, wire_byte_13 = stype/2")
    print()
    print(f"{'key':>10}  {'type':>4}  {'stype':>5}  {'wire_b12':>8}  {'wire_b13':>8}  enum")
    for key, name in sorted(pairs):
        t, s = key // 1000, key % 1000
        b12 = str(t // 2) if t % 2 == 0 else f"{t/2:.1f}"
        b13 = str(s // 2) if s % 2 == 0 else f"{s/2:.1f}"
        print(f"{key:>10}  {t:>4}  {s:>5}  {b12:>8}  {b13:>8}  {name}")


if __name__ == "__main__":
    main()
