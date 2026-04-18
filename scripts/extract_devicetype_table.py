"""Extract the SAL Pixie DeviceType → (type, stype) mapping from a Dart AOT dump.

The mapping is what `pixie_sdk.dart::getTypeStype()` returns for each DeviceType
enum value. Verified against libapp.so v2.15.2375 (Dart 3.3.3); the function
addresses and the jump-table size will need updating for newer Pixie releases.

Prerequisite: run blutter against the APK's libapp.so first, e.g.:
    python3 ~/src/blutter/blutter.py path/to/lib/arm64-v8a out_dir
This produces `asm/pixie_sdk/pixie_sdk.dart` and `pp.txt`, both consumed here.

Usage:
    python3 extract_devicetype_table.py <blutter_out_dir> > devicetype_table.txt
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

# These will need bumping if the function moves in a future libapp build.
# Run `grep -n "static _ getTypeStype(" asm/pixie_sdk/pixie_sdk.dart` to find
# the new ** addr line; the BASE is the function entry point.
FUNC_BASE = 0xb3b5f8
JUMP_TABLE_SIZE = 81


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("blutter_out", type=Path, help="Blutter output directory")
    args = parser.parse_args()

    asm_path = args.blutter_out / "asm" / "pixie_sdk" / "pixie_sdk.dart"
    pp_path = args.blutter_out / "pp.txt"
    body = _extract_function_body(asm_path.read_text())
    offsets = _extract_jump_table(body, JUMP_TABLE_SIZE)
    addr_typestype = _extract_typestype_pairs(body, offsets, FUNC_BASE)
    names = _extract_enum_names(pp_path.read_text())
    _print_table(offsets, addr_typestype, names, FUNC_BASE)


def _extract_function_body(asm_text: str) -> str:
    m = re.search(r"static _ getTypeStype\(.*?\n(.*?)\n  \}\s*\n", asm_text, re.DOTALL)
    if not m:
        raise SystemExit("getTypeStype not found — function may have moved")
    return m.group(1)


def _extract_jump_table(body: str, size: int) -> list[int]:
    m = re.search(rf"_Int32List\({size}\) \[([^\]]+)\]", body)
    if not m:
        raise SystemExit(f"Jump table of size {size} not found in function body")
    return [int(x.strip(), 16) for x in m.group(1).split(",")]


def _extract_typestype_pairs(
    body: str, offsets: list[int], base: int
) -> dict[int, tuple[int, int]]:
    """Return {case_start_addr: (type, stype)} for each non-default case."""
    default = offsets[0]
    case_starts = sorted({base + off for off in offsets if off != default})

    current_addr = None
    last_mov = None
    pending: dict[str, int] = {}
    out: dict[int, tuple[int, int]] = {}

    for line in body.splitlines():
        addr_m = re.search(r"// 0x([0-9a-f]+):", line)
        if addr_m:
            current_addr = int(addr_m.group(1), 16)
        mov_m = re.search(r"mov\s+x17, #(0x[0-9a-f]+|\d+)", line)
        if mov_m:
            s = mov_m.group(1)
            last_mov = int(s, 16) if s.startswith("0x") else int(s)
        if "stur" in line and "[x0, #0x13]" in line and last_mov is not None:
            pending["type"] = last_mov
            pending["addr"] = current_addr  # type: ignore[assignment]
        if (
            "stur" in line
            and "[x0, #0x1b]" in line
            and last_mov is not None
            and "type" in pending
        ):
            pending["stype"] = last_mov
            case_start = max(
                (a for a in case_starts if a <= pending["addr"]), default=None
            )
            if case_start is not None and case_start not in out:
                out[case_start] = (pending["type"], pending["stype"])
            pending = {}
    return out


def _extract_enum_names(pp_text: str) -> dict[int, str]:
    pat = re.compile(
        r"Obj!DeviceType@\w+ : \{\s*Super!_Enum : \{\s*off_8: int\(0x([0-9a-f]+)\),"
        r"\s*off_10: \"([^\"]+)\""
    )
    return {int(m.group(1), 16): m.group(2) for m in pat.finditer(pp_text)}


def _print_table(
    offsets: list[int],
    addr_typestype: dict[int, tuple[int, int]],
    names: dict[int, str],
    base: int,
) -> None:
    default = offsets[0]
    print("# SAL Pixie DeviceType → (type, stype) mapping")
    print(f"# Extracted from libapp.so via blutter (getTypeStype @ 0x{base:x})")
    print("# (type << 8) | stype is the 16-bit big-endian value at bytes [15..16]")
    print("# of HA's manufacturer_data[0x0211] (i.e. raw Skytone bytes [11..12]).")
    print()
    print(f"{'idx':>3}  {'enum':<15}  {'type':>5}  {'stype':>5}  {'BE16':>6}  {'hex':>6}")
    print("-" * 50)
    for idx, off in enumerate(offsets):
        if off == default:
            continue
        name = names.get(idx, "?")
        pair = addr_typestype.get(base + off)
        if pair is None:
            print(f"{idx:>3}  {name:<15}  (no parse)")
            continue
        t, s = pair
        be = (t << 8) | s
        print(f"{idx:>3}  {name:<15}  {t:>5}  {s:>5}  {be:>6}  0x{be:04x}")
    print()
    print("# Indices that take the default branch (handled by _getTypeStypeP3rd):")
    for idx, off in enumerate(offsets):
        if off == default:
            print(f"#   {idx:>3}  0x{idx:02x}  {names.get(idx, '?')}")


if __name__ == "__main__":
    main()
