"""Sweep every visible gateway-capable Pixie device and check whether its
self-reply 0xDB MAC matches its DIS / config MAC.

We discovered via ``probe_0xdb_layout.py`` that Verandah (addr 251) reports
a different mac[3] in its self-reply (0x58) than what DIS/config claim
(0x5C). Verandah was the only sampled device that misbehaved when
self-replying as gateway.

This script widens the sample: scan all visible Pixie candidates, connect
to each in turn, poll the gateway's own address, and record:

    dev_addr | config name | DIS MAC (low 4 bytes) | payload MAC slice | match?

A useful pattern would emerge if e.g. *every* gateway shows a specific
byte anomaly (protocol quirk, not unit-specific), or if only a subset do
(hinting at a firmware revision issue).

Usage
-----
    python examples/probe_gateway_mac.py <config.toml>
"""

import asyncio
import sys
import tomllib

from bleak import BleakScanner

from pigsydust import PixieClient
import pigsydust.client as _client_mod
from pigsydust.notification import parse_device_status as _orig_parse


_raw_0xdb: dict[int, str] = {}


def _hooked_parse(n):
    ds = _orig_parse(n)
    _raw_0xdb[n.source] = bytes(n.payload).hex()
    return ds


_client_mod.parse_device_status = _hooked_parse


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def name_for(dev_addr: int, devices: list[dict]) -> str:
    for d in devices:
        if d.get("dev_addr") == dev_addr:
            return d.get("name", "(unknown)")
    return "(not in config)"


def config_mac_for(dev_addr: int, devices: list[dict]) -> str | None:
    for d in devices:
        if d.get("dev_addr") == dev_addr:
            return d.get("mac")
    return None


def _low_byte_of_mfr_mac(mfr_data: dict[int, bytes]) -> int | None:
    """Low byte of the BLE MAC from 0x0211 manufacturer data.

    Per ``client._extract_mac_from_manufacturer_data``: the BLE MAC low byte
    (== dev_addr for Pixie) lives at ``data[2]``.
    """
    data = mfr_data.get(0x0211)
    if data is None or len(data) < 6:
        return None
    return data[2]


async def scan_candidates(mesh_name: str) -> list[tuple[str, int | None, str | None]]:
    """Return (ble_uuid, mesh_low_byte, adv_name) for each visible Pixie."""
    adv_map = await BleakScanner.discover(timeout=10.0, return_adv=True)
    out: list[tuple[str, int | None, str | None]] = []
    for d, adv in adv_map.values():
        mfr = adv.manufacturer_data or {}
        if not ((d.name and mesh_name in d.name) or 0x0211 in mfr):
            continue
        out.append((d.address, _low_byte_of_mfr_mac(mfr), d.name))
    # De-duplicate by BLE UUID
    seen_uuids: set[str] = set()
    dedup: list[tuple[str, int | None, str | None]] = []
    for item in out:
        if item[0] in seen_uuids:
            continue
        seen_uuids.add(item[0])
        dedup.append(item)
    return dedup


async def probe_one(
    ble_uuid: str, mesh_name: str, mesh_password: str, devices: list[dict]
) -> dict | None:
    """Connect, poll self, return a row dict (or None on failure)."""
    client = PixieClient(ble_uuid)
    try:
        await client.connect()
        await client.login(mesh_name, mesh_password)

        dis_mac_str = client.gateway_mac  # "AA:BB:CC:DD:EE:FF"
        dis_low4 = bytes.fromhex(dis_mac_str.replace(":", ""))[2:6]
        gw_dev_addr = dis_low4[3]  # low byte of MAC

        _raw_0xdb.pop(gw_dev_addr, None)
        ds = await client.ping_device(gw_dev_addr, timeout=3.0)
        raw = _raw_0xdb.get(gw_dev_addr)
        if ds is None or raw is None or len(raw) < 16:
            return {
                "ble_uuid": ble_uuid,
                "dev_addr": gw_dev_addr,
                "dis_mac": dis_mac_str,
                "name": name_for(gw_dev_addr, devices),
                "config_mac": config_mac_for(gw_dev_addr, devices),
                "payload_slice": None,
                "match": None,
                "note": "no self-reply",
            }

        # payload bytes [4..7] = mac[5:2] per parse_device_status docstring
        payload_slice = bytes.fromhex(raw[8:16])

        # Reverse the payload slice to get MAC mac[2..5] for comparison
        mac_low4_from_payload = bytes(reversed(payload_slice))
        match = (mac_low4_from_payload == dis_low4)

        return {
            "ble_uuid": ble_uuid,
            "dev_addr": gw_dev_addr,
            "dis_mac": dis_mac_str,
            "name": name_for(gw_dev_addr, devices),
            "config_mac": config_mac_for(gw_dev_addr, devices),
            "payload_slice": payload_slice.hex(),
            "payload_mac_low4": mac_low4_from_payload.hex(),
            "dis_mac_low4": dis_low4.hex(),
            "match": match,
            "note": "ok",
        }
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass


async def main(config_path: str) -> None:
    cfg = load_config(config_path)
    mesh_name = cfg["mesh"]["name"]
    mesh_password = cfg["mesh"]["password"]
    devices = cfg.get("devices", [])

    print(f"Scanning for Pixie candidates (mesh={mesh_name!r})...")
    candidates = await scan_candidates(mesh_name)
    print(f"  {len(candidates)} candidate BLE UUIDs found\n")

    rows: list[dict] = []
    for i, (uuid, _low, advname) in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] Connecting to {uuid} (adv={advname!r})...")
        try:
            row = await probe_one(uuid, mesh_name, mesh_password, devices)
        except Exception as err:
            print(f"           -> FAILED: {err}")
            continue
        if row is None:
            continue
        rows.append(row)
        print(
            f"           -> dev_addr={row['dev_addr']} "
            f"({row['name']})  match={row['match']}  note={row['note']}"
        )
        await asyncio.sleep(1.0)

    print("\n\nSummary:")
    print(
        f"{'addr':>4}  {'name':<20}  {'dis_mac_low4':<13}  "
        f"{'payload_low4':<13}  {'match':<5}"
    )
    print("-" * 72)
    for r in sorted(rows, key=lambda x: x["dev_addr"] or 0):
        match_str = "YES" if r["match"] else ("NO" if r["match"] is False else "?")
        print(
            f"{r['dev_addr']:>4}  {r['name']:<20}  "
            f"{r.get('dis_mac_low4', '-'):<13}  "
            f"{r.get('payload_mac_low4', '-'):<13}  {match_str:<5}"
        )

    mismatches = [r for r in rows if r["match"] is False]
    print(f"\nTotal gateways probed: {len(rows)}")
    print(f"Mismatched self-reply MACs: {len(mismatches)}")
    if mismatches:
        print("\nMismatch detail (DIS byte → payload byte):")
        for r in mismatches:
            a = bytes.fromhex(r["dis_mac_low4"])
            b = bytes.fromhex(r["payload_mac_low4"])
            diffs = [f"[{i}] 0x{a[i]:02X}->0x{b[i]:02X}" for i in range(4) if a[i] != b[i]]
            print(f"  addr {r['dev_addr']:>3} ({r['name']}): {', '.join(diffs)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
