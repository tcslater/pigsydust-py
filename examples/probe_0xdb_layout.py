"""Probe the 0xDB status-response payload layout.

We want to answer:

    In a 0xDB (unicast status poll) reply, what do bytes 8 and 9 actually
    encode?

Current pigsydust-py labels them ``routing_metric`` (byte 8) and an on/off
state (byte 9, via ``is_on = byte9 != 0``). Telink's SDK manual §6.9
relabels the same bytes as **ttc** (time-to-cost) and **hops**.  If Telink
is right, the current ``is_on`` test is coincidental and will misreport
whenever hops == 0 for an ON light, or hops > 0 for an OFF light.

How it works
------------
Before running, put a mix of devices into known on/off states (via HA, the
Pixie app, or physical switches).  The probe then unicasts a status_poll
to every responding device and dumps the raw 0xDB payload.  Cross-reference
the ``byte[8]`` / ``byte[9]`` columns against the known states + whether a
device is the gateway (hop 0) or a mesh-remote (hop >= 1).

Usage
-----
    python examples/probe_0xdb_layout.py <config.toml> [<exclude_dev_addr>]

    Optional second argument: a device dev_addr to *avoid* picking as the
    gateway. Useful for controlled experiments where we want to force the
    scan to pick a different entry node (e.g. to check whether a
    gateway-only MAC quirk disappears when the device replies via mesh
    relay rather than via direct GATT).

Output
------
    addr  is_gw  name              byte[8]  byte[9]  is_on_parsed  raw_payload_hex
    ----  -----  ----------------  -------  -------  ------------  ---------------
    ...
"""

import asyncio
import sys
import tomllib

from bleak import BleakScanner

from pigsydust import PixieClient
import pigsydust.client as _client_mod
from pigsydust.notification import parse_device_status as _orig_parse_device_status


# Keyed on dev_addr -> raw payload hex for its most-recent 0xDB.
_raw_0xdb: dict[int, str] = {}


def _hooked_parse(n):
    ds = _orig_parse_device_status(n)
    _raw_0xdb[n.source] = bytes(n.payload).hex()
    return ds


_client_mod.parse_device_status = _hooked_parse


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def name_for(addr: int, devices: list[dict]) -> str:
    for d in devices:
        if d.get("dev_addr") == addr:
            return d.get("name", "unknown")
    return "unknown"


def _dev_addr_from_mfr(mfr_data: dict[int, bytes]) -> int | None:
    """Derive the mesh dev_addr from the 0x0211 manufacturer-data payload.

    Pixie auto-configures dev_addr from the low byte of the BLE MAC, which
    is the last byte of the 6-byte MAC embedded in the advertisement. The
    manufacturer-data extractor in ``client.py`` pulls bytes 2..5, so the
    MAC low byte lives at ``data[5]``.
    """
    data = mfr_data.get(0x0211)
    if data is None or len(data) < 6:
        return None
    return data[5]


async def find_gateway(mesh_name: str, exclude_addr: int | None = None) -> str:
    print(f"Scanning for gateway (mesh={mesh_name!r}, exclude={exclude_addr})...")
    adv_map = await BleakScanner.discover(timeout=10.0, return_adv=True)

    candidates: list[tuple[str, int | None, str | None]] = []
    for d, adv in adv_map.values():
        mfr = adv.manufacturer_data or {}
        is_pixie = (d.name and mesh_name in d.name) or 0x0211 in mfr
        if not is_pixie:
            continue
        dev_addr = _dev_addr_from_mfr(mfr)
        candidates.append((d.address, dev_addr, d.name))

    if not candidates:
        raise RuntimeError(f"No Pixie gateway found for mesh {mesh_name!r}")

    print(f"  Found {len(candidates)} candidate(s):")
    for ble_addr, dev_addr, name in candidates:
        marker = ""
        if exclude_addr is not None and dev_addr == exclude_addr:
            marker = " [EXCLUDED]"
        print(f"    {ble_addr}  name={name!r}  dev_addr={dev_addr}{marker}")

    for ble_addr, dev_addr, _name in candidates:
        if exclude_addr is not None and dev_addr == exclude_addr:
            continue
        print(f"  Picked {ble_addr} (dev_addr={dev_addr}) as gateway\n")
        return ble_addr

    raise RuntimeError(
        f"All {len(candidates)} candidate(s) match exclude_addr={exclude_addr}"
    )


async def main(config_path: str, exclude_addr: int | None = None) -> None:
    cfg = load_config(config_path)
    mesh_name = cfg["mesh"]["name"]
    mesh_password = cfg["mesh"]["password"]
    devices = cfg.get("devices", [])

    ble_addr = await find_gateway(mesh_name, exclude_addr=exclude_addr)
    client = PixieClient(ble_addr)

    print(f"Connecting to {ble_addr}...")
    await client.connect()
    await client.login(mesh_name, mesh_password)
    print(f"Logged in. Gateway MAC={client.gateway_mac}")

    gateway_mac = bytes.fromhex(client.gateway_mac.replace(":", ""))

    print("\nQuerying mesh status to enumerate responders...")
    status = await client.query_status()
    print(f"  {len(status)} devices responded\n")

    gw_addr: int | None = None
    for addr, ds in status.items():
        if ds.mac == gateway_mac:
            gw_addr = addr
            break

    if gw_addr is not None:
        print(f"Gateway dev_addr = {gw_addr} (expected hop=0 in its own reply)\n")
    else:
        print("Gateway dev_addr could not be matched against MAC — hop=0 row unknown\n")

    print("Unicast-polling each responding device (wait ~2s per probe)...\n")
    results: list[dict] = []
    for addr in sorted(status.keys()):
        _raw_0xdb.pop(addr, None)
        ds = await client.ping_device(addr, timeout=2.0)
        if ds is None:
            continue
        raw_hex = _raw_0xdb.get(addr)
        if raw_hex is None or len(raw_hex) < 20:
            continue
        byte8 = int(raw_hex[16:18], 16)
        byte9 = int(raw_hex[18:20], 16)
        results.append({
            "addr": addr,
            "is_gw": (addr == gw_addr),
            "name": name_for(addr, devices),
            "byte8": byte8,
            "byte9": byte9,
            "ttc_parsed": ds.ttc,
            "hops_parsed": ds.hops,
            "raw": raw_hex,
        })

    print(f"{'addr':>4}  {'gw?':>3}  {'name':<20}  {'byte[8]=ttc':>11}  {'byte[9]=hops':>12}  raw_payload_hex")
    print("-" * 100)
    for r in results:
        gw_marker = "yes" if r["is_gw"] else ""
        print(
            f"{r['addr']:>4}  {gw_marker:>3}  {r['name']:<20}  "
            f"{r['byte8']:>11}  {r['byte9']:>12}  {r['raw']}"
        )

    print("\nLegend:")
    print("  gw?         = is the gateway (hops=0 in Telink's scheme)")
    print("  byte[8]=ttc = Telink 'time to cost' relay-quality metric")
    print("  byte[9]=hops= relay count from the connected gateway")
    print("\nCross-reference hops against mesh topology.")

    await client.disconnect()


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(__doc__)
        sys.exit(1)
    exclude = int(sys.argv[2]) if len(sys.argv) == 3 else None
    asyncio.run(main(sys.argv[1], exclude_addr=exclude))
