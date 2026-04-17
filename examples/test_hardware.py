"""Standalone hardware test for pigsydust.

Usage:
    python examples/test_hardware.py <config.toml>

Example:
    python examples/test_hardware.py /Users/tim/src/pixiedust/proxy/config.toml

Reads mesh credentials and device map from the TOML config, scans for
a gateway, connects, queries all devices, toggles one, then restores it.
"""

import asyncio
import logging
import sys
import tomllib

from bleak import BleakScanner

from pigsydust import PixieClient

logging.basicConfig(level=logging.DEBUG)


def load_config(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def build_device_map(cfg: dict) -> dict[int, dict]:
    """Build addr -> {name, mac, building, groups} from config."""
    devices = {}
    for d in cfg.get("devices", []):
        devices[d["dev_addr"]] = d
    return devices


def device_label(addr: int, device_map: dict[int, dict]) -> str:
    d = device_map.get(addr)
    if d:
        return f"{d['name']} (addr={addr}, mac={d['mac']})"
    return f"unknown (addr={addr})"


async def find_gateway(mesh_name: str) -> str:
    print(f"\n[0/5] Scanning for gateway (mesh={mesh_name!r})...")
    devices = await BleakScanner.discover(timeout=10.0)
    for d in devices:
        if d.name and mesh_name in d.name:
            print(f"      Found: {d.address}  {d.name}")
            return d.address

    print("      No name match, scanning by manufacturer ID...")
    devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
    for d, adv in devices.values():
        if 0x0211 in (adv.manufacturer_data or {}):
            print(f"      Found by manufacturer ID: {d.address}  {d.name or '(no name)'}")
            return d.address

    raise RuntimeError(f"No Pixie gateway found for mesh {mesh_name!r}")


async def main(config_path: str) -> None:
    cfg = load_config(config_path)
    mesh_name = cfg["mesh"]["name"]
    mesh_password = cfg["mesh"]["password"]
    device_map = build_device_map(cfg)

    print(f"Loaded {len(device_map)} devices from config")

    address = await find_gateway(mesh_name)
    client = PixieClient(address)

    # --- Connect ---
    print(f"\n[1/5] Connecting to {address}...")
    await client.connect()
    print("      Connected.")

    # --- Login ---
    print(f"\n[2/5] Logging in (mesh={mesh_name!r})...")
    await client.login(mesh_name, mesh_password)
    print("      Logged in.")

    # --- Query status ---
    print("\n[3/5] Querying mesh status...")
    status = await client.query_status()
    if not status:
        print("      No devices responded.")
    for addr, ds in sorted(status.items()):
        state = "ON" if ds.is_on else "OFF"
        mac = ":".join(f"{b:02X}" for b in ds.mac)
        label = device_label(addr, device_map)
        print(f"      {label}  major=0x{ds.major_type:02X}  {state}  (reported MAC={mac})")

    # Show which living-building devices didn't respond.
    responded = set(status.keys())
    living_devices = {a: d for a, d in device_map.items() if d.get("building") == "living"}
    missing = set(living_devices) - responded
    if missing:
        print(f"\n      Missing (in-range but no response):")
        for addr in sorted(missing):
            print(f"        {device_label(addr, device_map)}")

    if not status:
        print("\n      Skipping on/off test — no devices found.")
        await client.disconnect()
        return

    # Listen for unsolicited events (e.g. physical switch toggle).
    print("\n[4/5] Listening for unsolicited events (toggle a switch now)... 15s")
    await asyncio.sleep(15)

    # Pick the first device for on/off test.
    test_addr = next(iter(sorted(status)))
    was_on = status[test_addr].is_on
    label = device_label(test_addr, device_map)

    # --- Toggle ---
    if was_on:
        print(f"\n[4/5] Turning OFF {label}...")
        await client.turn_off(test_addr)
    else:
        print(f"\n[4/5] Turning ON {label}...")
        await client.turn_on(test_addr)

    await asyncio.sleep(2)

    # --- Restore ---
    if was_on:
        print(f"\n[5/5] Restoring {label} to ON...")
        await client.turn_on(test_addr)
    else:
        print(f"\n[5/5] Restoring {label} to OFF...")
        await client.turn_off(test_addr)

    await asyncio.sleep(1)

    # --- Disconnect ---
    await client.disconnect()
    print("\nDone. All steps completed successfully.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
