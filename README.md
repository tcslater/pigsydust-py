# Pigsydust

A Python library for controlling [SAL Pixie](https://pixieplus.com.au/) / Telink BLE mesh wall switches - fully offline, no cloud, no hub, no app dependency.

[![PyPI](https://img.shields.io/pypi/v/pigsydust)](https://pypi.org/project/pigsydust/)

## Features

- **Full protocol implementation** - login, session key derivation, AES-CCM encryption/decryption
- **Device control** - on/off, LED indicator control (blue/orange/purple), find-me blink
- **Status monitoring** - broadcast queries, real-time push notifications (0xDB/0xDC)
- **Cross-platform** - macOS (CoreBluetooth) and Linux (BlueZ via raw HCI)
- **Home Assistant integration** - see [ha-pigsydust](https://github.com/tcslater/ha-pigsydust)

## Install

```
pip install pigsydust
```

On Linux, the process needs `CAP_NET_RAW` (or run as root / `--privileged` in Docker) for the raw HCI socket used to receive BLE notifications.

## Quick Start

```python
import asyncio
from pigsydust import PixieClient

async def main():
    client = PixieClient("AA:BB:CC:DD:EE:FF")
    await client.connect()
    await client.login("Smart Light", "12345678")

    await client.turn_on(1)

    status = await client.query_status()
    for addr, ds in status.items():
        print(f"Device {addr}: {'ON' if ds.is_on else 'OFF'}")

    await client.disconnect()

asyncio.run(main())
```

## API

| Method | Description |
|--------|-------------|
| `connect()` | Establish BLE connection (scans on macOS, direct on Linux) |
| `login(name, password)` | Authenticate with the mesh |
| `turn_on(addr)` / `turn_off(addr)` | Control a device, group, or broadcast (`0xFFFF`) |
| `query_status()` | Poll all devices and return `dict[int, DeviceStatus]` |
| `set_led_blue(addr, on)` | Toggle blue indicator LED |
| `set_led_orange(addr, level)` | Set orange indicator LED brightness (0-15) |
| `set_led_purple(addr, level)` | Set purple (both) indicator LED |
| `reset_led(addr)` | Clear indicator LEDs |
| `find_me(addr)` | Flash device LED for 15 seconds |
| `on_status_update(callback)` | Register for real-time push notifications |
| `disconnect()` | Disconnect and clean up |

## Mesh credentials

All nodes in a Pixie mesh share two values:

- **Mesh name** - typically `"Smart Light"` (the firmware default)
- **Mesh password** - the numeric string shown in the Pixie app's "Share Home" screen

## Protocol reference

See [`docs/PROTOCOL-REFERENCE.md`](docs/PROTOCOL-REFERENCE.md) for the complete reverse-engineered protocol specification.

## License

MIT
