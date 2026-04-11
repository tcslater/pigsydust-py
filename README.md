# pigsydust

Python library for controlling SAL Pixie BLE mesh wall switches.

## Installation

```
pip install pigsydust
```

## Quick Start

```python
import asyncio
from pigsydust import PixieClient

async def main():
    client = PixieClient("AA:BB:CC:DD:EE:FF")
    await client.connect()
    await client.login("Smart Light", "12345678")

    await client.turn_on(0x0001)

    status = await client.query_status()
    for addr, ds in status.items():
        print(f"Device {addr}: {'ON' if ds.is_on else 'OFF'}")

    await client.disconnect()

asyncio.run(main())
```
