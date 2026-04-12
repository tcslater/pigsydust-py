"""Async BLE client for SAL Pixie mesh switches."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Callable

from bleak import BleakClient, BleakScanner

from . import command
from .const import (
    CHAR_CMD_UUID,
    CHAR_NOTIFY_UUID,
    CHAR_PAIR_UUID,
    DIS_FIRMWARE_REV_UUID,
    DIS_HARDWARE_REV_UUID,
    DIS_MODEL_NUMBER_UUID,
    MANUFACTURER_ID,
)
from .crypto import (
    LoginError,
    build_login_request,
    command_nonce,
    derive_session_key,
    encrypt,
    parse_login_response,
)
from .notification import (
    DeviceStatus,
    Notification,
    decrypt_notification,
    parse_device_status,
    parse_device_status_broadcast,
)

_LOGGER = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL = 30  # seconds
_STATUS_COLLECT_TIMEOUT = 3  # seconds
_MAX_RECONNECT_ATTEMPTS = 3


def _extract_mac_from_manufacturer_data(mfr_data: dict[int, bytes]) -> bytes | None:
    """Extract the gateway MAC from BLE manufacturer data (company ID 0x0211)."""
    data = mfr_data.get(MANUFACTURER_ID)
    if data is None or len(data) < 6:
        return None
    mac = bytearray(6)
    mac[5] = data[2]
    mac[4] = data[3]
    mac[3] = data[4]
    mac[2] = data[5]
    return bytes(mac)


def _format_mac(mac: bytes) -> str:
    return ":".join(f"{b:02X}" for b in mac)


class PixieClient:
    """Manages an authenticated session with a Pixie BLE mesh.

    Two connection modes:

    1. **Standalone** (e.g. scripts)::

           client = PixieClient("AA:BB:CC:DD:EE:FF")
           await client.connect()
           await client.login(name, password)

    2. **HA-managed** (pass a pre-connected BleakClient)::

           client = PixieClient("AA:BB:CC:DD:EE:FF")
           client.set_ble_client(ble_client)
           await client.login(name, password)
    """

    def __init__(self, ble_address: str) -> None:
        self._address = ble_address
        self._client: BleakClient | None = None
        self._owns_client: bool = False  # True if we created the BleakClient
        self._session_key: bytes = b""
        self._gw_mac: bytes = b"\x00" * 6
        self._salt: bytes = b"\x00\x00"
        self._seq: int = 0
        self._heartbeat_task: asyncio.Task | None = None
        self._status_callbacks: list[Callable[[DeviceStatus], None]] = []
        self._mesh_name: str = ""
        self._mesh_password: str = ""
        self._firmware_version: str | None = None
        self._hardware_version: str | None = None

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def firmware_version(self) -> str | None:
        return self._firmware_version

    @property
    def hardware_version(self) -> str | None:
        return self._hardware_version

    @property
    def gateway_address(self) -> str:
        """BLE address of the currently connected gateway."""
        return self._address

    @property
    def gateway_mac(self) -> str:
        """MAC address of the currently connected gateway (colon-separated)."""
        return _format_mac(self._gw_mac)

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def set_ble_client(self, client: BleakClient) -> None:
        """Use an externally-managed BleakClient (e.g. from HA bluetooth)."""
        self._client = client
        self._owns_client = False

    async def connect(self) -> None:
        """Establish BLE connection (standalone mode — scans and connects)."""
        device = None
        adv_data = None

        devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
        for d, adv in devices.values():
            if d.address == self._address:
                device = d
                adv_data = adv
                break

        if device is None:
            raise ConnectionError(f"Device {self._address} not found")

        if adv_data and adv_data.manufacturer_data:
            mac = _extract_mac_from_manufacturer_data(adv_data.manufacturer_data)
            if mac is not None:
                self._gw_mac = mac
                _LOGGER.debug("MAC from advertisement: %s", _format_mac(mac))

        self._client = BleakClient(device)
        self._owns_client = True
        await self._client.connect()

        for svc in self._client.services:
            for ch in svc.characteristics:
                props = ", ".join(ch.properties)
                descs = [f"{d.uuid}@{d.handle}" for d in ch.descriptors]
                _LOGGER.debug(
                    "  %s char %s handle=%d [%s] descs=%s",
                    svc.uuid, ch.uuid, ch.handle, props, descs,
                )

    async def login(self, mesh_name: str, mesh_password: str) -> None:
        """Authenticate with the mesh and start background tasks."""
        assert self._client is not None

        # Always run service discovery — HA's BleakClientWithServiceCache may
        # return a stale/empty cache without raising.
        _LOGGER.debug("Running service discovery")
        await self._client.get_services()

        self._mesh_name = mesh_name
        self._mesh_password = mesh_password

        rand_a = os.urandom(8)
        self._salt = os.urandom(2)
        self._seq = 0

        req = build_login_request(mesh_name, mesh_password, rand_a)
        await self._client.write_gatt_char(CHAR_PAIR_UUID, req, response=True)
        resp = await self._client.read_gatt_char(CHAR_PAIR_UUID)
        rand_b = parse_login_response(resp)

        self._session_key = derive_session_key(
            mesh_name, mesh_password, rand_a, rand_b
        )

        dis_mac = await self._read_gateway_mac()
        if dis_mac != b"\x00" * 6:
            self._gw_mac = dis_mac
        _LOGGER.debug("Gateway MAC: %s", _format_mac(self._gw_mac))

        self._firmware_version = await self._read_dis_string(DIS_FIRMWARE_REV_UUID)
        self._hardware_version = await self._read_dis_string(DIS_HARDWARE_REV_UUID)
        _LOGGER.debug("Firmware: %s, Hardware: %s", self._firmware_version, self._hardware_version)

        notify_char = self._find_char_object(CHAR_NOTIFY_UUID)
        if notify_char is None:
            raise ConnectionError(
                f"CHAR_NOTIFY ({CHAR_NOTIFY_UUID}) not found on device"
            )

        try:
            await self._client.start_notify(notify_char, self._on_notification)
        except Exception as err:
            _LOGGER.debug(
                "start_notify failed (%s), trying manual CCCD write", err
            )
            await self._enable_notify_manual(notify_char)

        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        try:
            await self._send(command.set_utc())
        except Exception:
            _LOGGER.warning("Failed to send time sync", exc_info=True)

    async def disconnect(self) -> None:
        """Disconnect from the gateway and stop background tasks."""
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        if self._owns_client and self._client is not None and self._client.is_connected:
            await self._client.disconnect()
        self._client = None

    async def _reconnect(self) -> None:
        """Reconnect and re-login using stored credentials."""
        _LOGGER.info("Reconnecting to %s...", self._address)
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Only reconnect in standalone mode (we own the BleakClient).
        # In HA-managed mode, the caller is responsible for reconnection.
        if not self._owns_client:
            self._client = None
            raise ConnectionError("HA-managed BLE connection lost — integration will retry")

        self._client = None
        await self.connect()
        await self.login(self._mesh_name, self._mesh_password)
        _LOGGER.info("Reconnected to %s", self._address)

    async def _ensure_connected(self) -> None:
        if self.is_connected:
            return
        if not self._mesh_name:
            raise ConnectionError("Not logged in — cannot reconnect")
        await self._reconnect()

    # ------------------------------------------------------------------
    # Device control
    # ------------------------------------------------------------------

    async def turn_on(self, address: int) -> None:
        await self._send_with_retry(command.turn_on(address))

    async def turn_off(self, address: int) -> None:
        await self._send_with_retry(command.turn_off(address))

    async def find_me(self, address: int, start: bool = True) -> None:
        """Flash the LED on a device for 15 seconds (find-me)."""
        await self._send_with_retry(command.find_me(address, start))

    async def set_led_blue(self, address: int, on: bool) -> None:
        await self._send_with_retry(command.led_set_blue(address, on))

    async def set_led_orange(self, address: int, level: int) -> None:
        await self._send_with_retry(command.led_set_orange(address, level))

    async def set_led_purple(self, address: int, orange_level: int = 15) -> None:
        await self._send_with_retry(command.led_set_purple(address, orange_level))

    async def reset_led(self, address: int = 0xFFFF) -> None:
        """Clear the firmware's purple latch with: blue-off, orange-off."""
        await self._send_with_retry(command.led_set_blue(address, False))
        await asyncio.sleep(0.1)
        await self._send_with_retry(command.led_set_orange(address, 0))
        await asyncio.sleep(0.1)

    async def query_status(self) -> dict[int, DeviceStatus]:
        results: dict[int, DeviceStatus] = {}
        event = asyncio.Event()

        def collector(ds: DeviceStatus) -> None:
            results[ds.address] = ds

        self._status_callbacks.append(collector)
        try:
            await self._send_with_retry(command.query_status())
            try:
                await asyncio.wait_for(event.wait(), _STATUS_COLLECT_TIMEOUT)
            except asyncio.TimeoutError:
                pass
        finally:
            self._status_callbacks.remove(collector)

        return results

    # ------------------------------------------------------------------
    # Push notification callbacks
    # ------------------------------------------------------------------

    def on_status_update(
        self, callback: Callable[[DeviceStatus], None]
    ) -> Callable[[], None]:
        self._status_callbacks.append(callback)

        def _unsubscribe():
            try:
                self._status_callbacks.remove(callback)
            except ValueError:
                pass

        return _unsubscribe

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _next_sno(self) -> bytes:
        seq = self._seq
        self._seq += 1
        return bytes([seq & 0xFF, self._salt[0], self._salt[1]])

    async def _send(self, plaintext: bytes) -> None:
        assert self._client is not None
        sno = self._next_sno()
        nonce = command_nonce(self._gw_mac, sno)
        packet = encrypt(self._session_key, nonce, sno, plaintext)

        cmd_char = self._find_characteristic(CHAR_CMD_UUID)
        if cmd_char is not None:
            await self._client.write_gatt_char(cmd_char, packet, response=False)
        else:
            await self._client.write_gatt_char(CHAR_CMD_UUID, packet, response=False)

    async def _send_with_retry(self, plaintext: bytes) -> None:
        # In HA-managed mode, don't retry internally — let the
        # coordinator handle reconnection on the next poll cycle.
        if not self._owns_client:
            if not self.is_connected:
                raise ConnectionError("BLE connection lost")
            await self._send(plaintext)
            return

        # Standalone mode: retry with reconnect.
        for attempt in range(_MAX_RECONNECT_ATTEMPTS):
            try:
                await self._ensure_connected()
                await self._send(plaintext)
                return
            except Exception:
                if attempt == _MAX_RECONNECT_ATTEMPTS - 1:
                    raise
                _LOGGER.warning(
                    "Send failed (attempt %d/%d), reconnecting...",
                    attempt + 1, _MAX_RECONNECT_ATTEMPTS,
                )
                try:
                    await self._reconnect()
                except Exception:
                    _LOGGER.warning("Reconnect failed", exc_info=True)

    def _find_characteristic(self, uuid: str) -> int | None:
        if self._client is None:
            return None
        for service in self._client.services:
            for char in service.characteristics:
                if char.uuid == uuid:
                    return char.handle
        return None

    def _find_char_object(self, uuid: str):
        if self._client is None:
            return None
        for service in self._client.services:
            for char in service.characteristics:
                if char.uuid == uuid:
                    return char
        return None

    async def _enable_notify_manual(self, char) -> None:
        """Enable Telink-style notifications without a standard CCCD.

        Telink mesh devices lack a proper CCCD descriptor, so bleak's
        start_notify fails on both macOS and Linux.  We write 0x01 to
        the characteristic to enable device-side notifications, then
        hook into bleak's platform-specific internals to receive them.
        """
        import sys

        assert self._client is not None
        _LOGGER.debug("Enabling notifications via characteristic write (handle %d)", char.handle)
        await self._client.write_gatt_char(char, b"\x01", response=True)

        backend = self._client._backend

        if sys.platform == "darwin":
            # CoreBluetooth: register on the PeripheralDelegate.
            delegate = backend._delegate
            delegate._characteristic_notify_callbacks[char.handle] = self._on_notification_raw
        else:
            # BlueZ: register callback and call StartNotify over DBus.
            try:
                char_path = char.obj[0]
                backend._notification_callbacks[char_path] = self._on_notification_raw

                from dbus_fast import Message
                reply = await backend._bus.call(
                    Message(
                        destination="org.bluez",
                        path=char_path,
                        interface="org.bluez.GattCharacteristic1",
                        member="StartNotify",
                    )
                )
                _LOGGER.debug("BlueZ StartNotify succeeded for %s", char_path)
            except Exception:
                _LOGGER.warning(
                    "BlueZ manual notify setup failed — notifications may not work",
                    exc_info=True,
                )

    def _on_notification_raw(self, data: bytearray) -> None:
        self._on_notification(0, data)

    def _on_notification(self, _sender: int, data: bytearray) -> None:
        raw = bytes(data)
        _LOGGER.debug("Raw notification (%d bytes): %s", len(raw), raw.hex())

        try:
            n = decrypt_notification(self._session_key, self._gw_mac, raw)
        except Exception:
            _LOGGER.debug("Failed to decrypt notification", exc_info=True)
            return

        _LOGGER.debug(
            "Decrypted: src=%d opcode=0x%02X vendor=0x%04X payload=%s",
            n.source, n.opcode, n.vendor, n.payload.hex(),
        )

        statuses: list[DeviceStatus] = []
        if n.opcode == 0xDC:
            try:
                statuses = parse_device_status_broadcast(n)
            except Exception:
                _LOGGER.debug("Failed to parse broadcast status", exc_info=True)
                return
        elif n.opcode == 0xDB:
            try:
                statuses = [parse_device_status(n)]
            except Exception:
                _LOGGER.debug("Failed to parse poll status", exc_info=True)
                return

        for ds in statuses:
            _LOGGER.debug(
                "DeviceStatus: addr=%d on=%s type=0x%02X",
                ds.address, ds.is_on, ds.device_type,
            )
            for cb in self._status_callbacks:
                try:
                    cb(ds)
                except Exception:
                    _LOGGER.exception("Status callback error")

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(_HEARTBEAT_INTERVAL)
            try:
                if self._client is not None and self._client.is_connected:
                    await self._client.read_gatt_char(CHAR_PAIR_UUID)
            except Exception:
                _LOGGER.debug("Heartbeat read failed", exc_info=True)

    async def _read_dis_string(self, uuid: str) -> str | None:
        assert self._client is not None
        try:
            raw = await self._client.read_gatt_char(uuid)
            return raw.replace(b"\x00", b"").decode("utf-8").strip() or None
        except Exception:
            _LOGGER.debug("Could not read DIS char %s", uuid, exc_info=True)
            return None

    async def _read_gateway_mac(self) -> bytes:
        assert self._client is not None
        try:
            raw = await self._client.read_gatt_char(DIS_MODEL_NUMBER_UUID)
            _LOGGER.debug("DIS Model Number raw: %r", bytes(raw))
            mac_str = raw.replace(b"\x00", b"").decode("utf-8").strip()
            mac_str = mac_str.replace("-", ":")
            parts = mac_str.split(":")
            if len(parts) == 6:
                return bytes(int(p, 16) for p in parts)
            _LOGGER.debug("DIS MAC parse failed, got parts: %r", parts)
        except Exception:
            _LOGGER.debug("Could not read MAC from DIS", exc_info=True)
        return b"\x00" * 6
