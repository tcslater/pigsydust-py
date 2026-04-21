"""Async BLE client for SAL Pixie mesh switches."""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Callable

from bleak import BleakClient, BleakScanner

from . import command
from .const import (
    ADDR_BROADCAST_POLL,
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
    TagMismatchError,
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

_HEARTBEAT_INTERVAL = 25  # seconds — must be < 30s Telink keepalive
_STATUS_COLLECT_TIMEOUT = 3  # seconds
_MAX_RECONNECT_ATTEMPTS = 3
_BROADCAST_POLL_RETRIES = 3
_BROADCAST_POLL_INTERVAL = 0.3  # seconds


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

    def __init__(
        self,
        ble_address: str,
        disconnect_callback: Callable[[], None] | None = None,
    ) -> None:
        self._address = ble_address
        self._client: BleakClient | None = None
        self._owns_client: bool = False  # True if we created the BleakClient
        self._disconnect_callback = disconnect_callback
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
        self._hci_sock = None  # raw HCI socket for notification capture

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

    def set_disconnect_callback(self, callback: Callable[[], None]) -> None:
        """Set or update the disconnect callback."""
        self._disconnect_callback = callback

    def _on_ble_disconnect(self, *_args) -> None:
        """Called by bleak when the BLE connection drops.

        The BleakClient wrapper passes (client,) but the raw BlueZ
        backend calls with no args — accept both.
        """
        _LOGGER.warning("BLE connection lost (disconnect callback)")
        if self._disconnect_callback is not None:
            self._disconnect_callback()

    def set_ble_client(self, client: BleakClient) -> None:
        """Use an externally-managed BleakClient (e.g. from HA bluetooth)."""
        self._client = client
        self._owns_client = False

    async def connect(self) -> None:
        """Establish BLE connection (standalone mode — scans and connects)."""
        import sys

        if sys.platform == "darwin":
            # macOS: need to scan first to get BLEDevice (can't connect by address).
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

            self._client = BleakClient(
                device, disconnected_callback=self._on_ble_disconnect
            )
        else:
            # Linux: BleakClient resolves UUIDs and wraps the BlueZ backend.
            self._client = BleakClient(
                self._address,
                disconnected_callback=self._on_ble_disconnect,
            )

            # Extract MAC from address (on Linux the address IS the MAC).
            try:
                parts = self._address.split(":")
                if len(parts) == 6:
                    self._gw_mac = bytes(int(p, 16) for p in parts)
            except Exception:
                pass

        self._owns_client = True
        await self._client.connect(timeout=15.0)

        _LOGGER.debug("Connected, %d services", len(list(self._client.services)))

    async def login(self, mesh_name: str, mesh_password: str) -> None:
        """Authenticate with the mesh and start background tasks."""
        assert self._client is not None

        # Ensure services are discovered. Different bleak wrappers handle
        # this differently — try get_services(), fall back to connect().
        try:
            _ = self._client.services
            _LOGGER.debug("Services already available (%d services)", len(list(self._client.services)))
        except Exception:
            _LOGGER.debug("Services not available, triggering discovery")
            if hasattr(self._client, 'get_services'):
                await self._client.get_services()
            elif not self._client.is_connected:
                await self._client.connect()
            else:
                _LOGGER.warning("Connected but services unavailable — may fail")

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

        # Start heartbeat BEFORE enabling notifications — the Telink 30s
        # keepalive timer is already ticking, and the notify setup may
        # take time (or block if D-Bus calls hang).
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        import sys
        if sys.platform == "darwin":
            # macOS: try standard start_notify first (works with HA's
            # wrapper and CoreBluetooth).  Fall back to manual method.
            try:
                await self._client.start_notify(notify_char, self._on_notification)
                _LOGGER.debug("start_notify succeeded")
            except Exception as err:
                _LOGGER.debug("start_notify failed (%s), trying manual enable", err)
                await self._enable_notify_manual(notify_char)
        else:
            # Linux: skip start_notify entirely.  BlueZ's AcquireNotify
            # hangs because the Telink CCCD doesn't respond to ATT writes,
            # and cancelling the call corrupts the D-Bus bus.  Go straight
            # to the manual Telink enable + raw HCI socket.
            await self._enable_notify_manual(notify_char)

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

        if self._hci_sock is not None:
            try:
                asyncio.get_running_loop().remove_reader(self._hci_sock.fileno())
            except Exception:
                pass
            try:
                self._hci_sock.close()
            except Exception:
                pass
            self._hci_sock = None

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

    async def ping_device(
        self, address: int, timeout: float = 2.0
    ) -> DeviceStatus | None:
        """Unicast-poll *address* and await its 0xDB reply.

        Returns the :class:`DeviceStatus` on reply, or ``None`` on timeout
        (device offline or unreachable). Filters to unicast 0xDB responses
        only — a broadcast 0xDC status (mac all-zero) does not count, so
        stale post-``query_status`` traffic won't mask a dead device.
        """
        result: DeviceStatus | None = None
        event = asyncio.Event()

        def collector(ds: DeviceStatus) -> None:
            nonlocal result
            if ds.address == address and ds.mac != bytes(6):
                result = ds
                event.set()

        self._status_callbacks.append(collector)
        try:
            await self._send_with_retry(command.status_poll(address))
            try:
                await asyncio.wait_for(event.wait(), timeout)
            except asyncio.TimeoutError:
                pass
        finally:
            try:
                self._status_callbacks.remove(collector)
            except ValueError:
                pass
        return result

    async def query_status(self) -> dict[int, DeviceStatus]:
        # Mirrors the Pixie app's startup sequence: a single 0xC5 broadcast
        # to elicit 0xDC from responding devices, followed by a handful of
        # 0x7FFF-addressed 0xDA polls that wake stragglers into emitting
        # fresh 0xDC. 0xC5 alone leaves dimly-reachable devices out of the
        # burst; the broadcast polls reliably close the gap.
        results: dict[int, DeviceStatus] = {}

        def collector(ds: DeviceStatus) -> None:
            results[ds.address] = ds

        self._status_callbacks.append(collector)
        try:
            await self._send_with_retry(command.query_status())
            for _ in range(_BROADCAST_POLL_RETRIES):
                await asyncio.sleep(_BROADCAST_POLL_INTERVAL)
                await self._send_with_retry(
                    command.status_poll(ADDR_BROADCAST_POLL)
                )
            await asyncio.sleep(_STATUS_COLLECT_TIMEOUT)
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
        """Enable Telink-style notifications.

        Telink mesh devices have a CCCD descriptor but the firmware
        ignores ATT writes to it, so bleak's start_notify hangs on
        Linux (BlueZ times out the ATT write after ~30s, killing the
        connection).  We write 0x01 to the characteristic *value* to
        enable device-side notifications, then use platform-specific
        internals to receive them.
        """
        import sys

        assert self._client is not None
        backend = self._client._backend

        # Write 0x01 to the characteristic to enable device-side notifications.
        _LOGGER.debug("Enabling notifications via characteristic write (handle %d)", char.handle)
        await self._client.write_gatt_char(char, b"\x01", response=True)

        if sys.platform == "darwin":
            # CoreBluetooth: register on the PeripheralDelegate.
            # Navigate through HA wrapper if present.
            cb_backend = backend
            while hasattr(cb_backend, '_backend') and not hasattr(cb_backend, '_delegate'):
                cb_backend = cb_backend._backend
            if hasattr(cb_backend, '_delegate'):
                delegate = cb_backend._delegate
                delegate._characteristic_notify_callbacks[char.handle] = self._on_notification_raw
                _LOGGER.debug("Registered CoreBluetooth notification callback on handle %d", char.handle)
            else:
                _LOGGER.warning("Could not find CoreBluetooth delegate — notifications won't work")
        else:
            # BlueZ: the Telink CCCD descriptor exists but doesn't
            # respond to standard ATT writes, causing AcquireNotify /
            # StartNotify to hang and eventually kill the connection.
            #
            # Bypass BlueZ's D-Bus notification layer entirely and read
            # ATT_HANDLE_VALUE_NTF PDUs from a raw HCI socket instead.
            # The value attribute handle is char.handle + 1 (GATT layout:
            # declaration handle, then value handle, then descriptors).
            value_handle = char.handle + 1
            self._start_hci_notify_reader(value_handle)

    def _start_hci_notify_reader(self, value_handle: int) -> None:
        """Monitor raw HCI traffic for ATT notification PDUs.

        BlueZ's StartNotify/AcquireNotify hang on Telink devices (the
        CCCD descriptor exists but the firmware doesn't respond to ATT
        writes on it).  Instead we open a raw HCI socket and parse
        ATT_HANDLE_VALUE_NTF (0x1B) PDUs directly.
        """
        import socket
        import struct

        ATT_HANDLE_VALUE_NTF = 0x1B
        HCI_ACL_DATA_PKT = 0x02
        ATT_CID = 0x0004

        try:
            sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI
            )
            sock.bind((0,))  # hci0

            # HCI filter: accept ACL data packets (type 2)
            # struct hci_filter { type_mask(4), event_mask(8), opcode(2), pad(2) }
            flt = bytearray(16)
            struct.pack_into("<I", flt, 0, 1 << HCI_ACL_DATA_PKT)  # type_mask
            sock.setsockopt(0, 2, bytes(flt))  # SOL_HCI=0, HCI_FILTER=2
            sock.setblocking(False)
        except Exception:
            _LOGGER.warning(
                "Could not open raw HCI socket — notifications won't work. "
                "Ensure the container runs with --privileged or has "
                "NET_RAW + NET_ADMIN capabilities.",
                exc_info=True,
            )
            return

        self._hci_sock = sock

        loop = asyncio.get_running_loop()

        def _on_hci_readable() -> None:
            try:
                while True:
                    data = sock.recv(1024)
                    if not data or data[0] != HCI_ACL_DATA_PKT:
                        continue
                    # ACL: type(1) handle(2) total_len(2) l2cap_len(2) l2cap_cid(2) att...
                    if len(data) < 10:
                        continue
                    l2cap_cid = struct.unpack_from("<H", data, 7)[0]
                    if l2cap_cid != ATT_CID:
                        continue
                    att_opcode = data[9]
                    if att_opcode != ATT_HANDLE_VALUE_NTF:
                        continue
                    if len(data) < 12:
                        continue
                    att_handle = struct.unpack_from("<H", data, 10)[0]
                    if att_handle != value_handle:
                        continue
                    att_value = bytearray(data[12:])
                    self._on_notification_raw(att_value)
            except BlockingIOError:
                pass
            except OSError:
                # Socket closed
                pass
            except Exception:
                _LOGGER.debug("HCI read error", exc_info=True)

        loop.add_reader(sock.fileno(), _on_hci_readable)
        _LOGGER.info(
            "HCI notification reader active (value_handle=%d)", value_handle
        )

    def _on_notification_raw(self, data: bytearray) -> None:
        self._on_notification(0, data)

    def _on_notification(self, _sender: int, data: bytearray) -> None:
        raw = bytes(data)
        _LOGGER.debug("Raw notification (%d bytes): %s", len(raw), raw.hex())

        try:
            n = decrypt_notification(self._session_key, self._gw_mac, raw)
        except TagMismatchError:
            # Common and expected — happens when a notification from a
            # prior session arrives after a re-login (new session key),
            # or when the mesh retransmits a packet we've already
            # consumed. Log without traceback to keep the noise down.
            _LOGGER.debug("Dropped notification (tag mismatch)")
            return
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
                "DeviceStatus: addr=%d on=%s ttc=%s hops=%s type=%s stype=%s status=%s",
                ds.address, ds.is_on, ds.ttc, ds.hops,
                ds.type, ds.stype, ds.status_byte,
            )
            for cb in self._status_callbacks:
                try:
                    cb(ds)
                except Exception:
                    _LOGGER.exception("Status callback error")

    async def _heartbeat_loop(self) -> None:
        # First heartbeat fires immediately — the Telink 30s keepalive
        # timer starts when the BLE connection is established, not when
        # the heartbeat task begins.  Login overhead can eat several
        # seconds, so we must not sleep before the first read.
        while True:
            try:
                if self._client is not None and self._client.is_connected:
                    await self._client.read_gatt_char(CHAR_PAIR_UUID)
                    _LOGGER.debug("Heartbeat OK")
            except Exception:
                _LOGGER.debug("Heartbeat read failed", exc_info=True)
            await asyncio.sleep(_HEARTBEAT_INTERVAL)

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
