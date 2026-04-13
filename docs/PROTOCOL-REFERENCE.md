# SAL Pixie / Telink BLE Mesh Protocol Reference

A complete protocol reference for SAL Pixie BLE mesh wall switches, based on
reverse-engineering of the PIXIE iOS app and verified against live hardware.

**Audience**: developers and agents building their own software stack to control
Pixie devices over BLE, fully offline — no cloud, no hub, no app dependency.

---

## Table of Contents

1. [Overview](#overview)
2. [BLE Advertisements](#ble-advertisements)
3. [GATT Services](#gatt-services)
4. [Authentication (Login)](#authentication-login)
5. [Session Key Derivation](#session-key-derivation)
6. [Command Packet Encryption (AES-CCM)](#command-packet-encryption-aes-ccm)
7. [Notification Packet Decryption](#notification-packet-decryption)
8. [Plaintext Payload Format](#plaintext-payload-format)
9. [Addressing](#addressing)
10. [Opcodes Reference](#opcodes-reference)
    - [Device Control](#device-control)
    - [Status & Polling](#status--polling)
    - [Group Management](#group-management)
    - [LED Indicator Control](#led-indicator-control)
    - [Find-me (LED Flash)](#find-me-led-flash)
    - [Time Synchronisation](#time-synchronisation)
    - [Schedule / Alarm Operations](#schedule--alarm-operations)
    - [Sunrise / Sunset (0xd0)](#sunrise--sunset-0xd0)
11. [Schedule Record Format](#schedule-record-format)
12. [Schedule Flows](#schedule-flows)
13. [Timezone & Weekday Rotation](#timezone--weekday-rotation)
14. [Gateway Detection](#gateway-detection)
15. [Connection Maintenance](#connection-maintenance)
16. [Platform Notes](#platform-notes)

---

## Overview

SAL Pixie switches use a **Telink BLE mesh** with a proprietary application
layer. All communication is BLE — there is no WiFi, no cloud, no internet
requirement. A client (phone, computer, proxy) connects to any one mesh node
(the "gateway"), authenticates, and sends encrypted commands that the mesh
relays to all other nodes.

Key characteristics:
- **Mesh topology**: single-hop BLE mesh. Commands sent to any connected node
  are relayed to the entire mesh.
- **Shared credentials**: all nodes share a single mesh name and password.
- **No persistent RTC**: devices rely on the client broadcasting the current
  time on each connection.
- **Session-based encryption**: AES-CCM with a per-session key derived during
  login.

---

## BLE Advertisements

Pixie devices advertise continuously. Relevant advertisement fields:

| Field | Value |
|-------|-------|
| Local Name | The mesh name (e.g. `"Smart Light"`) |
| 16-bit Service UUID | `0xCDAB` |
| Manufacturer ID | `0x0211` (Skytone) |

### Manufacturer Data Layout

Bytes after the 2-byte company ID (`0x0211`):

| Offset | Length | Content |
|--------|--------|---------|
| 0-1 | 2 | Unknown |
| 2-5 | 4 | MAC bytes `[5,4,3,2]` in little-endian order |
| 14 | 1 | Device type: `0x47` = gateway, `0x45` = leaf |
| 17-20 | 4 | Mesh network ID (little-endian 32-bit) |

The **mesh network ID** at bytes 17-20 is how nodes recognise members of
their home network in the advertisement stream.

The **device type byte** at offset 14 indicates which node currently holds
the gateway role. The gateway role is dynamic — the mesh periodically
renegotiates which node serves as gateway. Your client should prefer
connecting to the current gateway (`0x47`) for best first-hop behaviour.

The **MAC bytes** at offset 2-5 provide the real hardware MAC address on
platforms (like macOS/iOS) where the OS randomises BLE addresses. Extract
the full 6-byte MAC by combining these 4 bytes with the remaining 2 bytes
from the BLE address or Device Information Service.

---

## GATT Services

### Service 0: Device Information Service (UUID `0x180a`)

Standard BLE DIS — readable without authentication.

| UUID | Characteristic | Notes |
|------|----------------|-------|
| `0x2a26` | Firmware Revision | e.g. `"1.7:6219"` — firmware version + build |
| `0x2a27` | Hardware Revision | e.g. `"12.22.1.0"` |
| `0x2a29` | Manufacturer Name | Reuses the mesh name |
| `0x2a24` | Model Number | Device MAC as a colon-separated string |

### Service 1: Telink Mesh Service (UUID `00010203-0405-0607-0809-0a0b0c0d1910`)

The primary mesh service. Four characteristics:

| UUID Suffix | Name | Purpose |
|-------------|------|---------|
| `1911` | CHAR_NOTIFY | Subscribe (`0x01`), then receive encrypted notifications |
| `1912` | CHAR_CMD | Write encrypted command packets |
| `1913` | CHAR_OTA | OTA / config (not used in normal operation) |
| `1914` | CHAR_PAIR | Login: write `0x0c` request, read `0x0d` response |

### Service 2: Mesh2 Service (UUID `19200d0c-0b0a-0908-0706-050403020100`)

A secondary service with one characteristic at UUID suffix `1921`. Likely
for a v2 mesh protocol. Not used by current firmware or the Pixie app.

---

## Authentication (Login)

### Credentials

Two shared values are needed:
- **Mesh name**: a string, often `"Smart Light"` (the firmware default).
- **Mesh password**: a numeric string (the `netID` displayed in the app's
  "Share Home" screen).

Both are zero-padded to 16 bytes for cryptographic operations.

### Reversed AES Primitive

All Telink mesh cryptography uses a "reversed AES" convention:

```
reversed_AES(key, plaintext):
    reverse all 16 bytes of key
    reverse all 16 bytes of plaintext
    ciphertext = AES-128-ECB(reversed_key, reversed_plaintext)
    reverse all 16 bytes of ciphertext
    return reversed_ciphertext
```

This byte-reversal is applied to every AES operation in the protocol — login,
session key, and per-packet AES-CCM.

### Login Sequence

1. **Client generates `rand_a`** — 8 random bytes. (The Pixie iOS app uses a
   fixed value; your implementation should use true random bytes.)

2. **Client computes `enc_req`**:
   ```
   key       = rand_a || 0x00 * 8          (16 bytes)
   plaintext = pad16(name) XOR pad16(pass) (16 bytes)
   ct        = reversed_AES(key, plaintext)
   enc_req   = ct[0:8]
   ```

3. **Client writes to CHAR_PAIR** (`0x1914`):
   ```
   [0x0c] || rand_a[8] || enc_req[8]      (17 bytes total)
   ```

4. **Client reads from CHAR_PAIR** — the device returns:
   ```
   [0x0d] || rand_b[8] || auth[8]         (17 bytes total)
   ```
   This is a standard ATT Read Response, **not** a notification.

5. Login is complete. The client now has `rand_a` and `rand_b`, which are
   used to derive the session key.

> **Important**: there is no separate "session key confirm" packet in this
> protocol variant. After reading the response, the client immediately
> begins sending encrypted commands.

---

## Session Key Derivation

The session key uses the **opposite key/plaintext assignment** from the login:

```
key       = pad16(name) XOR pad16(pass)   (16 bytes)
plaintext = rand_a[8] || rand_b[8]        (16 bytes)
sk        = reversed_AES(key, plaintext)   (16 bytes)
```

For login, `key = rand_a || zeros` and `plaintext = name ^ pass`.
For the session key, `key = name ^ pass` and `plaintext = rand_a || rand_b`.

This asymmetry is the single most common implementation mistake — getting it
wrong produces a valid-looking session that decrypts to garbage.

---

## Command Packet Encryption (AES-CCM)

Commands are written to CHAR_CMD (`0x1912`) as encrypted packets.

### Wire Format

```
sno(3) || tag(2) || ciphertext(N)
```

- **`sno`** (3 bytes): sequence number. Byte 0 is a per-command counter that
  increments by 1 for each command sent. Bytes 1-2 are a per-session salt
  (random, fixed at login time for the session).
- **`tag`** (2 bytes): truncated CBC-MAC authentication tag.
- **`ciphertext`** (N bytes): encrypted payload. Length depends on the
  command (typically 15 bytes for on/off, 10 bytes for status queries, etc.).

### Nonce Construction

```
nonce[8] = gwMAC[5] || gwMAC[4] || gwMAC[3] || gwMAC[2] || 0x01 || sno[0] || sno[1] || sno[2]
```

Where `gwMAC` is the connected gateway's MAC address in standard printed order
(`AA:BB:CC:DD:EE:FF` → `gwMAC[0]=AA ... gwMAC[5]=FF`). The nonce uses the
**low 4 bytes in little-endian order** (bytes 5,4,3,2 of the printed MAC).

### CBC-MAC

```
B0         = nonce[8] || data_len(1) || 0x00 * 7    (16 bytes)
mac_state  = reversed_AES(sk, B0)

for i in 0..len(data)-1:
    mac_state[i & 0xf] ^= data[i]
    if (i & 0xf) == 0xf  OR  i == len(data)-1:
        mac_state = reversed_AES(sk, mac_state)

tag = mac_state[0:2]
```

### CTR Encryption

```
ctr_block = 0x00 || nonce[8] || 0x00 * 7            (16 bytes)

for i in 0..len(data)-1:
    if (i & 0xf) == 0:
        keystream = reversed_AES(sk, ctr_block)
        ctr_block[0]++
    ciphertext[i] = data[i] XOR keystream[i & 0xf]
```

---

## Notification Packet Decryption

Notifications arrive on CHAR_NOTIFY (`0x1911`) as 20-byte encrypted packets.

### Wire Format

```
sno(3) || src_addr(2 LE) || tag(2) || ciphertext(13)
```

- **`sno`** (bytes 0-2): the source device's own sequence counter
  (independent of the client's command counter).
- **`src_addr`** (bytes 3-4): source device's mesh address, little-endian.
- **`tag`** (bytes 5-6): 2-byte CBC-MAC tag.
- **`ciphertext`** (bytes 7-19): 13 bytes of encrypted payload.

### Notification Nonce

The nonce for notifications differs from the command nonce:

```
nonce[8] = gwMAC[5] || gwMAC[4] || gwMAC[3] || sno[0] || sno[1] || sno[2] || src_addr_lo || src_addr_hi
```

Note: only **3 MAC bytes** (not 4), and `src_addr` replaces the constant
`0x01` byte. This difference is the reason many Telink implementations fail
to decrypt notifications.

Decryption uses the same CTR mode as encryption (CTR is its own inverse)
with the session key.

---

## Plaintext Payload Format

After decryption, the plaintext payload is:

```
dst(2 LE) || opcode(1) || vendor(2 LE) || data(N) || zero_pad
```

| Field | Size | Description |
|-------|------|-------------|
| `dst` | 2 | Destination mesh address, little-endian |
| `opcode` | 1 | `(op_type << 6) \| (op6 & 0x3f)` — `op_type` is 3 for client→device commands |
| `vendor` | 2 | Vendor ID, little-endian. Usually `0x6969` (Skytone application layer) |
| `data` | N | Opcode-specific payload |
| pad | rest | Zero bytes to fill the plaintext length |

The total plaintext length varies by opcode:
- **15 bytes** for most commands (on/off, LED, groups, schedules)
- **10 bytes** for status queries and short commands
- **7 bytes** for polls

---

## Addressing

| Range | Meaning |
|-------|---------|
| `0x0001 – 0x7FFF` | Individual device addresses |
| `0x8000 \| groupID` | Group addresses (e.g. `0x8001` = group 1) |
| `0x7FFF` | Broadcast poll address (used by status polling) |
| `0xFFFF` | Full broadcast (used by on/off, time sync) |
| `0x0030` | Schedule coordinator (receives all alarm operations) |

---

## Opcodes Reference

Wire opcode byte = `(op_type << 6) | (op6 & 0x3f)`.
For client→device commands, `op_type = 3`.

### Device Control

#### 0xed — On/Off

```
dst(2 LE) || 0xed || 69 69 || state(1) || 0x00 * pad
```

- `state`: `0x01` = ON, `0x00` = OFF
- Works for individual devices, groups, and broadcast (`0xFFFF`)

#### 0xe7 — Group On/Off

An alternative on/off used specifically for group control:

```
group_addr(2 LE) || 0xe7 || 69 69 || state(1) 00 10 00 00 00 || group_addr(2 LE) || 00
```

- `state`: `0x0e` = ON, `0x0d` = OFF
- The group address appears twice: as `dst` and in the data tail
- `0x10` between state and group tail is treated as a constant

Both `0xed` and `0xe7` work for group addressing. The app uses `0xe7` for
group toggles.

### Status & Polling

#### 0xc5 — Status Query (broadcast)

```
0xFFFF || 0xc5 || 69 69 || xx xx || d7 69 00
```

- Broadcast to all mesh nodes
- Causes all devices to respond with `0xdc` status notifications
- Bytes `[0-1]` of data are session-variable (firmware is indifferent)
- Bytes `[2-4]` are the fixed tag `d7 69 00`
- **10-byte plaintext** (shorter than the standard 15)

#### 0xda — Status Poll (unicast or broadcast)

```
dst(2 LE) || 0xda || 11 02 || 10 00
```

- Vendor is `0x0211` (Skytone), **not** `0x6969`
- Elicits a `0xdb` status notification from the target
- Use `dst = 0x7FFF` for broadcast poll, or a specific device address
- **7-byte plaintext**
- Used as a keepalive / heartbeat (~60s interval)
- Also used as a wake-up prerequisite before LED state queries

#### 0xdb — Status Response (notification)

13-byte decrypted notification payload:

| Offset | Content |
|--------|---------|
| 0 | `0xdb` (opcode) |
| 1-2 | `0x11 0x02` (fixed) |
| 3 | `0x00` (padding) |
| 4 | Product revision |
| 5 | Product class |
| 6 | Device type (`0x45` = leaf, `0x47` = gateway) |
| 7-10 | Source MAC bytes `[5,4,3,2]` |
| 11 | Mesh routing metric (variable per-frame, likely hop count) |
| 12 | On/off state: `0x00` = off, `0x01` = on |

#### 0xdc — Device Status Notification

Used for both **broadcast status bursts** (response to `0xc5` query or
`set_utc`) and **unsolicited state-change events** (physical switch
toggle). The wire `src_addr` is always `0x0000`.

Unlike `0xdb`, the device address is embedded in the payload rather than
the wire header. Each notification carries **one or two** device statuses
in a 4-byte-per-device packed format.

13-byte decrypted notification plaintext:

| Offset | Content |
|--------|---------|
| 0 | `0xdc` (opcode) |
| 1-2 | `0x11 0x02` (vendor) |
| 3 | Device A: mesh address (low byte = MAC[5]) |
| 4 | Device A: routing metric (`0x00` = unreachable) |
| 5 | Device A: brightness (`0x00` = off, `0x64` = on at 100%) |
| 6 | Device A: flags |
| 7 | Device B: mesh address (`0x00` if absent) |
| 8 | Device B: routing metric |
| 9 | Device B: brightness |
| 10 | Device B: flags |
| 11-12 | `0x00 0x00` (padding) |

**Broadcast burst**: a mesh with N devices produces ceil(N/2)
notifications, each carrying two device statuses. Triggered by `0xc5`
status query or `set_utc` time sync.

**Unsolicited event**: a single device status in the first slot; the
second slot (bytes 7-10) is zeroed. Triggered by physical switch toggle.

The device address in the payload is the low byte of the mesh address
(which also equals the last byte of the device's MAC).

### Group Management

#### 0xef — Set Group Membership

Sets a device's **complete** group membership list (not add/remove):

```
dst(2 LE) || 0xef || 69 69 || grp_count(1) || gw_mac5(1) || grp_low[0..N-1] || 0x00 * pad
```

- `grp_count`: number of groups (0 = remove from all groups)
- `gw_mac5`: last byte of the connected gateway's MAC (required for
  firmware validation)
- `grp_low[i]`: low byte of each group address (firmware reconstructs
  `0x8000 | grp_low`)
- **ACK**: device responds with `0xee` notification mirroring `grp_count`

> **Critical**: this command sets the FULL membership list. Sending
> `grp_count=1, grp_low=0x02` assigns the device to group 2 ONLY,
> removing it from any other groups.

#### 0xd7 — Query Group Membership

```
dst(2 LE) || 0xd7 || 11 02 || 00 00 00
```

- Vendor is `0x0211` (Skytone), not `0x6969`
- Response: `0xd4` notification with the device's group list

#### 0xdd — Group Address Probe

```
group_addr(2 LE) || 0xdd || 11 02 || 0a 01
```

- Vendor is `0x0211` (Skytone)
- Tests whether a group address is in use
- If any device is a member, it responds with a `0xd4` notification
- No response = address is free

#### 0xd4 — Group Response (notification)

```
0xd4 || 11 02 || grp_low[0] grp_low[1] ... || 0xff * pad
```

- Dual-purpose response to both `0xdd` (probe) and `0xd7` (query)
- Group low bytes start at offset 3, terminated by `0x00` or `0xff`

#### 0xee — Group Membership ACK (notification)

```
0xee || 69 69 || grp_count || 0x00 * pad
```

Acknowledgement of a `0xef` membership command.

### Group Architecture Note

Groups have **no mesh-side existence as named objects**. Each device simply
holds a list of group addresses it subscribes to. The mapping from group
address to human-readable name is purely client-local. Different app installs
on different devices can have completely divergent group names pointing at the
same underlying group addresses on the hardware.

"Creating" a group in the app picks the next free group address, names it
locally, and writes membership to chosen devices via `0xef`. The app uses
`0xdd` probes to find an unused group address before creating.

### LED Indicator Control

Wall switches have two physical LED channels on the pilot indicator:
- **Blue channel** — binary on/off (no PWM dimming)
- **Orange channel** — PWM-dimmable, lower nibble of level byte = brightness 0-15

#### 0xff — LED Indicator Set

```
dst(2 LE) || 0xff || 69 69 || b_ch(1) b_lvl(1) o_ch(1) o_lvl(1) || 0x00 * pad
```

**Per-channel slot format** (4 bytes):

| Byte | Name | Values |
|------|------|--------|
| 0 | `b_ch` | `0xa0` = blue channel select, `0x00` = don't touch blue |
| 1 | `b_lvl` | Non-zero = blue ON, `0x00` = blue OFF (binary, no dimming) |
| 2 | `o_ch` | `0xff` = orange channel select, `0x00` = don't touch orange |
| 3 | `o_lvl` | Lower nibble = brightness 0-15. Upper nibble is ignored |

> **Critical rule**: each packet must update **exactly one channel**.
> The untouched channel's bytes must be zeroed.
>
> - Blue ON:   `a0 12 00 00`
> - Blue OFF:  `a0 00 00 00`
> - Orange ON: `00 00 ff 1F` (brightness 15)
> - Orange OFF:`00 00 ff 00`
>
> Sending a combined packet like `a0 12 ff 12` lights both LEDs
> simultaneously (producing purple), but this latches the firmware into
> an undefined state that survives normal per-channel updates. Clearing
> this state requires a reset sequence: blue-off → orange-off → orange-on.

The firmware normalises `0xff` (orange channel select) to `0xb6` internally,
so query responses report `0xb6` as the orange channel byte.

State is persistent on the device across power cycles.

#### 0xd9 — LED Indicator Query

```
dst(2 LE) || 0xd9 || 6b 69 || gw_mac5(1) || 0x00
```

- **Vendor is `0x696b`** (unique to this opcode, not the usual `0x6969`)
- `gw_mac5`: last byte of the connected gateway's MAC address. This is a
  **relay routing tag** — the mesh firmware silently drops the response if
  this byte doesn't match the gateway identity. Sending any other value
  results in a timeout with no error indication.

**Required query sequence**:
1. Send unicast `0xda` status poll to the target device
2. Wait for the `0xdb` wake-up notification to arrive
3. Wait ~210ms (shorter gaps produce no response)
4. Send `0xd9` query with correct `gw_mac5`
5. `0xd3` response arrives within ~60ms

#### 0xd3 — LED State Response / Slot Assignment Response (notification)

This opcode serves **two purposes** depending on context:

**LED state response** (after `0xd9` query):
```
0xd3 || 69 69 || 94 10 || b_ch(1) b_lvl(1) o_ch(1) o_lvl(1) || tail
```

Bytes 5-8 carry the same 4-byte layout as the `0xff` setter. The orange
channel byte will be `0xb6` (the canonical internal value), not `0xff`.

**Slot assignment response** (after `0xf0` query):
```
0xd3 || 69 69 || echo(1) || 10 04 || slot(1) || 0x00 * pad
```

See [Schedule Operations](#schedule--alarm-operations) for details.

### Find-me (LED Flash)

#### 0xf5 — Find-me

```
dst(2 LE) || 0xf5 || 69 69 || mode(1) duration(1) || 0x00 * pad
```

- Start: `mode=0x03, duration=0x0f` (blink pattern, 15 seconds)
- Stop: `mode=0x00, duration=0x00`
- Flashes the currently configured LED colour (set via `0xff`)

### Time Synchronisation

#### 0xc5 — SetUTC (broadcast)

```
0xFFFF || 0xc5 || 69 69 || tv_sec(4 LE) || tz(1)
```

- `tv_sec`: Unix epoch seconds, little-endian 32-bit
- `tz`: timezone byte — **MUST be `0x00`**

> **Critical**: the firmware offsets its internal clock by the timezone byte.
> Since alarm records store times in UTC, any non-zero timezone value causes
> schedule misfires (e.g. a 10-hour offset). Always send `tz=0x00`.

This command must be sent on every connection. Mesh devices have no
persistent RTC and rely on this broadcast to anchor their schedule clock.
Typically sent immediately after login, sometimes repeated during reconnects.

The mesh responds with a burst of `0xdc` status notifications from every
device, providing the current on/off state of the entire mesh at session
start.

### Schedule / Alarm Operations

All schedule operations target the **schedule coordinator** at address
`0x0030`. The coordinator manages up to 250 alarm slots (0x00-0xf9).

The **gateway cookie** (`gw_mac5` — last byte of the connected gateway's
MAC) is required for all schedule queries and deletes. Sending the wrong
cookie causes silent failures.

#### 0xcc — Write Alarm (2 fragments)

Creates or updates an alarm record. Sent as two consecutive packets:

**Fragment 0** (10 data bytes):
```
0x0030 || 0xcc || 69 69 || 0x00 || alarm[0..8]
```

**Fragment 1** (9 data bytes):
```
0x0030 || 0xcc || 69 69 || 0x01 || alarm[9..15] || xor_checksum
```

The XOR checksum is the XOR-fold of all 16 alarm record bytes.

See [Schedule Record Format](#schedule-record-format) for the 16-byte layout.

#### 0xcd — Query Alarm Slot

```
0x0030 || 0xcd || 69 69 || start_slot(1) || gw_mac5(1) || 0x00 || target_lo(1) || target_hi(1)
```

- `start_slot`: scan-from cursor (0-indexed). The coordinator returns the
  first occupied slot **at or after** this position.
- `target`: device/group address to filter (use `0x0000` for all alarms)

Response is **two `0xc2` notifications** per occupied slot:

```
0xc2 || 69 69 || actual_slot(1) || frag_data[9]
```

- `actual_slot`: the real slot index where the alarm is stored
- End-of-list sentinel: `actual_slot == 0xff` (remaining data zeroed)
- Walk algorithm: `cursor=0; loop { query(cursor) → actual_slot; if 0xff: break; cursor = actual_slot + 1 }`

#### 0xce — Delete Alarm

```
0x0030 || 0xce || 69 69 || slot(1) || gw_mac5(1) || 0x00
```

Deletes the alarm at the given slot index (obtained from `0xf0` after
create, or from `0xcd` query walk).

#### 0xf0 — Slot Assignment Query

Sent after writing an alarm via `0xcc` to learn which slot was assigned:

```
0x0030 || 0xf0 || 69 69 || gw_mac5(1) || 0x00
```

Response is a `0xd3` notification:
```
0xd3 || 69 69 || echo(1) || 0x10 0x04 || slot(1) || 0x00 * pad
```

The coordinator allocates a **new slot** for each write (monotonically
increasing) rather than overwriting in-place.

### Sunrise / Sunset (0xd0)

A 3-fragment opcode for pushing compressed sunrise/sunset schedule data.
The frame layout is documented from firmware analysis:

**Per fragment** (3 frames, each 15-byte plaintext):
```
dst(2 LE) || 0xd0 || 69 69 || frag_index(1) || compressed_sun_data[8]
```

- Fragment 2 has an XOR checksum as the trailing byte
- Payload contains day-of-epoch and compressed astronomical data

> **Status**: fully analysed from firmware but never observed in any app
> capture. Believed to be exclusive to the "PIXIE Plus" / Gateway app
> variant, not the plain PIXIE app. The firmware code exists in the shared
> library but may not be reachable from the plain app's UI layer.

---

## Schedule Record Format

The 16-byte alarm record carried by `0xcc` write and `0xc2` query responses:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `id` | Alarm identifier. `0xc9` conventionally for countdowns; otherwise a monotonic counter. Must be consistent across enable/disable toggles. |
| 1 | 1 | `repeat` | Weekday bitmask (UTC-rotated). `bit0`=Mon, `bit1`=Tue, ... `bit6`=Sun. `0x7f`=daily, `0x1f`=Mon-Fri, `0x00`=one-shot. See [Timezone & Weekday Rotation](#timezone--weekday-rotation). |
| 2 | 1 | `hour` | Fire hour in **UTC** (0-23). |
| 3 | 1 | `min` | Fire minute in **UTC** (0-59). |
| 4-5 | 2 | `type` | Type marker (little-endian). `0x0003` = countdown timer. `0x0000` = regular timer. |
| 6 | 1 | `sec` | For countdowns: duration in whole minutes. For regular timers: always `0x00`. |
| 7 | 1 | `act` | Enable flag. `0x01` = active, `0x00` = disabled but retained. |
| 8-9 | 2 | `target` | Target device or group address (little-endian). Groups use `0x8000 \| id`. |
| 10-14 | 5 | `state` | Kind-dependent state bytes. See below. |
| 15 | 1 | `action` | `0x00` = turn OFF. `0x64` = turn ON at 100%. `0xff` = ON at current/unchanged brightness. |

### State Bytes (offset 10-14)

| Timer Type | State Bytes | Action Byte | Notes |
|------------|------------|-------------|-------|
| Countdown OFF | `00 00 00 00 00` | `0x00` | Countdown timers are OFF-only by firmware design |
| Recurring/one-shot ON (device) | `00 00 ff ff ff` | `0x64` | 100% brightness |
| Recurring/one-shot ON (group) | `00 00 ff ff ff` | `0xff` | "Use current" brightness |
| Recurring/one-shot OFF | `00 00 ff ff ff` | `0x00` | Turn off |

The `ff ff ff` tail means "don't change mode/colour".

### Alarm Types

1. **Countdown timer** (`type=0x0003`): fires after a duration in minutes.
   Uses the `id=0xc9` convention. **OFF-only** — the firmware hardcodes all
   state bytes to zero. A "countdown to ON" must use a regular one-shot timer
   instead.

2. **One-shot timer** (`type=0x0000, repeat=0x00`): fires once at the
   specified UTC hour:minute. Minute-level precision (no seconds field).

3. **Recurring schedule** (`type=0x0000, repeat!=0x00`): fires on the
   specified weekdays at the given UTC hour:minute.

### Enable/Disable Toggle

Toggling a schedule's enable state is a plain `0xcc` rewrite with ONLY the
`act` byte flipped (`0x01` ↔ `0x00`). There is no separate enable/disable
opcode. The XOR checksum updates accordingly (single-bit delta).

### Alarm ID Allocation

The `id` byte (offset 0) is a monotonic counter. The range 0x01-0xC8 and
0xCA-0xFF is available (0xC9 is conventionally reserved for countdown
timers). IDs do not need to be globally unique — the coordinator stores
alarms by slot index, not by ID. However, IDs must be consistent across
enable/disable toggles of the same alarm.

---

## Schedule Flows

### Create Alarm

1. Build the 16-byte alarm record
2. Send `0xcc` fragment 0 (alarm bytes 0-8)
3. Send `0xcc` fragment 1 (alarm bytes 9-15 + XOR checksum)
4. Send `0xf0` slot query to get the assigned slot index
5. Optionally send `0xcd` query for the assigned slot to verify the write

### List Alarms

1. Send `0xcd` with `start_slot=0`
2. Receive two `0xc2` notifications (fragments 0 and 1 of the alarm record)
3. Extract `actual_slot` from the first byte after vendor
4. If `actual_slot == 0xff`: end of list, stop
5. Set `cursor = actual_slot + 1`, go to step 1

### Delete Alarm

1. Send `0xce` with the slot index and gateway cookie

### Enable/Disable Alarm

1. Read the current alarm record via `0xcd`
2. Flip the `act` byte (offset 7): `0x01` ↔ `0x00`
3. Recompute the XOR checksum
4. Write the modified record via `0xcc` (2 fragments)

---

## Timezone & Weekday Rotation

All times on the wire are **UTC**. The client must convert local time to UTC
before building alarm records.

When the UTC conversion crosses a day boundary, the weekday bitmask must be
**rotated**:

```
local_to_utc(local_hour, repeat_bitmask, tz_offset_hours):
    utc_hour = (local_hour - tz_offset_hours + 24) % 24
    adjusted = local_hour - tz_offset_hours + 24

    if adjusted < 24:
        # Day went backward: right-rotate 7-bit mask by 1
        utc_repeat = (repeat >> 1) | ((repeat & 1) << 6)
    elif adjusted >= 48:
        # Day went forward: left-rotate 7-bit mask by 1
        utc_repeat = ((repeat << 1) & 0x7f) | ((repeat >> 6) & 1)
    else:
        utc_repeat = repeat

    return utc_hour, utc_repeat & 0x7f
```

**Example**: "8:00 AM Mon-Fri" in AEST (UTC+10):
- `local_hour=8, repeat=0x1f, tz=10`
- `utc_hour = (8 - 10 + 24) % 24 = 22`
- `adjusted = 22 < 24` → right-rotate: `0x1f` → `0x4f`
- Wire: `hour=22, repeat=0x4f` (Sun-Thu UTC = Mon-Fri AEST)

The reverse conversion (UTC→local) uses the inverse rotations.

---

## Gateway Detection

The **gateway** is whichever mesh node the client has a direct BLE connection
to. Any mesh node can serve as gateway — the role is dynamic and renegotiated
by the mesh.

To select a gateway:
1. Scan for BLE advertisements matching the mesh name and network ID
2. Read manufacturer data byte 14: `0x47` = current gateway, `0x45` = leaf
3. Prefer connecting to the current gateway (`0x47`) for best relay performance
4. If no `0x47` node is visible, any `0x45` node works — it will relay commands

The gateway's MAC address is needed for:
- Command packet encryption (nonce construction)
- Notification packet decryption (nonce construction)
- The `gw_mac5` cookie in LED queries, schedule queries, group commands, and
  schedule deletes

`gw_mac5` is specifically byte index 5 (the last byte) of the gateway's MAC
address in standard printed order (`AA:BB:CC:DD:EE:FF` → `gw_mac5 = 0xFF`).

---

## Connection Maintenance

### Heartbeat

The client must periodically read from CHAR_PAIR (`0x1914`) to keep the BLE
connection alive. A 30-second interval is typical. Without this, the
connection will time out and drop.

### Post-Login Initialisation

Immediately after login, the client should:
1. Subscribe to CHAR_NOTIFY (`0x1911`) by writing `0x01`
2. Send `0xc5` SetUTC time sync broadcast
3. Optionally send `0xda` status polls to populate device state

### Reconnection

On connection drop:
- Scan, reconnect, re-login, re-derive session key
- All sequence counters and session salts reset
- Alarm records on the coordinator are persistent across reconnects
- Exponential backoff (e.g. 2s → 30s) is recommended

---

## Platform Notes

### macOS / iOS (CoreBluetooth)

- Real MAC addresses are hidden by the OS. Extract the MAC from:
  - Manufacturer data bytes 2-5 (partial)
  - DIS Model Number characteristic (`0x2a24`) for the full MAC string
- CHAR_PAIR login write must use ATT Write Request (with response), not
  Write Without Response
- CoreBluetooth UUIDs are used instead of MAC addresses for device identity

### Linux (BlueZ)

- Real MAC addresses are available directly from the BLE scan
- CHAR_PAIR login can use Write Without Response (BlueZ maps correctly)
- No additional MAC extraction needed
