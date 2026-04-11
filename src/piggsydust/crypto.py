"""Telink BLE mesh cryptographic primitives.

All operations use a "reversed AES" convention where key, plaintext,
and ciphertext bytes are reversed before and after standard AES-128-ECB.
"""

from __future__ import annotations

import os
import struct

from Crypto.Cipher import AES


class LoginError(Exception):
    """Login handshake failed."""


class TagMismatchError(Exception):
    """CBC-MAC tag did not match during decryption."""


# ---------------------------------------------------------------------------
# Byte utilities
# ---------------------------------------------------------------------------

def _pad16(s: str) -> bytes:
    """Pad or truncate *s* to exactly 16 bytes, zero-filled on the right."""
    b = s.encode("utf-8")[:16]
    return b.ljust(16, b"\x00")


def _xor16(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of two 16-byte values."""
    return bytes(x ^ y for x, y in zip(a, b))


def _reverse16(b: bytes) -> bytes:
    """Reverse all 16 bytes."""
    return bytes(reversed(b[:16]))


# ---------------------------------------------------------------------------
# Core AES primitive
# ---------------------------------------------------------------------------

def reversed_aes(key: bytes, plaintext: bytes) -> bytes:
    """Telink reversed AES-128-ECB.

    1. Reverse key bytes
    2. Reverse plaintext bytes
    3. AES-128-ECB encrypt
    4. Reverse ciphertext bytes
    """
    cipher = AES.new(_reverse16(key), AES.MODE_ECB)
    ct = cipher.encrypt(_reverse16(plaintext))
    return _reverse16(ct)


# ---------------------------------------------------------------------------
# Login handshake
# ---------------------------------------------------------------------------

def build_login_request(name: str, password: str, rand_a: bytes) -> bytes:
    """Build the 17-byte CHAR_PAIR login request.

    Returns ``0x0c || rand_a[8] || enc_req[8]``.
    """
    # key = rand_a || 0x00*8
    key = rand_a[:8].ljust(16, b"\x00")
    # plaintext = pad16(name) XOR pad16(password)
    pt = _xor16(_pad16(name), _pad16(password))
    ct = reversed_aes(key, pt)
    return b"\x0c" + rand_a[:8] + ct[:8]


def parse_login_response(resp: bytes) -> bytes:
    """Extract rand_b from the 17-byte CHAR_PAIR login response.

    Raises :class:`LoginError` if the response is malformed.
    """
    if len(resp) < 17 or resp[0] != 0x0D:
        raise LoginError("invalid login response")
    return resp[1:9]


def derive_session_key(
    name: str, password: str, rand_a: bytes, rand_b: bytes
) -> bytes:
    """Derive the per-session encryption key.

    Note the key/plaintext assignment is the *opposite* of the login request:

    - key       = pad16(name) XOR pad16(password)
    - plaintext = rand_a || rand_b
    """
    key = _xor16(_pad16(name), _pad16(password))
    pt = rand_a[:8] + rand_b[:8]
    return reversed_aes(key, pt)


# ---------------------------------------------------------------------------
# Nonce construction
# ---------------------------------------------------------------------------

def command_nonce(gw_mac: bytes, sno: bytes) -> bytes:
    """Build the 8-byte nonce for encrypting commands.

    ``gw_mac[5] || gw_mac[4] || gw_mac[3] || gw_mac[2] || 0x01 || sno[0:3]``

    *gw_mac* is in standard order (index 0 = first printed octet).
    """
    return bytes([
        gw_mac[5], gw_mac[4], gw_mac[3], gw_mac[2],
        0x01,
        sno[0], sno[1], sno[2],
    ])


def notification_nonce(gw_mac: bytes, sno: bytes, src_addr: int) -> bytes:
    """Build the 8-byte nonce for decrypting notifications.

    ``gw_mac[5] || gw_mac[4] || gw_mac[3] || sno[0:3] || src_lo || src_hi``
    """
    return bytes([
        gw_mac[5], gw_mac[4], gw_mac[3],
        sno[0], sno[1], sno[2],
        src_addr & 0xFF, (src_addr >> 8) & 0xFF,
    ])


# ---------------------------------------------------------------------------
# AES-CCM encrypt / decrypt
# ---------------------------------------------------------------------------

def _cbc_mac(sk: bytes, nonce: bytes, data: bytes) -> bytes:
    """Compute the 2-byte truncated CBC-MAC tag."""
    # B0 = nonce[8] || len(data) || 0x00*7
    b0 = bytearray(16)
    b0[:8] = nonce[:8]
    b0[8] = len(data) & 0xFF

    state = bytearray(reversed_aes(sk, bytes(b0)))

    for i, d in enumerate(data):
        state[i & 0xF] ^= d
        if (i & 0xF) == 0xF or i == len(data) - 1:
            state = bytearray(reversed_aes(sk, bytes(state)))

    return bytes(state[:2])


def _ctr(sk: bytes, nonce: bytes, data: bytes) -> bytes:
    """CTR-mode encrypt/decrypt (symmetric operation)."""
    ctr_block = bytearray(16)
    ctr_block[1:9] = nonce[:8]

    out = bytearray(len(data))
    keystream = bytearray(16)

    for i, d in enumerate(data):
        if (i & 0xF) == 0:
            keystream = bytearray(reversed_aes(sk, bytes(ctr_block)))
            ctr_block[0] += 1
        out[i] = d ^ keystream[i & 0xF]

    return bytes(out)


def encrypt(
    sk: bytes, nonce: bytes, sno: bytes, plaintext: bytes
) -> bytes:
    """Encrypt a command payload using Telink AES-CCM.

    Returns ``sno(3) || tag(2) || ciphertext(N)``.
    """
    tag = _cbc_mac(sk, nonce, plaintext)
    ct = _ctr(sk, nonce, plaintext)
    return sno[:3] + tag + ct


def decrypt(
    sk: bytes, nonce: bytes, tag: bytes, ciphertext: bytes
) -> bytes:
    """Decrypt and verify a notification payload.

    Raises :class:`TagMismatchError` if the CBC-MAC tag does not match.
    """
    plaintext = _ctr(sk, nonce, ciphertext)
    expected = _cbc_mac(sk, nonce, plaintext)
    if tag[:2] != expected[:2]:
        raise TagMismatchError("CBC-MAC tag mismatch")
    return plaintext
