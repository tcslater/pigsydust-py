"""Tests for crypto module — ported from Go test vectors."""

from Crypto.Cipher import AES

from piggsydust.crypto import (
    LoginError,
    TagMismatchError,
    _pad16,
    _reverse16,
    _xor16,
    build_login_request,
    command_nonce,
    decrypt,
    derive_session_key,
    encrypt,
    notification_nonce,
    parse_login_response,
    reversed_aes,
)


# ---------------------------------------------------------------------------
# Reversed AES
# ---------------------------------------------------------------------------


def test_reversed_aes_round_trip():
    """Verify ReversedAES matches manual AES with reversed inputs."""
    key = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
    pt = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00])

    result = reversed_aes(key, pt)

    # Manual computation.
    rk = _reverse16(key)
    rp = _reverse16(pt)
    cipher = AES.new(rk, AES.MODE_ECB)
    ct = cipher.encrypt(rp)
    expected = _reverse16(ct)

    assert result == expected


def test_reversed_aes_different_keys():
    key1 = b"\x01" + b"\x00" * 15
    key2 = b"\x02" + b"\x00" * 15
    pt = b"\xff" + b"\x00" * 15
    assert reversed_aes(key1, pt) != reversed_aes(key2, pt)


def test_reversed_aes_zero_key():
    result = reversed_aes(b"\x00" * 16, b"\x00" * 16)
    assert result != b"\x00" * 16


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


def test_login_request_format():
    rand_a = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    payload = build_login_request("Smart Light", "12345678", rand_a)

    assert len(payload) == 17
    assert payload[0] == 0x0C
    assert payload[1:9] == rand_a
    # enc_req should be non-zero.
    assert payload[9:17] != b"\x00" * 8


def test_parse_login_response_valid():
    resp = bytearray(17)
    resp[0] = 0x0D
    for i in range(8):
        resp[1 + i] = (i + 1) * 0x11
    rand_b = parse_login_response(bytes(resp))
    for i in range(8):
        assert rand_b[i] == (i + 1) * 0x11


def test_parse_login_response_wrong_tag():
    resp = bytearray(17)
    resp[0] = 0x0C  # wrong
    try:
        parse_login_response(bytes(resp))
        assert False, "expected LoginError"
    except LoginError:
        pass


def test_parse_login_response_too_short():
    resp = bytearray(10)
    resp[0] = 0x0D
    try:
        parse_login_response(bytes(resp))
        assert False, "expected LoginError"
    except LoginError:
        pass


# ---------------------------------------------------------------------------
# Session key
# ---------------------------------------------------------------------------


def test_derive_session_key_deterministic():
    rand_a = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    rand_b = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    sk1 = derive_session_key("Smart Light", "12345678", rand_a, rand_b)
    sk2 = derive_session_key("Smart Light", "12345678", rand_a, rand_b)
    assert sk1 == sk2


def test_derive_session_key_nonzero():
    rand_a = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    rand_b = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    sk = derive_session_key("Smart Light", "12345678", rand_a, rand_b)
    assert sk != b"\x00" * 16


def test_derive_session_key_different_nonces():
    rand_a1 = b"\x01" + b"\x00" * 7
    rand_a2 = b"\x02" + b"\x00" * 7
    rand_b = b"\x11" + b"\x00" * 7
    sk1 = derive_session_key("test", "pass", rand_a1, rand_b)
    sk2 = derive_session_key("test", "pass", rand_a2, rand_b)
    assert sk1 != sk2


# ---------------------------------------------------------------------------
# Nonce construction
# ---------------------------------------------------------------------------


def test_command_nonce():
    gw_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    sno = bytes([0x01, 0x42, 0x43])
    nonce = command_nonce(gw_mac, sno)
    assert nonce == bytes([0xFF, 0xEE, 0xDD, 0xCC, 0x01, 0x01, 0x42, 0x43])


def test_notification_nonce():
    gw_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    sno = bytes([0x05, 0x06, 0x07])
    src_addr = 0x0102
    nonce = notification_nonce(gw_mac, sno, src_addr)
    assert nonce == bytes([0xFF, 0xEE, 0xDD, 0x05, 0x06, 0x07, 0x02, 0x01])


# ---------------------------------------------------------------------------
# AES-CCM encrypt/decrypt round-trip
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_round_trip():
    rand_a = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    rand_b = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    sk = derive_session_key("Smart Light", "12345678", rand_a, rand_b)

    gw_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    sno = bytes([0x01, 0x42, 0x43])
    nonce = command_nonce(gw_mac, sno)

    plaintext = bytes([
        0xFF, 0xFF,  # dst broadcast
        0xED,        # opcode
        0x69, 0x69,  # vendor
        0x01,        # state=ON
    ] + [0x00] * 9)

    packet = encrypt(sk, nonce, sno, plaintext)
    assert len(packet) == 3 + 2 + len(plaintext)
    assert packet[:3] == sno

    tag = packet[3:5]
    ct = packet[5:]
    decrypted = decrypt(sk, nonce, tag, ct)
    assert decrypted == plaintext


def test_decrypt_wrong_key():
    sk1 = b"\x01" + b"\x00" * 15
    sk2 = b"\x02" + b"\x00" * 15
    nonce = bytes(range(8))
    sno = b"\x00\x00\x00"
    plaintext = bytes([0x01, 0x02, 0x03, 0x04, 0x05])

    packet = encrypt(sk1, nonce, sno, plaintext)
    tag = packet[3:5]
    ct = packet[5:]

    try:
        decrypt(sk2, nonce, tag, ct)
        assert False, "expected TagMismatchError"
    except TagMismatchError:
        pass


def test_encrypt_different_sno():
    sk = b"\x42" + b"\x00" * 15
    nonce1 = bytes([1, 2, 3, 4, 5, 0, 0, 0])
    nonce2 = bytes([1, 2, 3, 4, 5, 1, 0, 0])
    sno1 = b"\x00\x00\x00"
    sno2 = b"\x01\x00\x00"
    plaintext = bytes([0x01, 0x02, 0x03, 0x04, 0x05])

    p1 = encrypt(sk, nonce1, sno1, plaintext)
    p2 = encrypt(sk, nonce2, sno2, plaintext)
    assert p1[5:] != p2[5:]


def test_encrypt_decrypt_various_lengths():
    sk = bytes([0xAA, 0xBB, 0xCC] + [0x00] * 13)
    nonce = bytes(range(1, 9))
    sno = bytes([0x01, 0x02, 0x03])

    for length in (7, 10, 15):
        plaintext = bytes(range(1, length + 1))
        packet = encrypt(sk, nonce, sno, plaintext)
        tag = packet[3:5]
        ct = packet[5:]
        decrypted = decrypt(sk, nonce, tag, ct)
        assert decrypted == plaintext
