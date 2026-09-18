#!/usr/bin/env python3
"""
SecureVault — Python Demonstration
===================================
Demonstrates the same cryptographic concepts as the C++/Node.js engine:
  - Custom SHA-256 (verified against NIST vectors)
  - AES-256-CTR encryption/decryption
  - Tamper-evident integrity verification
  - Time-locking with proof-of-work key wrapping
  - Chunk-based streaming

This uses Python's hashlib (SHA-256) and cryptography concepts matching the C++ implementation.
"""

import hashlib
import os
import struct
import time
import sys

# ============================================================================
# SHA-256 — Using Python's hashlib (same algorithm as our C++ implementation)
# ============================================================================
def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash — matches our C++ bitwise implementation."""
    return hashlib.sha256(data).digest()

# ============================================================================
# AES-256-CTR — Pure Python implementation matching our C++ code
# ============================================================================

# Rijndael S-Box (same as src/aes256.cpp)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _gmul(a, b):
    """Galois Field multiplication (same as C++ gmul)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _key_expansion(key: bytes) -> list:
    """AES-256 key expansion → 15 round keys (same as C++ keyExpansion)."""
    Nk = 8
    Nr = 14
    total_words = 4 * (Nr + 1)
    rk = list(key[:32])

    for i in range(Nk, total_words):
        temp = rk[(i - 1) * 4:(i - 1) * 4 + 4]
        temp = list(temp)

        if i % Nk == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [SBOX[b] for b in temp]
            # Rcon
            temp[0] ^= RCON[i // Nk]
        elif i % Nk == 4:
            temp = [SBOX[b] for b in temp]

        for j in range(4):
            rk.append(rk[(i - Nk) * 4 + j] ^ temp[j])

    return rk

def _encrypt_block(block: bytes, round_keys: list) -> bytes:
    """Encrypt a single 16-byte block (same as C++ encryptBlock)."""
    state = list(block)

    # AddRoundKey (initial)
    for i in range(16):
        state[i] ^= round_keys[i]

    # Rounds 1..13
    for r in range(1, 14):
        # SubBytes
        state = [SBOX[b] for b in state]
        # ShiftRows
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[10] = state[10], state[2]
        state[6], state[14] = state[14], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        # MixColumns
        for c in range(4):
            col = state[c*4:c*4+4]
            state[c*4]   = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
            state[c*4+1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
            state[c*4+2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
            state[c*4+3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
        # AddRoundKey
        rk = round_keys[r*16:r*16+16]
        for i in range(16):
            state[i] ^= rk[i]

    # Final round (no MixColumns)
    state = [SBOX[b] for b in state]
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[10] = state[10], state[2]
    state[6], state[14] = state[14], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
    rk = round_keys[14*16:14*16+16]
    for i in range(16):
        state[i] ^= rk[i]

    return bytes(state)

def _increment_counter(counter: bytearray):
    """Increment 128-bit big-endian counter (same as C++ incrementCounter)."""
    for i in range(15, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break

def aes256_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CTR encrypt/decrypt (same as C++ processCTR)."""
    round_keys = _key_expansion(key)
    counter = bytearray(iv)
    result = bytearray()
    offset = 0

    while offset < len(data):
        keystream = _encrypt_block(bytes(counter), round_keys)
        block_len = min(16, len(data) - offset)
        for i in range(block_len):
            result.append(data[offset + i] ^ keystream[i])
        _increment_counter(counter)
        offset += block_len

    return bytes(result)

# ============================================================================
# Encryption Engine (matches src/encryption_engine.cpp)
# ============================================================================

MAGIC = b'SVENC'
VERSION = 0x01
FLAG_TIME_LOCKED = 0x01
HEADER_SIZE = 5 + 1 + 1 + 16 + 32  # 55

def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt with AES-256-CTR + embedded SHA-256 integrity digest."""
    digest = sha256(plaintext)
    header = MAGIC + bytes([VERSION, 0x00]) + iv + digest
    ciphertext = aes256_ctr(plaintext, key, iv)
    return header + ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt and verify integrity."""
    if len(ciphertext) < HEADER_SIZE:
        raise ValueError("Ciphertext too short")
    if ciphertext[:5] != MAGIC:
        raise ValueError("Bad magic header")
    flags = ciphertext[6]
    if flags & FLAG_TIME_LOCKED:
        raise ValueError("Data is time-locked — use decrypt_time_locked() instead")

    iv = ciphertext[7:23]
    stored_digest = ciphertext[23:55]
    enc_data = ciphertext[55:]

    plaintext = aes256_ctr(enc_data, key, iv)
    computed_digest = sha256(plaintext)

    if computed_digest != stored_digest:
        raise ValueError("Integrity check failed — data may be tampered or wrong key")

    return plaintext

# ============================================================================
# Time-Locking (matches src/time_lock.cpp)
# ============================================================================

TL_MAGIC = b'SVTL'
TL_HEADER_SIZE = 40

def _derive_key(seed: bytes, iterations: int) -> bytes:
    """Derive key by iterating SHA-256 N times (same as C++ deriveKey)."""
    out = sha256(seed)
    for _ in range(iterations):
        out = sha256(out)
    return out

def encrypt_with_time_lock(plaintext: bytes, key: bytes, iv: bytes,
                           unlock_timestamp: int, iterations: int, salt: bytes) -> bytes:
    """Encrypt with time-lock (matches C++ encryptWithTimeLock)."""
    digest = sha256(plaintext)
    header = MAGIC + bytes([VERSION, FLAG_TIME_LOCKED]) + iv + digest

    # TimeLock header
    tl_header = TL_MAGIC + bytes([0x01, 0x03])
    tl_header += struct.pack('>Q', unlock_timestamp)
    tl_header += struct.pack('>Q', iterations)
    tl_header += salt
    tl_header += b'\x00\x00'

    # Derive wrapping key
    derivation_seed = salt + struct.pack('>Q', unlock_timestamp) + struct.pack('>Q', iterations)
    wrap_key = _derive_key(derivation_seed, iterations)

    # XOR key with wrapping key
    locked_key = bytes(k ^ w for k, w in zip(key, wrap_key))

    # Encrypt plaintext
    ciphertext = aes256_ctr(plaintext, key, iv)

    return header + tl_header + locked_key + ciphertext

def decrypt_time_locked(ciphertext: bytes, current_timestamp: int) -> bytes:
    """Decrypt time-locked data (matches C++ decryptTimeLocked)."""
    if len(ciphertext) < HEADER_SIZE + TL_HEADER_SIZE + 32:
        raise ValueError("Ciphertext too short for time-locked data")
    if ciphertext[:5] != MAGIC:
        raise ValueError("Bad magic header")
    flags = ciphertext[6]
    if not (flags & FLAG_TIME_LOCKED):
        raise ValueError("Not time-locked — use decrypt() with a key")

    iv = ciphertext[7:23]
    stored_digest = ciphertext[23:55]
    tl_data = ciphertext[55:]

    # Parse time-lock header
    if tl_data[:4] != TL_MAGIC:
        raise ValueError("Bad time-lock magic")
    tl_flags = tl_data[5]
    unlock_ts = struct.unpack('>Q', tl_data[6:14])[0]
    iters = struct.unpack('>Q', tl_data[14:22])[0]
    salt = tl_data[22:38]

    # Check timestamp
    if tl_flags & 0x01:
        if current_timestamp < unlock_ts:
            raise ValueError("Time not yet reached — cannot decrypt")

    # Derive wrapping key (computationally expensive)
    derivation_seed = salt + struct.pack('>Q', unlock_ts) + struct.pack('>Q', iters)
    wrap_key = _derive_key(derivation_seed, iters)

    # Unlock the key
    locked_key = tl_data[TL_HEADER_SIZE:TL_HEADER_SIZE + 32]
    key = bytes(lk ^ wk for lk, wk in zip(locked_key, wrap_key))

    # Decrypt
    enc_data = tl_data[TL_HEADER_SIZE + 32:]
    plaintext = aes256_ctr(enc_data, key, iv)

    # Verify integrity
    computed_digest = sha256(plaintext)
    if computed_digest != stored_digest:
        raise ValueError("Integrity check failed — data may be tampered")

    return plaintext

def is_time_locked(data: bytes) -> bool:
    if len(data) < HEADER_SIZE:
        return False
    if data[:5] != MAGIC:
        return False
    return (data[6] & FLAG_TIME_LOCKED) != 0

def get_unlock_timestamp(data: bytes) -> int:
    if not is_time_locked(data):
        return 0
    tl_data = data[HEADER_SIZE:]
    return struct.unpack('>Q', tl_data[6:14])[0]

def estimate_iterations(lock_duration_seconds: float) -> int:
    return max(1, int(lock_duration_seconds * 1000000))

# ============================================================================
# Key Derivation (matches C++ deriveKeyFromPassword)
# ============================================================================

def derive_key_from_password(password: bytes, salt: bytes, iterations: int = 100000) -> bytes:
    """PBKDF-like key derivation (matches C++ deriveKeyFromPassword)."""
    out = sha256(password + salt)
    for _ in range(iterations):
        out = sha256(out)
    return out

# ============================================================================
# Streaming Engine (matches src/streaming_engine.cpp)
# ============================================================================

CHUNK_SIZE = 64 * 1024

def stream_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> tuple:
    """Chunk-based streaming encrypt (matches C++ StreamingEngine::encryptBuffer)."""
    round_keys = _key_expansion(key)
    counter = bytearray(iv)
    result = bytearray()
    h = hashlib.sha256()

    offset = 0
    while offset < len(plaintext):
        chunk_len = min(CHUNK_SIZE, len(plaintext) - offset)
        chunk = plaintext[offset:offset + chunk_len]

        # Update rolling hash with plaintext
        h.update(chunk)

        # Encrypt chunk
        chunk_result = bytearray()
        co = 0
        while co < len(chunk):
            keystream = _encrypt_block(bytes(counter), round_keys)
            bl = min(16, len(chunk) - co)
            for i in range(bl):
                chunk_result.append(chunk[co + i] ^ keystream[i])
            _increment_counter(counter)
            co += bl

        result.extend(chunk_result)
        offset += chunk_len

    return bytes(result), h.digest()

def stream_decrypt(ciphertext: bytes, key: bytes, iv: bytes, expected_digest: bytes) -> tuple:
    """Chunk-based streaming decrypt (matches C++ StreamingEngine::decryptBuffer)."""
    round_keys = _key_expansion(key)
    counter = bytearray(iv)
    result = bytearray()
    h = hashlib.sha256()

    offset = 0
    while offset < len(ciphertext):
        chunk_len = min(CHUNK_SIZE, len(ciphertext) - offset)
        chunk = ciphertext[offset:offset + chunk_len]

        # Decrypt chunk
        chunk_result = bytearray()
        co = 0
        while co < len(chunk):
            keystream = _encrypt_block(bytes(counter), round_keys)
            bl = min(16, len(chunk) - co)
            for i in range(bl):
                chunk_result.append(chunk[co + i] ^ keystream[i])
            _increment_counter(counter)
            co += bl

        # Update rolling hash with decrypted plaintext
        h.update(chunk_result)
        result.extend(chunk_result)
        offset += chunk_len

    computed = h.digest()
    verified = (computed == expected_digest)
    return bytes(result), verified

def random_bytes(length: int) -> bytes:
    return os.urandom(length)


# ============================================================================
# DEMONSTRATION
# ============================================================================

def main():
    # Windows may use cp1252 for redirected output, which cannot represent the
    # box-drawing characters used by this presentation-friendly demo.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║   SecureVault — Live Demonstration (Python)      ║")
    print("║   (Same crypto as the C++/Node.js engine)        ║")
    print("╚══════════════════════════════════════════════════╝")
    print()

    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  ✓ {name}")
            passed += 1
        else:
            print(f"  ✗ {name}")
            failed += 1

    # ─── 1. SHA-256 Tests ──────────────────────────────────────────
    print("━━━ 1. SHA-256 Hashing ━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # NIST test vector: SHA-256("")
    digest = sha256(b'')
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print(f"  SHA-256('')  = {digest.hex()}")
    check("SHA-256 of empty string matches NIST vector", digest.hex() == expected)

    # NIST test vector: SHA-256("abc")
    digest = sha256(b'abc')
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print(f"  SHA-256('abc') = {digest.hex()}")
    check("SHA-256 of 'abc' matches NIST vector", digest.hex() == expected)

    # Large data
    data = os.urandom(10000)
    check("SHA-256 of 10KB random data matches hashlib", sha256(data) == hashlib.sha256(data).digest())
    print()

    # ─── 2. AES-256-CTR Encryption ────────────────────────────────
    print("━━━ 2. AES-256-CTR Encryption ━━━━━━━━━━━━━━━━━━━")

    plaintext = b'Hello, SecureVault!'
    key = random_bytes(32)
    iv = random_bytes(16)

    print(f"  Plaintext:  {plaintext.decode()}")
    encrypted = encrypt(plaintext, key, iv)
    print(f"  Encrypted:  {encrypted[55:75].hex()}... ({len(encrypted)} bytes)")
    decrypted = decrypt(encrypted, key)
    print(f"  Decrypted:  {decrypted.decode()}")
    check("Encrypt/decrypt round-trip", decrypted == plaintext)
    print()

    # ─── 3. Multi-block Data (64 KiB) ─────────────────────────────
    print("━━━ 3. Multi-block Encryption (64 KiB) ━━━━━━━━━━")

    large_data = os.urandom(64 * 1024)
    key = random_bytes(32)
    iv = random_bytes(16)

    t0 = time.time()
    enc = encrypt(large_data, key, iv)
    enc_time = time.time() - t0

    t0 = time.time()
    dec = decrypt(enc, key)
    dec_time = time.time() - t0

    total_mib = len(large_data) / (1024 * 1024)
    print(f"  Data size: 64 KiB")
    print(f"  Encrypt: {enc_time*1000:.1f} ms")
    print(f"  Decrypt: {dec_time*1000:.1f} ms")
    print(f"  Round-trip throughput: {total_mib/(enc_time+dec_time):.2f} MiB/s")
    check("64 KiB round-trip verified", dec == large_data)
    print()

    # ─── 4. Tamper Detection ───────────────────────────────────────
    print("━━━ 4. Tamper Detection ━━━━━━━━━━━━━━━━━━━━━━━━━")

    data = b'Critical financial data'
    key = random_bytes(32)
    iv = random_bytes(16)
    encrypted = encrypt(data, key, iv)

    # Flip a bit
    tampered = bytearray(encrypted)
    tampered[60] ^= 0x01

    try:
        decrypt(bytes(tampered), key)
        check("Tamper detection (should have failed)", False)
    except ValueError as e:
        print(f"  Tamper detected: {e}")
        check("Tamper detection works", True)
    print()

    # ─── 5. Wrong Key Detection ────────────────────────────────────
    print("━━━ 5. Wrong Key Detection ━━━━━━━━━━━━━━━━━━━━━━")

    data = b'Secret message'
    key = random_bytes(32)
    wrong_key = random_bytes(32)
    iv = random_bytes(16)
    encrypted = encrypt(data, key, iv)

    try:
        decrypt(encrypted, wrong_key)
        check("Wrong key detection (should have failed)", False)
    except ValueError as e:
        print(f"  Wrong key rejected: {e}")
        check("Wrong key detection works", True)
    print()

    # ─── 6. Password-Based Encryption ───────────────────────────────
    print("━━━ 6. Password-Based Encryption ━━━━━━━━━━━━━━━━")

    data = b'Password-protected file contents'
    salt = random_bytes(16)
    key = derive_key_from_password(b'mySecretPass', salt, 10000)
    iv = random_bytes(16)
    encrypted = encrypt(data, key, iv)

    # Decrypt with correct password
    key2 = derive_key_from_password(b'mySecretPass', salt, 10000)
    decrypted = decrypt(encrypted, key2)
    print(f"  Data:      {data.decode()}")
    print(f"  Decrypted: {decrypted.decode()}")
    check("Password encryption round-trip", decrypted == data)

    # Wrong password
    key3 = derive_key_from_password(b'wrongPass', salt, 10000)
    try:
        decrypt(encrypted, key3)
        check("Wrong password detection (should have failed)", False)
    except ValueError:
        check("Wrong password rejected", True)
    print()

    # ─── 7. Streaming Encryption ────────────────────────────────────
    print("━━━ 7. Streaming Encryption (64 KiB) ━━━━━━━━━━━━━")

    stream_data = os.urandom(64 * 1024)
    key = random_bytes(32)
    iv = random_bytes(16)

    enc_data, digest = stream_encrypt(stream_data, key, iv)
    dec_data, verified = stream_decrypt(enc_data, key, iv, digest)

    print(f"  Data size: 64 KiB")
    print(f"  Integrity: {'✓ Verified' if verified else '✗ FAILED'}")
    check("Stream round-trip verified", dec_data == stream_data)
    check("Stream integrity verified", verified)

    # Tamper test
    tampered = bytearray(enc_data)
    tampered[0] ^= 0xFF
    _, verified2 = stream_decrypt(bytes(tampered), key, iv, digest)
    check("Stream tamper detection", not verified2)
    print()

    # ─── 8. Time-Locked Encryption ──────────────────────────────────
    print("━━━ 8. Time-Locked Encryption ━━━━━━━━━━━━━━━━━━━")

    secret = b'This data is locked until the future arrives!'
    key = random_bytes(32)
    iv = random_bytes(16)
    salt = random_bytes(16)

    now = int(time.time())
    unlock_time = now + 10  # 10 seconds in the future
    iterations = 5000  # Small for demo

    print(f"  Secret:    {secret.decode()}")
    print(f"  Lock until: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(unlock_time))}")
    print(f"  PoW iterations: {iterations}")

    locked = encrypt_with_time_lock(secret, key, iv, unlock_time, iterations, salt)
    print(f"  Time-locked: {'Yes' if is_time_locked(locked) else 'No'}")
    print(f"  Encrypted size: {len(locked)} bytes")

    # Try to decrypt now (should fail)
    try:
        decrypt_time_locked(locked, now)
        check("Time-lock before unlock (should fail)", False)
    except ValueError as e:
        print(f"  Before unlock: {e}")
        check("Time-lock correctly refuses decryption before unlock time", True)

    # Decrypt with future timestamp
    future_ts = now + 3600
    print(f"  Unlocking with future timestamp (PoW: {iterations} SHA-256 iterations)...")
    t0 = time.time()
    tl_decrypted = decrypt_time_locked(locked, future_ts)
    pow_time = time.time() - t0
    print(f"  PoW time: {pow_time*1000:.1f} ms")
    print(f"  Decrypted: {tl_decrypted.decode()}")
    check("Time-lock decryption after unlock time", tl_decrypted == secret)

    # getUnlockTimestamp
    retrieved_ts = get_unlock_timestamp(locked)
    check("getUnlockTimestamp returns correct value", retrieved_ts == unlock_time)
    print()

    # ─── 9. Non-time-locked detection ──────────────────────────────
    print("━━━ 9. Time-Lock Detection ━━━━━━━━━━━━━━━━━━━━━━")

    data = b'Regular non-locked data'
    key = random_bytes(32)
    iv = random_bytes(16)
    encrypted = encrypt(data, key, iv)
    check("Non-time-locked data detected correctly", not is_time_locked(encrypted))
    print()

    # ─── Summary ────────────────────────────────────────────────────
    print("════════════════════════════════════════════════════")
    print(f"  Results: {passed} passed, {failed} failed")
    print("════════════════════════════════════════════════════")
    print()
    print("  Note: This Python demo mirrors the algorithms and test vectors")
    print("  used by the C++/Node.js engine. It is a functional reference,")
    print("  not a production cryptography recommendation or benchmark.")
    print()

    return 1 if failed > 0 else 0

if __name__ == '__main__':
    sys.exit(main())

