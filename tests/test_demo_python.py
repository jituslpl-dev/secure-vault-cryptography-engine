"""Regression tests for the dependency-free Python reference implementation."""

import hashlib
import time
import unittest

from test.demo_python import (
    aes256_ctr,
    decrypt,
    decrypt_time_locked,
    derive_key_from_password,
    encrypt,
    encrypt_with_time_lock,
    get_unlock_timestamp,
    is_time_locked,
    sha256,
    stream_decrypt,
    stream_encrypt,
)


class SecureVaultReferenceTests(unittest.TestCase):
    KEY = bytes(range(32))
    IV = bytes(range(16))

    def test_sha256_known_answer_vectors(self):
        vectors = {
            b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        }
        for message, expected in vectors.items():
            self.assertEqual(sha256(message).hex(), expected)

    def test_aes_ctr_is_symmetric(self):
        plaintext = b"CTR mode round trip across several blocks" * 3
        ciphertext = aes256_ctr(plaintext, self.KEY, self.IV)
        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(aes256_ctr(ciphertext, self.KEY, self.IV), plaintext)

    def test_container_round_trip_and_tamper_rejection(self):
        plaintext = b"portfolio verification payload"
        ciphertext = encrypt(plaintext, self.KEY, self.IV)
        self.assertEqual(decrypt(ciphertext, self.KEY), plaintext)
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        with self.assertRaises(ValueError):
            decrypt(bytes(tampered), self.KEY)

    def test_stream_round_trip_and_integrity(self):
        plaintext = bytes(range(256)) * 64
        ciphertext, digest = stream_encrypt(plaintext, self.KEY, self.IV)
        recovered, verified = stream_decrypt(ciphertext, self.KEY, self.IV, digest)
        self.assertTrue(verified)
        self.assertEqual(recovered, plaintext)
        modified = bytearray(ciphertext)
        modified[100] ^= 0x80
        _, verified = stream_decrypt(bytes(modified), self.KEY, self.IV, digest)
        self.assertFalse(verified)

    def test_password_derivation_is_deterministic_and_salted(self):
        a = derive_key_from_password(b"password", b"A" * 16, 10)
        b = derive_key_from_password(b"password", b"A" * 16, 10)
        c = derive_key_from_password(b"password", b"B" * 16, 10)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_time_lock_timestamp_gate(self):
        now = int(time.time())
        unlock_at = now + 60
        locked = encrypt_with_time_lock(
            b"future payload", self.KEY, self.IV, unlock_at, 10, b"S" * 16
        )
        self.assertTrue(is_time_locked(locked))
        self.assertEqual(get_unlock_timestamp(locked), unlock_at)
        with self.assertRaises(ValueError):
            decrypt_time_locked(locked, now)
        self.assertEqual(decrypt_time_locked(locked, unlock_at), b"future payload")


if __name__ == "__main__":
    unittest.main()
