/**
 * @file encryption_engine.h
 * @brief Encrypt/decrypt pipeline with tamper-evident integrity verification.
 *
 * Combines AES-256-CTR encryption with an embedded SHA-256 digest for
 * integrity verification. Supports optional time-locking via proof-of-work.
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_ENCRYPTION_ENGINE_H
#define SECURE_VAULT_ENCRYPTION_ENGINE_H

#include <cstdint>
#include <cstddef>
#include "sha256.h"
#include "aes256.h"
#include "time_lock.h"

namespace securevault {

/**
 * @brief Encrypted payload format.
 *
 * @par Payload Layout
 * @code
 * +------------------+-------------------+
 * | Field             | Size (bytes)      |
 * +------------------+-------------------+
 * | Magic "SVENC"     | 5                 |
 * | Version           | 1                 |
 * | Flags             | 1                 |
 * | IV / Nonce        | 16                |
 * | SHA-256(plaintext)| 32                |
 * | [TimeLock header] | 0 or 40           |
 * | [Locked key]      | 0 or 32           |
 * | Ciphertext        | variable          |
 * +------------------+-------------------+
 * @endcode
 *
 * If time-locked, the 32-byte AES key is wrapped in the TimeLock
 * structure instead of being derived directly from the password.
 */

/**
 * @brief Encryption engine: encrypt/decrypt with integrity verification.
 *
 * Provides static methods for encrypting and decrypting data using
 * AES-256-CTR with an embedded SHA-256 integrity digest. Supports
 * optional time-locking via proof-of-work key wrapping.
 */
class EncryptionEngine {
public:
    static constexpr uint8_t MAGIC[5] = {'S', 'V', 'E', 'N', 'C'}; ///< Magic header bytes
    static constexpr uint8_t VERSION = 0x01;                         ///< Format version

    /// @brief Flag bit: payload is time-locked
    static constexpr uint8_t FLAG_TIME_LOCKED = 0x01;

    /// @brief Header size in bytes (magic + version + flags + IV + digest)
    static constexpr size_t HEADER_SIZE = 5 + 1 + 1 + 16 + 32; ///< = 55

    /**
     * @brief Encrypt a buffer with AES-256-CTR and integrity digest.
     *
     * Produces a payload of size plaintextLen + HEADER_SIZE.
     *
     * @param plaintext Input data to encrypt.
     * @param plaintextLen Length of input data in bytes.
     * @param key 32-byte AES-256 key.
     * @param iv 16-byte initialization vector (nonce).
     * @param out Output buffer (must be at least plaintextLen + HEADER_SIZE bytes).
     * @param outLen Receives the actual output length.
     */
    static void encrypt(
        const uint8_t* plaintext, size_t plaintextLen,
        const uint8_t key[32],
        const uint8_t iv[16],
        uint8_t* out, size_t& outLen
    );

    /**
     * @brief Encrypt a buffer with time-locking.
     *
     * The AES key is wrapped using the TimeLock proof-of-work mechanism.
     * Decryption requires performing the PoW and the current time must
     * be past the unlock timestamp.
     *
     * @param plaintext Input data to encrypt.
     * @param plaintextLen Length of input data in bytes.
     * @param key 32-byte AES-256 key.
     * @param iv 16-byte initialization vector (nonce).
     * @param unlockTimestamp Unix timestamp after which decryption is allowed.
     * @param iterations PoW iterations for the time-lock.
     * @param salt 16-byte salt for time-lock key derivation.
     * @param out Output buffer.
     * @param outLen Receives the actual output length.
     */
    static void encryptWithTimeLock(
        const uint8_t* plaintext, size_t plaintextLen,
        const uint8_t key[32],
        const uint8_t iv[16],
        uint64_t unlockTimestamp,
        uint64_t iterations,
        const uint8_t salt[16],
        uint8_t* out, size_t& outLen
    );

    /**
     * @brief Decrypt a buffer and verify integrity.
     *
     * @param ciphertext Input encrypted data.
     * @param ciphertextLen Length of encrypted data in bytes.
     * @param key 32-byte AES-256 key.
     * @param out Output buffer (must be at least ciphertextLen bytes).
     * @param outLen Receives the actual output length.
     * @return 0 on success, negative error code on failure:
     *         -1 = too short, -2 = bad magic, -3 = time-locked (use decryptTimeLocked),
     *         -4 = integrity check failed.
     */
    static int decrypt(
        const uint8_t* ciphertext, size_t ciphertextLen,
        const uint8_t key[32],
        uint8_t* out, size_t& outLen
    );

    /**
     * @brief Decrypt a time-locked buffer.
     *
     * Performs the proof-of-work to unwrap the key, then decrypts.
     * The current timestamp must be past the unlock timestamp.
     *
     * @param ciphertext Input encrypted data.
     * @param ciphertextLen Length of encrypted data in bytes.
     * @param currentTimestamp Current Unix timestamp.
     * @param out Output buffer.
     * @param outLen Receives the actual output length.
     * @return 0 on success, negative error code on failure:
     *         -1 = too short, -2 = bad magic, -3 = time not yet reached,
     *         -4 = integrity check failed.
     */
    static int decryptTimeLocked(
        const uint8_t* ciphertext, size_t ciphertextLen,
        uint64_t currentTimestamp,
        uint8_t* out, size_t& outLen
    );

    /**
     * @brief Check if an encrypted payload is time-locked.
     * @param data Pointer to the encrypted payload.
     * @param len Length of the payload.
     * @return true if the payload has the time-locked flag set.
     */
    static bool isTimeLocked(const uint8_t* data, size_t len);

    /**
     * @brief Get the unlock timestamp from a time-locked payload.
     * @param data Pointer to the encrypted payload.
     * @param len Length of the payload.
     * @return Unix timestamp, or 0 if not time-locked.
     */
    static uint64_t getUnlockTimestamp(const uint8_t* data, size_t len);

    /**
     * @brief Derive a 32-byte key from a password using iterated SHA-256.
     *
     * PBKDF-like key derivation: SHA-256(password + salt) iterated N times.
     *
     * @param password Password bytes.
     * @param passwordLen Password length in bytes.
     * @param salt 16-byte salt.
     * @param iterations Iteration count (higher = more secure but slower).
     * @param out 32-byte derived key output.
     */
    static void deriveKeyFromPassword(
        const uint8_t* password, size_t passwordLen,
        const uint8_t salt[16],
        uint64_t iterations,
        uint8_t out[32]
    );
};

} // namespace securevault

#endif // SECURE_VAULT_ENCRYPTION_ENGINE_H



