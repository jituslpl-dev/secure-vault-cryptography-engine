/**
 * @file time_lock.h
 * @brief Algorithmic time-locking via proof-of-work key wrapping.
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_TIME_LOCK_H
#define SECURE_VAULT_TIME_LOCK_H

#include <cstdint>
#include <cstddef>

namespace securevault {

/**
 * @brief Algorithmic time-locking mechanism.
 *
 * Embeds immutable temporal constraints directly into the encrypted payload.
 * The time-lock uses a sequential hash-iteration proof-of-work scheme:
 * the decryption key is derived by performing N iterations of SHA-256,
 * where N is proportional to the lock duration. This makes it impossible
 * to decrypt before the required computational work is completed, which
 * takes a deterministic amount of wall-clock time.
 *
 * Additionally, an absolute Unix timestamp is embedded: the payload cannot
 * be decrypted before that timestamp, regardless of computational speed.
 */
class TimeLock {
public:
    static constexpr uint8_t MAGIC[4] = {'S', 'V', 'T', 'L'}; ///< Magic header for time-locked payloads

    /// @brief Header size: magic(4) + version(1) + flags(1) + unlock_ts(8) + iters(8) + salt(16) + reserved(2) = 40
    static constexpr size_t HEADER_SIZE = 40;

    /**
     * @brief Create a time-locked key wrapper.
     *
     * Wraps the encryption key using a proof-of-work scheme. The key is
     * XOR-encrypted with a wrapping key derived by iterating SHA-256 N times.
     *
     * @param key The 32-byte encryption key to lock.
     * @param unlockTimestamp Unix timestamp (seconds) after which decryption is allowed.
     * @param iterations Number of SHA-256 iterations for the proof-of-work lock.
     * @param salt 16-byte salt for key derivation.
     * @param out Output buffer (must be at least HEADER_SIZE + 32 bytes).
     * @return Total bytes written.
     */
    static size_t lock(
        const uint8_t key[32],
        uint64_t unlockTimestamp,
        uint64_t iterations,
        const uint8_t salt[16],
        uint8_t* out
    );

    /**
     * @brief Attempt to unlock a time-locked key.
     *
     * Performs the proof-of-work computation to derive the wrapping key,
     * then XOR-decrypts the locked key. The current timestamp must be
     * past the unlock timestamp.
     *
     * @param lockedData The locked payload (header + encrypted key).
     * @param lockedLen Length of lockedData.
     * @param currentTimestamp Current Unix timestamp.
     * @param outKey Output: 32-byte decrypted key.
     * @return 0 on success, negative error code on failure:
     *         -1 = too short, -2 = bad magic, -3 = time not yet reached.
     */
    static int unlock(
        const uint8_t* lockedData,
        size_t lockedLen,
        uint64_t currentTimestamp,
        uint8_t outKey[32]
    );

    /**
     * @brief Read the unlock timestamp from a locked payload without unlocking.
     * @param lockedData Pointer to the locked payload.
     * @param lockedLen Length of the payload.
     * @return Unix timestamp, or 0 if payload is too short.
     */
    static uint64_t getUnlockTimestamp(const uint8_t* lockedData, size_t lockedLen);

    /**
     * @brief Read the iteration count from a locked payload.
     * @param lockedData Pointer to the locked payload.
     * @param lockedLen Length of the payload.
     * @return Iteration count, or 0 if payload is too short.
     */
    static uint64_t getIterations(const uint8_t* lockedData, size_t lockedLen);

    /**
     * @brief Estimate the number of iterations needed for a target lock duration.
     *
     * Based on ~1M SHA-256 iterations per second on a typical CPU.
     *
     * @param lockDurationSeconds Desired lock duration in seconds.
     * @return Estimated iteration count (at least 1).
     */
    static uint64_t estimateIterations(double lockDurationSeconds);

private:
    /**
     * @brief Derive a key by iterating SHA-256 N times on seed material.
     * @param seed Seed material for key derivation.
     * @param seedLen Length of seed in bytes.
     * @param iterations Number of SHA-256 iterations.
     * @param out 32-byte derived key output.
     */
    static void deriveKey(
        const uint8_t* seed, size_t seedLen,
        uint64_t iterations,
        uint8_t out[32]
    );
};

} // namespace securevault

#endif // SECURE_VAULT_TIME_LOCK_H



