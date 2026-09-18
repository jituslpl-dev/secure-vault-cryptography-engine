/**
 * @file streaming_engine.h
 * @brief Chunk-based streaming encryption/decryption engine.
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_STREAMING_ENGINE_H
#define SECURE_VAULT_STREAMING_ENGINE_H

#include <cstdint>
#include <cstddef>
#include "sha256.h"
#include "aes256.h"

namespace securevault {

/**
 * @brief Chunk-based streaming encryption/decryption engine.
 *
 * Designed for large-scale datasets: processes data in configurable chunks
 * to minimize I/O latency and memory overhead. Each chunk is encrypted
 * independently using AES-256-CTR with a monotonically increasing counter,
 * enabling concurrent processing of multiple chunks.
 *
 * A rolling SHA-256 hash is maintained across all chunks for tamper-evident
 * integrity verification of the entire stream.
 */
class StreamingEngine {
public:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 64 * 1024; ///< Default chunk size: 64 KB

    /**
     * @brief Streaming encryptor for incremental encryption.
     *
     * Usage: call init(), then processChunk() repeatedly, then finalize().
     */
    class Encryptor {
    public:
        /** @brief Construct an uninitialized encryptor. */
        Encryptor();

        /**
         * @brief Initialize with key, IV, and optional chunk size.
         * @param key 32-byte AES-256 key.
         * @param iv 16-byte initialization vector.
         * @param chunkSize Chunk size in bytes (default: 64 KB).
         */
        void init(const uint8_t key[32], const uint8_t iv[16],
                  size_t chunkSize = DEFAULT_CHUNK_SIZE);

        /**
         * @brief Encrypt one chunk of data.
         * @param in Input data (chunk-sized, except possibly the last chunk).
         * @param inLen Input length in bytes.
         * @param out Output buffer (at least inLen bytes).
         * @param outLen Receives output length.
         */
        void processChunk(const uint8_t* in, size_t inLen, uint8_t* out, size_t& outLen);

        /**
         * @brief Finalize and write the rolling SHA-256 digest.
         * @param outDigest 32-byte output digest of all plaintext.
         * @param totalBytes Receives total bytes processed.
         */
        void finalize(uint8_t outDigest[32], uint64_t& totalBytes);

    private:
        AES256  aes_;
        SHA256  hash_;
        uint64_t totalBytes_;
        size_t  chunkSize_;
        bool    initialized_;
    };

    /**
     * @brief Streaming decryptor for incremental decryption.
     *
     * Usage: call init(), then processChunk() repeatedly, then finalize() + verify().
     */
    class Decryptor {
    public:
        /** @brief Construct an uninitialized decryptor. */
        Decryptor();

        /**
         * @brief Initialize with key and IV.
         * @param key 32-byte AES-256 key.
         * @param iv 16-byte initialization vector.
         */
        void init(const uint8_t key[32], const uint8_t iv[16]);

        /**
         * @brief Decrypt one chunk of data.
         * @param in Input ciphertext chunk.
         * @param inLen Input length in bytes.
         * @param out Output buffer (at least inLen bytes).
         * @param outLen Receives output length.
         */
        void processChunk(const uint8_t* in, size_t inLen, uint8_t* out, size_t& outLen);

        /**
         * @brief Finalize and compute the rolling SHA-256 digest.
         * @param outDigest 32-byte output digest of all decrypted plaintext.
         * @param totalBytes Receives total bytes processed.
         */
        void finalize(uint8_t outDigest[32], uint64_t& totalBytes);

        /**
         * @brief Verify the computed digest against an expected value.
         * @param expectedDigest 32-byte expected digest.
         * @return true if digests match.
         */
        bool verify(const uint8_t expectedDigest[32]) const;

    private:
        AES256  aes_;
        SHA256  hash_;
        uint8_t computedDigest_[32];
        uint64_t totalBytes_;
        bool    initialized_;
        bool    finalized_;
    };

    /**
     * @brief Encrypt an entire buffer in one call using chunked processing.
     *
     * Convenience method that internally uses the Encryptor class.
     *
     * @param in Input data buffer.
     * @param inLen Input length in bytes.
     * @param key 32-byte AES-256 key.
     * @param iv 16-byte initialization vector.
     * @param out Output buffer (at least inLen bytes).
     * @param outLen Receives output length.
     * @param outDigest 32-byte SHA-256 digest of all plaintext.
     */
    static void encryptBuffer(
        const uint8_t* in, size_t inLen,
        const uint8_t key[32],
        const uint8_t iv[16],
        uint8_t* out, size_t& outLen,
        uint8_t outDigest[32]
    );

    /**
     * @brief Decrypt an entire buffer in one call using chunked processing.
     *
     * Convenience method that internally uses the Decryptor class.
     *
     * @param in Input ciphertext buffer.
     * @param inLen Input length in bytes.
     * @param key 32-byte AES-256 key.
     * @param iv 16-byte initialization vector.
     * @param out Output buffer (at least inLen bytes).
     * @param outLen Receives output length.
     * @param expectedDigest 32-byte expected SHA-256 digest.
     * @return true if integrity verification passes.
     */
    static bool decryptBuffer(
        const uint8_t* in, size_t inLen,
        const uint8_t key[32],
        const uint8_t iv[16],
        uint8_t* out, size_t& outLen,
        const uint8_t expectedDigest[32]
    );
};

} // namespace securevault

#endif // SECURE_VAULT_STREAMING_ENGINE_H



