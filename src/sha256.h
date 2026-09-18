/**
 * @file sha256.h
 * @brief Custom SHA-256 hash function (NIST FIPS 180-4).
 *
 * Dependency-free implementation using low-level bitwise operations.
 * Verified against NIST known-answer test vectors.
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_SHA256_H
#define SECURE_VAULT_SHA256_H

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace securevault {

/**
 * @brief Custom SHA-256 implementation using bitwise operations.
 *
 * No external cryptographic dependencies — fully self-contained.
 * Produces a deterministic, tamper-evident 32-byte digest.
 *
 * Supports both one-shot hashing and incremental (streaming) updates.
 *
 * @par NIST Compliance
 * Verified against FIPS 180-4 test vectors:
 * - SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * - SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 */
class SHA256 {
public:
    static constexpr size_t BLOCK_SIZE  = 64;  ///< 512-bit block size
    static constexpr size_t DIGEST_SIZE = 32;  ///< 256-bit digest size

    /** @brief Construct a SHA-256 hasher with initial state. */
    SHA256();

    /**
     * @brief Reset the hash state for reuse.
     *
     * Returns the hasher to its initial state (H0..H7) as if just constructed.
     */
    void reset();

    /**
     * @brief Feed data into the hash.
     *
     * Can be called multiple times for incremental hashing.
     * Data is buffered internally and processed in 64-byte blocks.
     *
     * @param data Pointer to input data (may be nullptr if len is 0).
     * @param len Length of input data in bytes.
     */
    void update(const uint8_t* data, size_t len);

    /**
     * @brief Finalize and write the 32-byte digest.
     *
     * Applies message padding and produces the final hash.
     * After calling, the hasher state is reset.
     *
     * @param out Output buffer for the 32-byte digest (must be at least DIGEST_SIZE bytes).
     */
    void finalize(uint8_t out[DIGEST_SIZE]);

    /**
     * @brief Convenience: hash a single buffer in one call.
     *
     * Equivalent to reset() + update() + finalize().
     *
     * @param data Pointer to input data (may be nullptr if len is 0).
     * @param len Length of input data in bytes.
     * @param out Output buffer for the 32-byte digest.
     */
    static void hash(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]);

private:
    uint32_t state_[8];           ///< Working state variables H0..H7
    uint64_t bitCount_;           ///< Total bits processed
    uint8_t  buffer_[BLOCK_SIZE]; ///< Partial block buffer
    size_t   bufferLen_;          ///< Current bytes in buffer

    /**
     * @brief Process one 64-byte block through the compression function.
     * @param block Pointer to a 64-byte block.
     */
    void processBlock(const uint8_t* block);

    /// @brief Rotate right by n bits.
    static inline uint32_t ROTR(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    /// @brief Shift right by n bits.
    static inline uint32_t SHR(uint32_t x, uint32_t n) {
        return x >> n;
    }
    /// @brief Ch function: (x AND y) XOR (NOT x AND z)
    static inline uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    /// @brief Maj function: (x AND y) XOR (x AND z) XOR (y AND z)
    static inline uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    /// @brief Big Sigma 0: ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22)
    static inline uint32_t BSIG0(uint32_t x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }
    /// @brief Big Sigma 1: ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25)
    static inline uint32_t BSIG1(uint32_t x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }
    /// @brief Small Sigma 0: ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3)
    static inline uint32_t SSIG0(uint32_t x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
    }
    /// @brief Small Sigma 1: ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
    static inline uint32_t SSIG1(uint32_t x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
    }
};

} // namespace securevault

#endif // SECURE_VAULT_SHA256_H



