/**
 * @file aes256.h
 * @brief AES-256 in CTR mode — dependency-free, pure C++ implementation.
 *
 * Implements the full Rijndael cipher with 14-round key expansion,
 * S-Box substitution, ShiftRows, MixColumns, and Galois field multiplication.
 * CTR mode turns AES into a stream cipher, enabling zero-copy-friendly
 * chunk processing with no padding overhead.
 *
 * @par Standards
 * - AES: NIST FIPS 197
 * - CTR mode: NIST SP 800-38A
 *
 * @license MIT
 */

#ifndef SECURE_VAULT_AES256_H
#define SECURE_VAULT_AES256_H

#include <cstdint>
#include <cstddef>

namespace securevault {

/**
 * @brief AES-256 block cipher in CTR (Counter) mode.
 *
 * CTR mode is symmetric: the same function encrypts and decrypts.
 * Operates in-place or with separate in/out buffers.
 */
class AES256 {
public:
    static constexpr size_t KEY_SIZE   = 32;  ///< 256-bit key
    static constexpr size_t BLOCK_SIZE = 16;  ///< 128-bit block
    static constexpr size_t ROUNDS     = 14;  ///< AES-256 uses 14 rounds

    /** @brief Construct an AES-256 instance with zeroed state. */
    AES256();

    /**
     * @brief Set the 256-bit encryption key.
     *
     * Performs key expansion to generate 15 round keys (240 bytes).
     *
     * @param key 32-byte AES-256 key.
     */
    void setKey(const uint8_t key[KEY_SIZE]);

    /**
     * @brief Encrypt or decrypt `len` bytes using CTR mode.
     *
     * CTR mode is symmetric: the same function encrypts and decrypts.
     * The counter is incremented after each 16-byte block.
     *
     * @param in Input data buffer.
     * @param out Output data buffer (can equal `in` for in-place operation).
     * @param len Number of bytes to process.
     */
    void processCTR(const uint8_t* in, uint8_t* out, size_t len);

    /**
     * @brief Reset the CTR counter to a specific 128-bit value.
     *
     * Used for chunked streaming where each chunk starts at a known counter.
     *
     * @param counter 16-byte counter/nonce value.
     */
    void setCounter(const uint8_t counter[BLOCK_SIZE]);

    /**
     * @brief Get the current counter value.
     * @param counter Output buffer for the 16-byte counter.
     */
    void getCounter(uint8_t counter[BLOCK_SIZE]) const;

private:
    uint8_t roundKeys_[240];        ///< 15 round keys × 16 bytes
    uint8_t counter_[BLOCK_SIZE];    ///< Current CTR counter value

    /**
     * @brief Expand the 256-bit key into 15 round keys.
     * @param key 32-byte AES-256 key.
     */
    void keyExpansion(const uint8_t key[KEY_SIZE]);

    /**
     * @brief Encrypt a single 16-byte block (used internally for CTR keystream).
     * @param in 16-byte input block.
     * @param out 16-byte output block.
     */
    void encryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]);

    /**
     * @brief Increment the 128-bit counter by 1 (big-endian).
     */
    void incrementCounter();

    /**
     * @brief Galois Field (2^8) multiplication.
     * @param a First operand.
     * @param b Second operand.
     * @return Product in GF(2^8).
     */
    static uint8_t gmul(uint8_t a, uint8_t b);

    /// @brief SubBytes: substitute each byte using the Rijndael S-Box.
    void subBytes(uint8_t state[16]);
    /// @brief ShiftRows: cyclically shift each row left.
    void shiftRows(uint8_t state[16]);
    /// @brief MixColumns: mix each column via GF(2^8) matrix multiplication.
    void mixColumns(uint8_t state[16]);
    /// @brief AddRoundKey: XOR state with the round key.
    void addRoundKey(uint8_t state[16], const uint8_t* roundKey);
};

} // namespace securevault

#endif // SECURE_VAULT_AES256_H



