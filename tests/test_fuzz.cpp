/**
 * @file test_fuzz.cpp
 * @brief Fuzz tests for invalid, corrupted, and edge-case inputs.
 *
 * These tests verify that the engine handles malformed inputs gracefully
 * without crashing or exhibiting undefined behavior.
 *
 * @license MIT
 */

#include "encryption_engine.h"
#include "time_lock.h"
#include "sha256.h"
#include <cstring>
#include <cstdlib>

using namespace securevault;

void testFuzz_randomInputs() {
    // Feed random garbage data to decrypt — should never crash
    srand(999);
    uint8_t key[32] = {0};

    for (int trial = 0; trial < 100; trial++) {
        size_t len = static_cast<size_t>(rand() % 200) + 1;
        uint8_t* data = static_cast<uint8_t*>(malloc(len));
        uint8_t* out = static_cast<uint8_t*>(malloc(len));

        for (size_t i = 0; i < len; i++) {
            data[i] = static_cast<uint8_t>(rand() & 0xFF);
        }

        size_t outLen = 0;
        // Should return an error code, not crash
        int result = EncryptionEngine::decrypt(data, len, key, out, outLen);
        (void)result;  // We just care that it doesn't crash

        free(data);
        free(out);
    }
    ASSERT_TRUE(true);  // If we got here, no crashes
}

void testFuzz_corruptedHeaders() {
    // Create valid encrypted data, then corrupt the header
    const char* msg = "Test data for header corruption";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    size_t outCapacity = msgLen + EncryptionEngine::HEADER_SIZE;
    uint8_t* encrypted = static_cast<uint8_t*>(malloc(outCapacity));
    uint8_t* out = static_cast<uint8_t*>(malloc(msgLen));
    size_t encLen = 0, outLen = 0;

    EncryptionEngine::encrypt(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen);

    // Corrupt each byte of the header one at a time
    for (size_t i = 0; i < EncryptionEngine::HEADER_SIZE; i++) {
        encrypted[i] ^= 0xFF;
        int result = EncryptionEngine::decrypt(encrypted, encLen, key, out, outLen);
        (void)result;  // Should be an error, not a crash
        encrypted[i] ^= 0xFF;  // Restore
    }

    ASSERT_TRUE(true);  // No crashes
    free(encrypted);
    free(out);
}

void testFuzz_truncatedData() {
    // Test progressively shorter data
    uint8_t key[32] = {0};
    uint8_t out[256];
    size_t outLen = 0;

    for (size_t len = 0; len < 100; len++) {
        uint8_t data[100] = {0};
        int result = EncryptionEngine::decrypt(data, len, key, out, outLen);
        (void)result;  // Should fail gracefully
    }

    ASSERT_TRUE(true);  // No crashes
}

void testFuzz_zeroLengthInput() {
    // SHA-256 of zero-length input should work
    uint8_t digest[32];
    SHA256::hash(nullptr, 0, digest);
    // Known answer: e3b0c442...
    ASSERT_EQ(digest[0], 0xe3);
    ASSERT_EQ(digest[1], 0xb0);

    // Encrypt zero-length plaintext
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t out[EncryptionEngine::HEADER_SIZE + 16];
    size_t outLen = 0;

    EncryptionEngine::encrypt(nullptr, 0, key, iv, out, outLen);

    // Should produce header-only output
    ASSERT_EQ(outLen, EncryptionEngine::HEADER_SIZE);

    // Decrypt it back
    uint8_t decrypted[16];
    size_t decLen = 0;
    int result = EncryptionEngine::decrypt(out, outLen, key, decrypted, decLen);

    ASSERT_EQ(result, 0);
    ASSERT_EQ(decLen, 0u);
}



