/**
 * @file test_aes256.cpp
 * @brief Unit tests for the AES-256-CTR implementation.
 *
 * @license MIT
 */

#include "aes256.h"
#include <cstring>
#include <cstdlib>

using namespace securevault;

void testAes256_singleBlock() {
    // Use a known key and plaintext
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);

    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    AES256 aes;
    aes.setKey(key);

    // Encrypt one block via CTR mode (counter starts at 0)
    uint8_t iv[16] = {0};
    aes.setCounter(iv);
    aes.processCTR(plaintext, ciphertext, 16);

    // Ciphertext should not equal plaintext
    ASSERT_TRUE(memcmp(plaintext, ciphertext, 16) != 0);

    // Decrypt: reset counter and process again
    aes.setCounter(iv);
    aes.processCTR(ciphertext, decrypted, 16);

    // Should recover original plaintext
    ASSERT_MEM_EQ(plaintext, decrypted, 16);
}

void testAes256_ctrMode() {
    uint8_t key[32];
    uint8_t iv[16];
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(0xAA ^ i);
    for (int i = 0; i < 16; i++) iv[i] = static_cast<uint8_t>(i);

    const char* msg = "Hello, AES-256-CTR mode encryption test!";
    size_t len = strlen(msg);

    uint8_t* plaintext = reinterpret_cast<uint8_t*>(const_cast<char*>(msg));
    uint8_t ciphertext[64];
    uint8_t decrypted[64];

    AES256 aes;
    aes.setKey(key);
    aes.setCounter(iv);
    aes.processCTR(plaintext, ciphertext, len);

    aes.setCounter(iv);
    aes.processCTR(ciphertext, decrypted, len);

    ASSERT_MEM_EQ(plaintext, decrypted, len);
}

void testAes256_ctrRoundTrip() {
    // Test with various sizes (not just multiples of 16)
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    for (size_t testLen : {1u, 7u, 15u, 16u, 17u, 31u, 32u, 33u, 100u, 255u}) {
        uint8_t* data = static_cast<uint8_t*>(malloc(testLen));
        uint8_t* enc = static_cast<uint8_t*>(malloc(testLen));
        uint8_t* dec = static_cast<uint8_t*>(malloc(testLen));

        for (size_t i = 0; i < testLen; i++) {
            data[i] = static_cast<uint8_t>(i * 7 + 3);
        }

        AES256 aes;
        aes.setKey(key);
        aes.setCounter(iv);
        aes.processCTR(data, enc, testLen);

        aes.setCounter(iv);
        aes.processCTR(enc, dec, testLen);

        if (memcmp(data, dec, testLen) != 0) {
            fprintf(stderr, "  FAIL: CTR round-trip failed for size %zu\n", testLen);
            g_testsFailed++;
            free(data); free(enc); free(dec);
            return;
        }

        free(data); free(enc); free(dec);
    }
}

void testAes256_keyExpansion() {
    // Verify that different keys produce different keystreams
    uint8_t key1[32] = {0};
    uint8_t key2[32] = {0};
    key2[0] = 0x01;  // One bit different

    uint8_t iv[16] = {0};
    uint8_t plaintext[16] = {0};
    uint8_t ct1[16], ct2[16];

    AES256 aes1, aes2;
    aes1.setKey(key1);
    aes1.setCounter(iv);
    aes1.processCTR(plaintext, ct1, 16);

    aes2.setKey(key2);
    aes2.setCounter(iv);
    aes2.processCTR(plaintext, ct2, 16);

    // Different keys → different ciphertext
    ASSERT_TRUE(memcmp(ct1, ct2, 16) != 0);
}



