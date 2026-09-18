/**
 * @file test_sha256.cpp
 * @brief Unit tests for the SHA-256 implementation.
 *
 * Verifies against NIST FIPS 180-4 known-answer test vectors.
 *
 * @license MIT
 */

#include "sha256.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

using namespace securevault;

// NIST FIPS 180-4 test vector: SHA-256("")
static const uint8_t kExpectedEmpty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

// NIST FIPS 180-4 test vector: SHA-256("abc")
static const uint8_t kExpectedAbc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

void testSha256_emptyString() {
    uint8_t digest[32];
    SHA256::hash(nullptr, 0, digest);
    ASSERT_MEM_EQ(digest, kExpectedEmpty, 32);
}

void testSha256_abc() {
    const char* input = "abc";
    uint8_t digest[32];
    SHA256::hash(reinterpret_cast<const uint8_t*>(input), 3, digest);
    ASSERT_MEM_EQ(digest, kExpectedAbc, 32);
}

void testSha256_largeData() {
    // Generate 10KB of pseudo-random data
    const size_t len = 10000;
    uint8_t* data = static_cast<uint8_t*>(malloc(len));
    srand(12345);
    for (size_t i = 0; i < len; i++) {
        data[i] = static_cast<uint8_t>(rand() & 0xFF);
    }

    // Hash twice — should be identical (deterministic)
    uint8_t digest1[32];
    uint8_t digest2[32];
    SHA256::hash(data, len, digest1);
    SHA256::hash(data, len, digest2);

    ASSERT_MEM_EQ(digest1, digest2, 32);

    // Change one byte — digest should change
    data[0] ^= 0x01;
    SHA256::hash(data, len, digest2);
    ASSERT_TRUE(memcmp(digest1, digest2, 32) != 0);

    free(data);
}

void testSha256_digestSize() {
    uint8_t digest[32];
    SHA256::hash(reinterpret_cast<const uint8_t*>("test"), 4, digest);
    // Digest size is always 32 bytes (verified by the function signature)
    ASSERT_EQ(SHA256::DIGEST_SIZE, 32u);
}



