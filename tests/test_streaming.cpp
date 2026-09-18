/**
 * @file test_streaming.cpp
 * @brief Unit tests for the chunk-based streaming engine.
 *
 * @license MIT
 */

#include "streaming_engine.h"
#include <cstring>
#include <cstdlib>

using namespace securevault;

void testStreaming_roundTrip() {
    const char* msg = "Streaming encryption test data for round-trip verification!";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);

    uint8_t* encrypted = static_cast<uint8_t*>(malloc(msgLen));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(msgLen));
    uint8_t digest[32];
    size_t encLen = 0, decLen = 0;

    StreamingEngine::encryptBuffer(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen, digest);

    bool verified = false;
    StreamingEngine::decryptBuffer(encrypted, encLen, key, iv, decrypted, decLen, digest, &verified);

    ASSERT_TRUE(verified);
    ASSERT_EQ(decLen, msgLen);
    ASSERT_MEM_EQ(decrypted, msg, msgLen);

    free(encrypted);
    free(decrypted);
}

void testStreaming_integrity() {
    size_t dataLen = 256 * 1024;  // 256KB
    uint8_t* data = static_cast<uint8_t*>(malloc(dataLen));
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    uint8_t key[32] = {0x55};
    uint8_t iv[16] = {0x11};

    uint8_t* encrypted = static_cast<uint8_t*>(malloc(dataLen));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
    uint8_t digest[32];
    size_t encLen = 0, decLen = 0;

    StreamingEngine::encryptBuffer(data, dataLen, key, iv, encrypted, encLen, digest);

    bool verified = false;
    StreamingEngine::decryptBuffer(encrypted, encLen, key, iv, decrypted, decLen, digest, &verified);

    ASSERT_TRUE(verified);
    ASSERT_MEM_EQ(decrypted, data, dataLen);

    free(data);
    free(encrypted);
    free(decrypted);
}

void testStreaming_tamperDetection() {
    const char* msg = "Tamper detection test";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    uint8_t* encrypted = static_cast<uint8_t*>(malloc(msgLen));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(msgLen));
    uint8_t digest[32];
    size_t encLen = 0, decLen = 0;

    StreamingEngine::encryptBuffer(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen, digest);

    // Tamper with encrypted data
    encrypted[0] ^= 0xFF;

    bool verified = true;  // Start as true, should become false
    StreamingEngine::decryptBuffer(encrypted, encLen, key, iv, decrypted, decLen, digest, &verified);

    ASSERT_FALSE(verified);

    free(encrypted);
    free(decrypted);
}

void testStreaming_largeData() {
    size_t dataLen = 1024 * 1024;  // 1MB
    uint8_t* data = static_cast<uint8_t*>(malloc(dataLen));
    srand(42);
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = static_cast<uint8_t>(rand() & 0xFF);
    }

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    uint8_t* encrypted = static_cast<uint8_t*>(malloc(dataLen));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
    uint8_t digest[32];
    size_t encLen = 0, decLen = 0;

    StreamingEngine::encryptBuffer(data, dataLen, key, iv, encrypted, encLen, digest);

    bool verified = false;
    StreamingEngine::decryptBuffer(encrypted, encLen, key, iv, decrypted, decLen, digest, &verified);

    ASSERT_TRUE(verified);
    ASSERT_MEM_EQ(decrypted, data, dataLen);

    free(data);
    free(encrypted);
    free(decrypted);
}



