/**
 * @file test_encryption_engine.cpp
 * @brief Unit tests for the encryption engine (encrypt/decrypt pipeline).
 *
 * @license MIT
 */

#include "encryption_engine.h"
#include <cstring>
#include <cstdlib>

using namespace securevault;

void testEncryptDecrypt_roundTrip() {
    const char* msg = "Hello, SecureVault!";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 16; i++) iv[i] = static_cast<uint8_t>(0xFF - i);

    size_t outCapacity = msgLen + EncryptionEngine::HEADER_SIZE;
    uint8_t* encrypted = static_cast<uint8_t*>(malloc(outCapacity));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(msgLen));

    size_t encLen = 0, decLen = 0;

    EncryptionEngine::encrypt(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen);

    int result = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);

    ASSERT_EQ(result, 0);
    ASSERT_EQ(decLen, msgLen);
    ASSERT_MEM_EQ(decrypted, msg, msgLen);

    free(encrypted);
    free(decrypted);
}

void testEncryptDecrypt_largeData() {
    size_t dataLen = 100000;
    uint8_t* data = static_cast<uint8_t*>(malloc(dataLen));
    for (size_t i = 0; i < dataLen; i++) {
        data[i] = static_cast<uint8_t>(i * 31 + 17);
    }

    uint8_t key[32] = {0x42};
    uint8_t iv[16] = {0x99};

    size_t outCapacity = dataLen + EncryptionEngine::HEADER_SIZE;
    uint8_t* encrypted = static_cast<uint8_t*>(malloc(outCapacity));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));

    size_t encLen = 0, decLen = 0;

    EncryptionEngine::encrypt(data, dataLen, key, iv, encrypted, encLen);
    int result = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);

    ASSERT_EQ(result, 0);
    ASSERT_MEM_EQ(decrypted, data, dataLen);

    free(data);
    free(encrypted);
    free(decrypted);
}

void testDecrypt_wrongKey() {
    const char* msg = "Secret data";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t wrongKey[32] = {0};
    wrongKey[0] = 0xFF;
    uint8_t iv[16] = {0};

    size_t outCapacity = msgLen + EncryptionEngine::HEADER_SIZE;
    uint8_t* encrypted = static_cast<uint8_t*>(malloc(outCapacity));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(msgLen));

    size_t encLen = 0, decLen = 0;

    EncryptionEngine::encrypt(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen);

    int result = EncryptionEngine::decrypt(encrypted, encLen, wrongKey, decrypted, decLen);

    // Should fail with integrity error (-4)
    ASSERT_EQ(result, -4);

    free(encrypted);
    free(decrypted);
}

void testDecrypt_tamperedData() {
    const char* msg = "Critical data";
    size_t msgLen = strlen(msg);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    size_t outCapacity = msgLen + EncryptionEngine::HEADER_SIZE;
    uint8_t* encrypted = static_cast<uint8_t*>(malloc(outCapacity));
    uint8_t* decrypted = static_cast<uint8_t*>(malloc(msgLen));

    size_t encLen = 0, decLen = 0;

    EncryptionEngine::encrypt(
        reinterpret_cast<const uint8_t*>(msg), msgLen, key, iv, encrypted, encLen);

    // Flip a bit in the ciphertext
    encrypted[encLen - 1] ^= 0x01;

    int result = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);

    // Should fail with integrity error (-4)
    ASSERT_EQ(result, -4);

    free(encrypted);
    free(decrypted);
}

void testDecrypt_tooShort() {
    uint8_t key[32] = {0};
    uint8_t shortData[10] = {0};
    uint8_t out[10] = {0};
    size_t outLen = 0;

    int result = EncryptionEngine::decrypt(shortData, 10, key, out, outLen);

    // Should fail with -1 (too short)
    ASSERT_EQ(result, -1);
}

void testDeriveKeyFromPassword() {
    const char* password = "mySecretPassword";
    uint8_t salt[16] = {0};
    for (int i = 0; i < 16; i++) salt[i] = static_cast<uint8_t>(i);

    uint8_t key1[32], key2[32];
    EncryptionEngine::deriveKeyFromPassword(
        reinterpret_cast<const uint8_t*>(password), strlen(password), salt, 1000, key1);
    EncryptionEngine::deriveKeyFromPassword(
        reinterpret_cast<const uint8_t*>(password), strlen(password), salt, 1000, key2);

    // Same inputs → same key
    ASSERT_MEM_EQ(key1, key2, 32);

    // Different password → different key
    const char* wrongPass = "wrongPassword";
    uint8_t key3[32];
    EncryptionEngine::deriveKeyFromPassword(
        reinterpret_cast<const uint8_t*>(wrongPass), strlen(wrongPass), salt, 1000, key3);

    ASSERT_TRUE(memcmp(key1, key3, 32) != 0);
}



