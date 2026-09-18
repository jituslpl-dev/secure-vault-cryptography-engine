/**
 * @file test_integration.cpp
 * @brief End-to-end integration tests for the full encryption pipeline.
 *
 * Tests the complete workflow: password → key derivation → encryption →
 * time-locking → decryption → integrity verification.
 *
 * @license MIT
 */

#include "encryption_engine.h"
#include "time_lock.h"
#include "streaming_engine.h"
#include "sha256.h"
#include "logger.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

using namespace securevault;

static int passed = 0;
static int failed = 0;

#define CHECK(name, cond) \
    do { \
        if (cond) { \
            printf("  ✓ %s\n", name); \
            passed++; \
        } else { \
            printf("  ✗ %s\n", name); \
            failed++; \
        } \
    } while (0)

int main() {
    printf("\n========================================\n");
    printf("  SecureVault Integration Tests\n");
    printf("========================================\n\n");

    // ─── Test 1: Full encrypt/decrypt pipeline with password ───────
    printf("[Full Pipeline: Password → Encrypt → Decrypt]\n");
    {
        const char* password = "mySecretPassword123";
        const char* data = "Confidential data for integration testing";
        size_t dataLen = strlen(data);
        uint8_t salt[16] = {0};
        for (int i = 0; i < 16; i++) salt[i] = static_cast<uint8_t>(i);

        // Derive key
        uint8_t key[32];
        EncryptionEngine::deriveKeyFromPassword(
            reinterpret_cast<const uint8_t*>(password), strlen(password), salt, 5000, key);

        // Encrypt
        uint8_t iv[16] = {0xAA};
        size_t encCapacity = dataLen + EncryptionEngine::HEADER_SIZE;
        uint8_t* encrypted = static_cast<uint8_t*>(malloc(encCapacity));
        size_t encLen = 0;
        EncryptionEngine::encrypt(
            reinterpret_cast<const uint8_t*>(data), dataLen, key, iv, encrypted, encLen);

        // Decrypt
        uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
        size_t decLen = 0;
        int result = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);

        CHECK("Password-based encrypt/decrypt round-trip",
              result == 0 && decLen == dataLen &&
              memcmp(decrypted, data, dataLen) == 0);

        free(encrypted);
        free(decrypted);
    }
    printf("\n");

    // ─── Test 2: Time-locked encryption full workflow ──────────────
    printf("[Full Pipeline: Time-Locked Encryption]\n");
    {
        const char* data = "Time-locked secret data";
        size_t dataLen = strlen(data);

        uint8_t key[32] = {0};
        for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);
        uint8_t iv[16] = {0};
        uint8_t salt[16] = {0xBB};

        uint64_t unlockTs = 1000000;
        uint64_t iterations = 100;

        // Encrypt with time-lock
        size_t encCapacity = dataLen + EncryptionEngine::HEADER_SIZE +
                             TimeLock::HEADER_SIZE + 32;
        uint8_t* encrypted = static_cast<uint8_t*>(malloc(encCapacity));
        size_t encLen = 0;
        EncryptionEngine::encryptWithTimeLock(
            reinterpret_cast<const uint8_t*>(data), dataLen, key, iv,
            unlockTs, iterations, salt, encrypted, encLen);

        // Verify it's detected as time-locked
        CHECK("isTimeLocked detects time-locked data",
              EncryptionEngine::isTimeLocked(encrypted, encLen));

        // Verify unlock timestamp
        uint64_t retrievedTs = EncryptionEngine::getUnlockTimestamp(encrypted, encLen);
        CHECK("getUnlockTimestamp returns correct value", retrievedTs == unlockTs);

        // Decrypt after unlock time
        uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
        size_t decLen = 0;
        int result = EncryptionEngine::decryptTimeLocked(
            encrypted, encLen, unlockTs + 1, decrypted, decLen);

        CHECK("Time-locked decryption after unlock time",
              result == 0 && decLen == dataLen &&
              memcmp(decrypted, data, dataLen) == 0);

        // Try decrypt before unlock time — should fail
        int result2 = EncryptionEngine::decryptTimeLocked(
            encrypted, encLen, unlockTs - 1, decrypted, decLen);
        CHECK("Time-locked decryption before unlock time fails", result2 == -3);

        free(encrypted);
        free(decrypted);
    }
    printf("\n");

    // ─── Test 3: Streaming pipeline ────────────────────────────────
    printf("[Full Pipeline: Streaming Encrypt/Decrypt]\n");
    {
        size_t dataLen = 512 * 1024;  // 512KB
        uint8_t* data = static_cast<uint8_t*>(malloc(dataLen));
        for (size_t i = 0; i < dataLen; i++) {
            data[i] = static_cast<uint8_t>((i * 7 + 3) & 0xFF);
        }

        uint8_t key[32] = {0x42};
        uint8_t iv[16] = {0x99};

        uint8_t* encrypted = static_cast<uint8_t*>(malloc(dataLen));
        uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
        uint8_t digest[32];
        size_t encLen = 0, decLen = 0;

        StreamingEngine::encryptBuffer(data, dataLen, key, iv, encrypted, encLen, digest);

        bool verified = false;
        StreamingEngine::decryptBuffer(encrypted, encLen, key, iv, decrypted, decLen, digest, &verified);

        CHECK("Streaming 512KB round-trip with integrity",
              verified && decLen == dataLen && memcmp(decrypted, data, dataLen) == 0);

        free(data);
        free(encrypted);
        free(decrypted);
    }
    printf("\n");

    // ─── Test 4: Tamper detection across pipeline ──────────────────
    printf("[Full Pipeline: Tamper Detection]\n");
    {
        const char* data = "Critical tamper-detection test data";
        size_t dataLen = strlen(data);

        uint8_t key[32] = {0};
        uint8_t iv[16] = {0};

        size_t encCapacity = dataLen + EncryptionEngine::HEADER_SIZE;
        uint8_t* encrypted = static_cast<uint8_t*>(malloc(encCapacity));
        uint8_t* decrypted = static_cast<uint8_t*>(malloc(dataLen));
        size_t encLen = 0, decLen = 0;

        EncryptionEngine::encrypt(
            reinterpret_cast<const uint8_t*>(data), dataLen, key, iv, encrypted, encLen);

        // Tamper with last byte of ciphertext
        encrypted[encLen - 1] ^= 0x80;

        int result = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);
        CHECK("Tampered ciphertext rejected", result == -4);

        // Tamper with integrity digest
        encrypted[54] ^= 0x01;  // Digest is at offset 23..54
        int result2 = EncryptionEngine::decrypt(encrypted, encLen, key, decrypted, decLen);
        CHECK("Tampered digest rejected", result2 == -4);

        free(encrypted);
        free(decrypted);
    }
    printf("\n");

    // ─── Summary ───────────────────────────────────────────────────
    printf("========================================\n");
    printf("  Results: %d passed, %d failed\n", passed, failed);
    printf("========================================\n\n");

    return failed > 0 ? 1 : 0;
}



