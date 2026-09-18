/**
 * @file test_main.cpp
 * @brief Test runner entry point for SecureVault C++ unit tests.
 *
 * Simple test framework with assertion macros. No external dependencies.
 *
 * @license MIT
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

// ─── Test Framework ─────────────────────────────────────────────

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "  FAIL: %s:%d: ASSERT_TRUE(%s) failed\n", __FILE__, __LINE__, #cond); \
            g_testsFailed++; \
            return; \
        } \
    } while (0)

#define ASSERT_FALSE(cond) \
    do { \
        if (cond) { \
            fprintf(stderr, "  FAIL: %s:%d: ASSERT_FALSE(%s) failed\n", __FILE__, __LINE__, #cond); \
            g_testsFailed++; \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            fprintf(stderr, "  FAIL: %s:%d: ASSERT_EQ(%s, %s) failed: %lld != %lld\n", \
                    __FILE__, __LINE__, #a, #b, (long long)(a), (long long)(b)); \
            g_testsFailed++; \
            return; \
        } \
    } while (0)

#define ASSERT_MEM_EQ(a, b, len) \
    do { \
        if (memcmp((a), (b), (len)) != 0) { \
            fprintf(stderr, "  FAIL: %s:%d: ASSERT_MEM_EQ(%s, %s, %d) failed\n", \
                    __FILE__, __LINE__, #a, #b, (int)(len)); \
            g_testsFailed++; \
            return; \
        } \
    } while (0)

#define RUN_TEST(testFunc) \
    do { \
        fprintf(stdout, "  > %s ... ", #testFunc); \
        int prevFailed = g_testsFailed; \
        testFunc(); \
        if (g_testsFailed == prevFailed) { \
            fprintf(stdout, "PASS\n"); \
            g_testsPassed++; \
        } else { \
            fprintf(stdout, "FAIL\n"); \
        } \
    } while (0)

// ─── Test Function Declarations ─────────────────────────────────

// SHA-256 tests (test_sha256.cpp)
void testSha256_emptyString();
void testSha256_abc();
void testSha256_largeData();
void testSha256_digestSize();

// AES-256 tests (test_aes256.cpp)
void testAes256_singleBlock();
void testAes256_ctrMode();
void testAes256_ctrRoundTrip();
void testAes256_keyExpansion();

// Encryption engine tests (test_encryption_engine.cpp)
void testEncryptDecrypt_roundTrip();
void testEncryptDecrypt_largeData();
void testDecrypt_wrongKey();
void testDecrypt_tamperedData();
void testDecrypt_tooShort();
void testDeriveKeyFromPassword();

// Time-lock tests (test_time_lock.cpp)
void testTimeLock_lockUnlock();
void testTimeLock_beforeUnlockTime();
void testTimeLock_afterUnlockTime();
void testTimeLock_tamperedData();
void testTimeLock_estimateIterations();

// Streaming tests (test_streaming.cpp)
void testStreaming_roundTrip();
void testStreaming_integrity();
void testStreaming_tamperDetection();
void testStreaming_largeData();

// Fuzz tests (test_fuzz.cpp)
void testFuzz_randomInputs();
void testFuzz_corruptedHeaders();
void testFuzz_truncatedData();
void testFuzz_zeroLengthInput();

// ─── Main ────────────────────────────────────────────────────────

int main() {
    fprintf(stdout, "\n");
    fprintf(stdout, "========================================\n");
    fprintf(stdout, "  SecureVault C++ Unit Test Suite\n");
    fprintf(stdout, "========================================\n\n");

    fprintf(stdout, "[SHA-256 Tests]\n");
    RUN_TEST(testSha256_emptyString);
    RUN_TEST(testSha256_abc);
    RUN_TEST(testSha256_largeData);
    RUN_TEST(testSha256_digestSize);

    fprintf(stdout, "\n[AES-256 Tests]\n");
    RUN_TEST(testAes256_singleBlock);
    RUN_TEST(testAes256_ctrMode);
    RUN_TEST(testAes256_ctrRoundTrip);
    RUN_TEST(testAes256_keyExpansion);

    fprintf(stdout, "\n[Encryption Engine Tests]\n");
    RUN_TEST(testEncryptDecrypt_roundTrip);
    RUN_TEST(testEncryptDecrypt_largeData);
    RUN_TEST(testDecrypt_wrongKey);
    RUN_TEST(testDecrypt_tamperedData);
    RUN_TEST(testDecrypt_tooShort);
    RUN_TEST(testDeriveKeyFromPassword);

    fprintf(stdout, "\n[Time-Lock Tests]\n");
    RUN_TEST(testTimeLock_lockUnlock);
    RUN_TEST(testTimeLock_beforeUnlockTime);
    RUN_TEST(testTimeLock_afterUnlockTime);
    RUN_TEST(testTimeLock_tamperedData);
    RUN_TEST(testTimeLock_estimateIterations);

    fprintf(stdout, "\n[Streaming Engine Tests]\n");
    RUN_TEST(testStreaming_roundTrip);
    RUN_TEST(testStreaming_integrity);
    RUN_TEST(testStreaming_tamperDetection);
    RUN_TEST(testStreaming_largeData);

    fprintf(stdout, "\n[Fuzz Tests]\n");
    RUN_TEST(testFuzz_randomInputs);
    RUN_TEST(testFuzz_corruptedHeaders);
    RUN_TEST(testFuzz_truncatedData);
    RUN_TEST(testFuzz_zeroLengthInput);

    fprintf(stdout, "\n========================================\n");
    fprintf(stdout, "  Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    fprintf(stdout, "========================================\n\n");

    return g_testsFailed > 0 ? 1 : 0;
}



