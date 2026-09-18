/**
 * @file test_time_lock.cpp
 * @brief Unit tests for the time-locking mechanism.
 *
 * @license MIT
 */

#include "time_lock.h"
#include "encryption_engine.h"
#include <cstring>
#include <cstdlib>

using namespace securevault;

void testTimeLock_lockUnlock() {
    uint8_t key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);

    uint64_t unlockTs = 1000000;
    uint64_t iterations = 100;
    uint8_t salt[16] = {0xAB};

    uint8_t locked[TimeLock::HEADER_SIZE + 32];
    size_t lockedLen = TimeLock::lock(key, unlockTs, iterations, salt, locked);

    ASSERT_EQ(lockedLen, TimeLock::HEADER_SIZE + 32u);

    uint8_t unlockedKey[32];
    int result = TimeLock::unlock(locked, lockedLen, unlockTs + 1, unlockedKey);

    ASSERT_EQ(result, 0);
    ASSERT_MEM_EQ(unlockedKey, key, 32);
}

void testTimeLock_beforeUnlockTime() {
    uint8_t key[32] = {0x42};
    uint64_t unlockTs = 1000000;
    uint64_t iterations = 100;
    uint8_t salt[16] = {0};

    uint8_t locked[TimeLock::HEADER_SIZE + 32];
    size_t lockedLen = TimeLock::lock(key, unlockTs, iterations, salt, locked);

    uint8_t unlockedKey[32];
    // Try to unlock before the timestamp
    int result = TimeLock::unlock(locked, lockedLen, unlockTs - 1, unlockedKey);

    // Should fail with -3 (time not yet reached)
    ASSERT_EQ(result, -3);
}

void testTimeLock_afterUnlockTime() {
    uint8_t key[32] = {0};
    key[0] = 0xDE; key[1] = 0xAD; key[2] = 0xBE; key[3] = 0xEF;

    uint64_t unlockTs = 500000;
    uint64_t iterations = 50;
    uint8_t salt[16] = {0x01};

    uint8_t locked[TimeLock::HEADER_SIZE + 32];
    size_t lockedLen = TimeLock::lock(key, unlockTs, iterations, salt, locked);

    uint8_t unlockedKey[32];
    // Unlock well after the timestamp
    int result = TimeLock::unlock(locked, lockedLen, unlockTs + 99999, unlockedKey);

    ASSERT_EQ(result, 0);
    ASSERT_MEM_EQ(unlockedKey, key, 32);
}

void testTimeLock_tamperedData() {
    uint8_t key[32] = {0x77};
    uint64_t unlockTs = 1000;
    uint64_t iterations = 10;
    uint8_t salt[16] = {0};

    uint8_t locked[TimeLock::HEADER_SIZE + 32];
    size_t lockedLen = TimeLock::lock(key, unlockTs, iterations, salt, locked);

    // Corrupt the magic header
    locked[0] ^= 0xFF;

    uint8_t unlockedKey[32];
    int result = TimeLock::unlock(locked, lockedLen, unlockTs + 1, unlockedKey);

    // Should fail with -2 (bad magic)
    ASSERT_EQ(result, -2);
}

void testTimeLock_estimateIterations() {
    // 1 second should give ~1M iterations
    uint64_t iters = TimeLock::estimateIterations(1.0);
    ASSERT_TRUE(iters > 0);
    ASSERT_TRUE(iters >= 100000);

    // 0 seconds should still give at least 1
    uint64_t iters0 = TimeLock::estimateIterations(0.0);
    ASSERT_TRUE(iters0 >= 1);
}

