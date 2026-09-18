#include "time_lock.h"
#include "sha256.h"
#include <cstring>
#include <cmath>

namespace securevault {

constexpr uint8_t TimeLock::MAGIC[4];

void TimeLock::deriveKey(
    const uint8_t* seed, size_t seedLen,
    uint64_t iterations,
    uint8_t out[32]
) {
    // Start with SHA-256 of the seed
    SHA256::hash(seed, seedLen, out);

    // Iterate: hash the previous digest N times
    for (uint64_t i = 0; i < iterations; ++i) {
        uint8_t tmp[32];
        SHA256::hash(out, 32, tmp);
        std::memcpy(out, tmp, 32);
    }
}

static void writeU64BE(uint8_t* buf, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        buf[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

static uint64_t readU64BE(const uint8_t* buf) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | buf[i];
    }
    return val;
}

size_t TimeLock::lock(
    const uint8_t key[32],
    uint64_t unlockTimestamp,
    uint64_t iterations,
    const uint8_t salt[16],
    uint8_t* out
) {
    uint8_t* p = out;

    // Magic header
    std::memcpy(p, MAGIC, 4);
    p += 4;

    // Version
    *p++ = 0x01;

    // Flags (bit 0 = timestamp lock, bit 1 = PoW lock)
    *p++ = 0x03;

    // Unlock timestamp (big-endian)
    writeU64BE(p, unlockTimestamp);
    p += 8;

    // Iteration count (big-endian)
    writeU64BE(p, iterations);
    p += 8;

    // Salt
    std::memcpy(p, salt, 16);
    p += 16;

    // Reserved
    *p++ = 0x00;
    *p++ = 0x00;

    // --- Now encrypt the key ---
    // Derive a wrapping key from salt + unlock timestamp + iterations
    // This ties the key to the temporal constraints
    uint8_t derivationSeed[32];
    std::memcpy(derivationSeed, salt, 16);
    writeU64BE(derivationSeed + 16, unlockTimestamp);
    writeU64BE(derivationSeed + 24, iterations);

    uint8_t wrapKey[32];
    deriveKey(derivationSeed, 32, iterations, wrapKey);

    // XOR the encryption key with the derived wrapping key
    // (simple but effective — the derived key is computationally expensive to reproduce)
    for (int i = 0; i < 32; ++i) {
        *p++ = key[i] ^ wrapKey[i];
    }

    return HEADER_SIZE + 32;
}

int TimeLock::unlock(
    const uint8_t* lockedData,
    size_t lockedLen,
    uint64_t currentTimestamp,
    uint8_t outKey[32]
) {
    if (lockedLen < HEADER_SIZE + 32) {
        return -1; // Too short
    }

    // Verify magic
    if (std::memcmp(lockedData, MAGIC, 4) != 0) {
        return -2; // Bad magic
    }

    uint8_t version = lockedData[4];
    uint8_t flags   = lockedData[5];
    (void)version;

    uint64_t unlockTs = readU64BE(lockedData + 6);
    uint64_t iters    = readU64BE(lockedData + 14);

    // Check timestamp constraint
    if (flags & 0x01) {
        if (currentTimestamp < unlockTs) {
            return -3; // Time not yet reached
        }
    }

    // Extract salt
    const uint8_t* salt = lockedData + 22;

    // Derive the wrapping key (this is the computationally expensive part)
    uint8_t derivationSeed[32];
    std::memcpy(derivationSeed, salt, 16);
    writeU64BE(derivationSeed + 16, unlockTs);
    writeU64BE(derivationSeed + 24, iters);

    uint8_t wrapKey[32];
    deriveKey(derivationSeed, 32, iters, wrapKey);

    // Decrypt the key
    const uint8_t* encKey = lockedData + HEADER_SIZE;
    for (int i = 0; i < 32; ++i) {
        outKey[i] = encKey[i] ^ wrapKey[i];
    }

    return 0;
}

uint64_t TimeLock::getUnlockTimestamp(const uint8_t* lockedData, size_t lockedLen) {
    if (lockedLen < HEADER_SIZE) return 0;
    return readU64BE(lockedData + 6);
}

uint64_t TimeLock::getIterations(const uint8_t* lockedData, size_t lockedLen) {
    if (lockedLen < HEADER_SIZE) return 0;
    return readU64BE(lockedData + 14);
}

uint64_t TimeLock::estimateIterations(double lockDurationSeconds) {
    // Approximate 1M SHA-256 iterations per second on a modern CPU
    // This is conservative; actual speed depends on hardware
    const double itersPerSecond = 1000000.0;
    uint64_t iters = static_cast<uint64_t>(lockDurationSeconds * itersPerSecond);
    if (iters < 1) iters = 1;
    return iters;
}

} // namespace securevault



