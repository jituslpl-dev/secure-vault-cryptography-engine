#include "encryption_engine.h"
#include <cstring>

namespace securevault {

constexpr uint8_t EncryptionEngine::MAGIC[5];
constexpr uint8_t EncryptionEngine::VERSION;

void EncryptionEngine::deriveKeyFromPassword(
    const uint8_t* password, size_t passwordLen,
    const uint8_t salt[16],
    uint64_t iterations,
    uint8_t out[32]
) {
    // PBKDF2-like derivation using our custom SHA-256
    // First pass: SHA-256(password || salt)
    SHA256 ctx;
    ctx.update(password, passwordLen);
    ctx.update(salt, 16);
    ctx.finalize(out);

    // Iterative strengthening
    for (uint64_t i = 0; i < iterations; ++i) {
        uint8_t tmp[32];
        SHA256::hash(out, 32, tmp);
        std::memcpy(out, tmp, 32);
    }
}

void EncryptionEngine::encrypt(
    const uint8_t* plaintext, size_t plaintextLen,
    const uint8_t key[32],
    const uint8_t iv[16],
    uint8_t* out, size_t& outLen
) {
    uint8_t* p = out;

    // Magic
    std::memcpy(p, MAGIC, 5);
    p += 5;

    // Version
    *p++ = VERSION;

    // Flags (no time-lock)
    *p++ = 0x00;

    // IV
    std::memcpy(p, iv, 16);
    p += 16;

    // SHA-256 of plaintext (integrity digest)
    uint8_t digest[32];
    SHA256::hash(plaintext, plaintextLen, digest);
    std::memcpy(p, digest, 32);
    p += 32;

    // Encrypt the plaintext using AES-256-CTR
    AES256 aes;
    aes.setKey(key);
    aes.setCounter(iv);
    aes.processCTR(plaintext, p, plaintextLen);
    p += plaintextLen;

    outLen = static_cast<size_t>(p - out);
}

void EncryptionEngine::encryptWithTimeLock(
    const uint8_t* plaintext, size_t plaintextLen,
    const uint8_t key[32],
    const uint8_t iv[16],
    uint64_t unlockTimestamp,
    uint64_t iterations,
    const uint8_t salt[16],
    uint8_t* out, size_t& outLen
) {
    uint8_t* p = out;

    // Magic
    std::memcpy(p, MAGIC, 5);
    p += 5;

    // Version
    *p++ = VERSION;

    // Flags (time-locked)
    *p++ = FLAG_TIME_LOCKED;

    // IV
    std::memcpy(p, iv, 16);
    p += 16;

    // SHA-256 of plaintext (integrity digest)
    uint8_t digest[32];
    SHA256::hash(plaintext, plaintextLen, digest);
    std::memcpy(p, digest, 32);
    p += 32;

    // Time-lock header + locked key (72 bytes)
    size_t tlLen = TimeLock::lock(key, unlockTimestamp, iterations, salt, p);
    p += tlLen;

    // Encrypt the plaintext using AES-256-CTR
    AES256 aes;
    aes.setKey(key);
    aes.setCounter(iv);
    aes.processCTR(plaintext, p, plaintextLen);
    p += plaintextLen;

    outLen = static_cast<size_t>(p - out);
}

int EncryptionEngine::decrypt(
    const uint8_t* ciphertext, size_t ciphertextLen,
    const uint8_t key[32],
    uint8_t* out, size_t& outLen
) {
    if (ciphertextLen < HEADER_SIZE) {
        return -1; // Too short
    }

    // Verify magic
    if (std::memcmp(ciphertext, MAGIC, 5) != 0) {
        return -2; // Bad magic
    }

    uint8_t version = ciphertext[5];
    uint8_t flags   = ciphertext[6];
    (void)version;

    if (flags & FLAG_TIME_LOCKED) {
        return -3; // Use decryptTimeLocked() for time-locked data
    }

    const uint8_t* iv      = ciphertext + 7;
    const uint8_t* digest  = ciphertext + 7 + 16;
    const uint8_t* encData  = ciphertext + HEADER_SIZE;
    size_t encDataLen       = ciphertextLen - HEADER_SIZE;

    // Decrypt
    AES256 aes;
    aes.setKey(key);
    aes.setCounter(iv);
    aes.processCTR(encData, out, encDataLen);
    outLen = encDataLen;

    // Verify integrity
    uint8_t computedDigest[32];
    SHA256::hash(out, outLen, computedDigest);

    if (std::memcmp(computedDigest, digest, 32) != 0) {
        return -4; // Integrity check failed — data may be tampered
    }

    return 0;
}

int EncryptionEngine::decryptTimeLocked(
    const uint8_t* ciphertext, size_t ciphertextLen,
    uint64_t currentTimestamp,
    uint8_t* out, size_t& outLen
) {
    if (ciphertextLen < HEADER_SIZE) {
        return -1; // Too short
    }

    // Verify magic
    if (std::memcmp(ciphertext, MAGIC, 5) != 0) {
        return -2; // Bad magic
    }

    uint8_t version = ciphertext[5];
    uint8_t flags   = ciphertext[6];
    (void)version;

    if (!(flags & FLAG_TIME_LOCKED)) {
        return -3; // Not time-locked — use decrypt() with a key
    }

    const uint8_t* iv      = ciphertext + 7;
    const uint8_t* digest  = ciphertext + 7 + 16;
    const uint8_t* tlData  = ciphertext + HEADER_SIZE;

    // Unlock the key (this performs the proof-of-work)
    uint8_t key[32];
    int unlockResult = TimeLock::unlock(tlData, TimeLock::HEADER_SIZE + 32, currentTimestamp, key);
    if (unlockResult != 0) {
        return unlockResult; // Time not reached or bad data
    }

    const uint8_t* encData  = tlData + TimeLock::HEADER_SIZE + 32;
    size_t encDataLen       = ciphertextLen - HEADER_SIZE - TimeLock::HEADER_SIZE - 32;

    // Decrypt
    AES256 aes;
    aes.setKey(key);
    aes.setCounter(iv);
    aes.processCTR(encData, out, encDataLen);
    outLen = encDataLen;

    // Verify integrity
    uint8_t computedDigest[32];
    SHA256::hash(out, outLen, computedDigest);

    if (std::memcmp(computedDigest, digest, 32) != 0) {
        return -4; // Integrity check failed
    }

    return 0;
}

bool EncryptionEngine::isTimeLocked(const uint8_t* data, size_t len) {
    if (len < HEADER_SIZE) return false;
    if (std::memcmp(data, MAGIC, 5) != 0) return false;
    return (data[6] & FLAG_TIME_LOCKED) != 0;
}

uint64_t EncryptionEngine::getUnlockTimestamp(const uint8_t* data, size_t len) {
    if (!isTimeLocked(data, len)) return 0;
    const uint8_t* tlData = data + HEADER_SIZE;
    return TimeLock::getUnlockTimestamp(tlData, len - HEADER_SIZE);
}

} // namespace securevault



