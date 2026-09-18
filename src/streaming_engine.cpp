#include "streaming_engine.h"
#include <cstring>

namespace securevault {

// ==================== Encryptor ====================

StreamingEngine::Encryptor::Encryptor()
    : totalBytes_(0)
    , chunkSize_(DEFAULT_CHUNK_SIZE)
    , initialized_(false)
{}

void StreamingEngine::Encryptor::init(
    const uint8_t key[32],
    const uint8_t iv[16],
    size_t chunkSize
) {
    aes_.setKey(key);
    aes_.setCounter(iv);
    hash_.reset();
    totalBytes_ = 0;
    chunkSize_ = (chunkSize > 0) ? chunkSize : DEFAULT_CHUNK_SIZE;
    initialized_ = true;
}

void StreamingEngine::Encryptor::processChunk(
    const uint8_t* in, size_t inLen,
    uint8_t* out, size_t& outLen
) {
    if (!initialized_) {
        outLen = 0;
        return;
    }

    // Update rolling hash with plaintext (before encryption)
    hash_.update(in, inLen);

    // Encrypt this chunk — CTR mode continues seamlessly from the current counter
    aes_.processCTR(in, out, inLen);

    totalBytes_ += inLen;
    outLen = inLen;
}

void StreamingEngine::Encryptor::finalize(uint8_t outDigest[32], uint64_t& totalBytes) {
    hash_.finalize(outDigest);
    totalBytes = totalBytes_;
}

// ==================== Decryptor ====================

StreamingEngine::Decryptor::Decryptor()
    : totalBytes_(0)
    , initialized_(false)
    , finalized_(false)
{
    std::memset(computedDigest_, 0, 32);
}

void StreamingEngine::Decryptor::init(const uint8_t key[32], const uint8_t iv[16]) {
    aes_.setKey(key);
    aes_.setCounter(iv);
    hash_.reset();
    totalBytes_ = 0;
    initialized_ = true;
    finalized_ = false;
}

void StreamingEngine::Decryptor::processChunk(
    const uint8_t* in, size_t inLen,
    uint8_t* out, size_t& outLen
) {
    if (!initialized_) {
        outLen = 0;
        return;
    }

    // Decrypt this chunk
    aes_.processCTR(in, out, inLen);

    // Update rolling hash with decrypted plaintext
    hash_.update(out, inLen);

    totalBytes_ += inLen;
    outLen = inLen;
}

void StreamingEngine::Decryptor::finalize(uint8_t outDigest[32], uint64_t& totalBytes) {
    hash_.finalize(computedDigest_);
    std::memcpy(outDigest, computedDigest_, 32);
    totalBytes = totalBytes_;
    finalized_ = true;
}

bool StreamingEngine::Decryptor::verify(const uint8_t expectedDigest[32]) const {
    if (!finalized_) return false;
    return std::memcmp(computedDigest_, expectedDigest, 32) == 0;
}

// ==================== Static convenience methods ====================

void StreamingEngine::encryptBuffer(
    const uint8_t* in, size_t inLen,
    const uint8_t key[32],
    const uint8_t iv[16],
    uint8_t* out, size_t& outLen,
    uint8_t outDigest[32]
) {
    Encryptor enc;
    enc.init(key, iv, DEFAULT_CHUNK_SIZE);

    size_t offset = 0;
    while (offset < inLen) {
        size_t chunkLen = (inLen - offset < DEFAULT_CHUNK_SIZE)
                        ? (inLen - offset)
                        : DEFAULT_CHUNK_SIZE;
        size_t outChunkLen;
        enc.processChunk(in + offset, chunkLen, out + offset, outChunkLen);
        offset += chunkLen;
    }

    uint64_t total;
    enc.finalize(outDigest, total);
    outLen = inLen;
}

bool StreamingEngine::decryptBuffer(
    const uint8_t* in, size_t inLen,
    const uint8_t key[32],
    const uint8_t iv[16],
    uint8_t* out, size_t& outLen,
    const uint8_t expectedDigest[32]
) {
    Decryptor dec;
    dec.init(key, iv);

    size_t offset = 0;
    while (offset < inLen) {
        size_t chunkLen = (inLen - offset < DEFAULT_CHUNK_SIZE)
                        ? (inLen - offset)
                        : DEFAULT_CHUNK_SIZE;
        size_t outChunkLen;
        dec.processChunk(in + offset, chunkLen, out + offset, outChunkLen);
        offset += chunkLen;
    }

    uint8_t digest[32];
    uint64_t total;
    dec.finalize(digest, total);
    outLen = inLen;

    return dec.verify(expectedDigest);
}

} // namespace securevault



