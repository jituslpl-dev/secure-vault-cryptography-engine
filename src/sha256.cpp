#include "sha256.h"

namespace securevault {

// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() {
    reset();
}

void SHA256::reset() {
    // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    state_[0] = 0x6a09e667;
    state_[1] = 0xbb67ae85;
    state_[2] = 0x3c6ef372;
    state_[3] = 0xa54ff53a;
    state_[4] = 0x510e527f;
    state_[5] = 0x9b05688c;
    state_[6] = 0x1f83d9ab;
    state_[7] = 0x5be0cd19;

    bitCount_  = 0;
    bufferLen_ = 0;
}

void SHA256::processBlock(const uint8_t* block) {
    uint32_t w[64];

    // First 16 words: big-endian load from block
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4])     << 24) |
               (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(block[i * 4 + 2]) <<  8) |
               (static_cast<uint32_t>(block[i * 4 + 3]));
    }

    // Extend the first 16 words into the remaining 48 words
    for (int i = 16; i < 64; ++i) {
        w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
    }

    // Initialize working variables from current hash state
    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    // 64 rounds of compression
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Add the compressed chunk to the current hash value
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void SHA256::update(const uint8_t* data, size_t len) {
    bitCount_ += static_cast<uint64_t>(len) * 8;

    // Fill remaining buffer first
    if (bufferLen_ > 0) {
        size_t needed = BLOCK_SIZE - bufferLen_;
        size_t copy = (len < needed) ? len : needed;
        std::memcpy(buffer_ + bufferLen_, data, copy);
        bufferLen_ += copy;
        data += copy;
        len  -= copy;

        if (bufferLen_ == BLOCK_SIZE) {
            processBlock(buffer_);
            bufferLen_ = 0;
        }
    }

    // Process full blocks directly from input (zero-copy when aligned)
    while (len >= BLOCK_SIZE) {
        processBlock(data);
        data += BLOCK_SIZE;
        len  -= BLOCK_SIZE;
    }

    // Buffer remaining bytes
    if (len > 0) {
        std::memcpy(buffer_, data, len);
        bufferLen_ = len;
    }
}

void SHA256::finalize(uint8_t out[DIGEST_SIZE]) {
    // Append the '1' bit
    buffer_[bufferLen_++] = 0x80;

    // If not enough room for 8-byte length, pad and process
    if (bufferLen_ > BLOCK_SIZE - 8) {
        while (bufferLen_ < BLOCK_SIZE) {
            buffer_[bufferLen_++] = 0x00;
        }
        processBlock(buffer_);
        bufferLen_ = 0;
    }

    // Pad with zeros up to the length field
    while (bufferLen_ < BLOCK_SIZE - 8) {
        buffer_[bufferLen_++] = 0x00;
    }

    // Append 64-bit big-endian bit count
    for (int i = 7; i >= 0; --i) {
        buffer_[bufferLen_++] = static_cast<uint8_t>((bitCount_ >> (i * 8)) & 0xFF);
    }

    processBlock(buffer_);

    // Write the final hash in big-endian
    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<uint8_t>((state_[i] >>  8) & 0xFF);
        out[i * 4 + 3] = static_cast<uint8_t>( state_[i]        & 0xFF);
    }
}

void SHA256::hash(const uint8_t* data, size_t len, uint8_t out[DIGEST_SIZE]) {
    SHA256 ctx;
    ctx.update(data, len);
    ctx.finalize(out);
}

} // namespace securevault



