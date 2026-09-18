#include "aes256.h"
#include <cstring>

namespace securevault {

// Rijndael S-Box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round constants for key expansion
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

AES256::AES256() {
    std::memset(roundKeys_, 0, sizeof(roundKeys_));
    std::memset(counter_, 0, BLOCK_SIZE);
}

uint8_t AES256::gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void AES256::subBytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];
}

void AES256::shiftRows(uint8_t state[16]) {
    // State is column-major: state[col*4 + row]
    // Row 0: no shift
    // Row 1: shift left 1
    uint8_t tmp;

    // Row 1
    tmp = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = tmp;

    // Row 2: shift left 2
    tmp = state[2];
    state[2]  = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6]  = state[14];
    state[14] = tmp;

    // Row 3: shift left 3 (= shift right 1)
    tmp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = tmp;
}

void AES256::mixColumns(uint8_t state[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = state + c * 4;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        col[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        col[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        col[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

void AES256::addRoundKey(uint8_t state[16], const uint8_t* roundKey) {
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKey[i];
}

void AES256::keyExpansion(const uint8_t key[KEY_SIZE]) {
    // Nk = 8 (256-bit key), Nb = 4, Nr = 14
    // Total 32-bit words: Nb * (Nr + 1) = 4 * 15 = 60 words = 240 bytes
    const int Nk = 8;
    const int Nr = 14;
    const int totalWords = 4 * (Nr + 1); // 60

    uint8_t* rk = roundKeys_;

    // First Nk words = the key itself
    std::memcpy(rk, key, KEY_SIZE);

    for (int i = Nk; i < totalWords; ++i) {
        uint8_t temp[4];
        temp[0] = rk[(i - 1) * 4];
        temp[1] = rk[(i - 1) * 4 + 1];
        temp[2] = rk[(i - 1) * 4 + 2];
        temp[3] = rk[(i - 1) * 4 + 3];

        if (i % Nk == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
            // Rcon
            temp[0] ^= rcon[i / Nk];
        } else if (i % Nk == 4) {
            // SubWord only
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];
        }

        rk[i * 4]     = rk[(i - Nk) * 4]     ^ temp[0];
        rk[i * 4 + 1] = rk[(i - Nk) * 4 + 1] ^ temp[1];
        rk[i * 4 + 2] = rk[(i - Nk) * 4 + 2] ^ temp[2];
        rk[i * 4 + 3] = rk[(i - Nk) * 4 + 3] ^ temp[3];
    }
}

void AES256::encryptBlock(const uint8_t in[BLOCK_SIZE], uint8_t out[BLOCK_SIZE]) {
    uint8_t state[16];
    std::memcpy(state, in, 16);

    // Initial round key addition
    addRoundKey(state, roundKeys_);

    // Rounds 1..13
    for (int round = 1; round < ROUNDS; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys_ + round * 16);
    }

    // Final round (no MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys_ + ROUNDS * 16);

    std::memcpy(out, state, 16);
}

void AES256::setKey(const uint8_t key[KEY_SIZE]) {
    keyExpansion(key);
}

void AES256::setCounter(const uint8_t counter[BLOCK_SIZE]) {
    std::memcpy(counter_, counter, BLOCK_SIZE);
}

void AES256::getCounter(uint8_t counter[BLOCK_SIZE]) const {
    std::memcpy(counter, counter_, BLOCK_SIZE);
}

void AES256::incrementCounter() {
    // Big-endian increment — carry from byte 15 upward
    for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
        if (++counter_[i] != 0)
            break;
    }
}

void AES256::processCTR(const uint8_t* in, uint8_t* out, size_t len) {
    uint8_t keystream[16];
    size_t offset = 0;

    while (offset < len) {
        // Generate keystream block
        encryptBlock(counter_, keystream);

        // XOR plaintext with keystream
        size_t blockLen = (len - offset < 16) ? (len - offset) : 16;
        for (size_t i = 0; i < blockLen; ++i) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        incrementCounter();
        offset += blockLen;
    }
}

} // namespace securevault



