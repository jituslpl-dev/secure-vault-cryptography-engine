/**
 * @file fuzz_main.cpp
 * @brief LibFuzzer harness for fuzz testing the encryption engine.
 *
 * Compile with: clang++ -fsanitize=fuzzer -o securevault_fuzz fuzz_main.cpp \
 *                ../src/*.cpp -I../src -std=c++14
 *
 * Run: ./securevault_fuzz -max_len=4096 -max_total_time=60
 *
 * @license MIT
 */

#include "encryption_engine.h"
#include "sha256.h"
#include <cstdint>
#include <cstddef>
#include <cstring>

using namespace securevault;

/**
 * @brief Fuzz target: feed arbitrary data to decrypt().
 *
 * The fuzzer generates random byte sequences and feeds them to the
 * decryption function. The function must never crash, hang, or exhibit
 * undefined behavior regardless of input.
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Need at least a header to not immediately fail
    if (size < EncryptionEngine::HEADER_SIZE) {
        return 0;
    }

    // Use a fixed key for deterministic fuzzing
    uint8_t key[32] = {0};

    // Allocate output buffer (max possible plaintext size)
    size_t maxOut = size;  // Can't be larger than input
    uint8_t* out = static_cast<uint8_t*>(malloc(maxOut));
    if (!out) return 0;

    size_t outLen = 0;
    int result = EncryptionEngine::decrypt(data, size, key, out, outLen);
    (void)result;  // We don't care about the result, just that it doesn't crash

    free(out);
    return 0;
}

/**
 * @brief Fuzz target: feed arbitrary data to SHA-256.
 *
 * SHA-256 should handle any input without crashing.
 */
extern "C" int LLVMFuzzerTestOneInput_Sha256(const uint8_t* data, size_t size) {
    uint8_t digest[32];
    SHA256::hash(data, size, digest);
    return 0;
}



