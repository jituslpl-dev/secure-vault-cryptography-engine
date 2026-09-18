/**
 * @file benchmark.cpp
 * @brief Performance benchmarks for SecureVault.
 *
 * Measures throughput (MB/s), latency (μs/op), and memory usage
 * for SHA-256, AES-256-CTR, encryption engine, and streaming engine.
 *
 * @license MIT
 */

#include "sha256.h"
#include "aes256.h"
#include "encryption_engine.h"
#include "streaming_engine.h"
#include "time_lock.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace securevault;
using Clock = std::chrono::high_resolution_clock;

// ─── Helpers ─────────────────────────────────────────────────────

static double elapsedMs(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

static void printHeader(const char* title) {
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ %-52s│\n", title);
    printf("├──────────────────┬───────────┬───────────┬───────────┤\n");
    printf("│ %-16s │ %9s │ %9s │ %9s │\n", "Operation", "Time(ms)", "Throughput", "Latency");
    printf("│                  │           │  (MB/s)   │  (μs/op)  │\n");
    printf("├──────────────────┼───────────┼───────────┼───────────┤\n");
}

static void printRow(const char* op, double ms, size_t bytes, int ops) {
    double mbps = (bytes / (1024.0 * 1024.0)) / (ms / 1000.0);
    double latencyUs = (ms * 1000.0) / ops;
    printf("│ %-16s │ %9.2f │ %9.2f │ %9.2f │\n", op, ms, mbps, latencyUs);
}

static void printFooter() {
    printf("└──────────────────┴───────────┴───────────┴───────────┘\n");
}

// ─── Benchmarks ───────────────────────────────────────────────────

static void benchSha256() {
    printHeader("SHA-256 Benchmark");

    // 1MB block
    const size_t size = 1024 * 1024;
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    for (size_t i = 0; i < size; i++) data[i] = static_cast<uint8_t>(i & 0xFF);

    uint8_t digest[32];

    // Warmup
    SHA256::hash(data, size, digest);

    // Benchmark: 1MB hash
    auto t0 = Clock::now();
    SHA256::hash(data, size, digest);
    auto t1 = Clock::now();
    printRow("SHA-256 (1MB)", elapsedMs(t0, t1), size, 1);

    // Benchmark: 100 × 1KB
    const int ops = 100;
    const size_t smallSize = 1024;
    t0 = Clock::now();
    for (int i = 0; i < ops; i++) {
        SHA256::hash(data, smallSize, digest);
    }
    t1 = Clock::now();
    printRow("SHA-256 (100×1KB)", elapsedMs(t0, t1), smallSize * ops, ops);

    printFooter();
    free(data);
}

static void benchAes256() {
    printHeader("AES-256-CTR Benchmark");

    const size_t size = 1024 * 1024;
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    uint8_t* out = static_cast<uint8_t*>(malloc(size));
    for (size_t i = 0; i < size; i++) data[i] = static_cast<uint8_t>(i & 0xFF);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    for (int i = 0; i < 32; i++) key[i] = static_cast<uint8_t>(i);

    AES256 aes;
    aes.setKey(key);

    // Warmup
    aes.setCounter(iv);
    aes.processCTR(data, out, size);

    // 1MB encrypt
    aes.setCounter(iv);
    auto t0 = Clock::now();
    aes.processCTR(data, out, size);
    auto t1 = Clock::now();
    printRow("AES-256 (1MB)", elapsedMs(t0, t1), size, 1);

    // 100 × 1KB
    const int ops = 100;
    const size_t smallSize = 1024;
    t0 = Clock::now();
    for (int i = 0; i < ops; i++) {
        aes.setCounter(iv);
        aes.processCTR(data, out, smallSize);
    }
    t1 = Clock::now();
    printRow("AES-256 (100×1KB)", elapsedMs(t0, t1), smallSize * ops, ops);

    printFooter();
    free(data);
    free(out);
}

static void benchEncryptionEngine() {
    printHeader("Encryption Engine Benchmark");

    const size_t size = 1024 * 1024;
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    uint8_t* enc = static_cast<uint8_t*>(malloc(size + EncryptionEngine::HEADER_SIZE));
    uint8_t* dec = static_cast<uint8_t*>(malloc(size));
    for (size_t i = 0; i < size; i++) data[i] = static_cast<uint8_t>(i & 0xFF);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};

    size_t encLen = 0, decLen = 0;

    // Encrypt
    auto t0 = Clock::now();
    EncryptionEngine::encrypt(data, size, key, iv, enc, encLen);
    auto t1 = Clock::now();
    printRow("Encrypt (1MB)", elapsedMs(t0, t1), size, 1);

    // Decrypt
    t0 = Clock::now();
    EncryptionEngine::decrypt(enc, encLen, key, dec, decLen);
    t1 = Clock::now();
    printRow("Decrypt (1MB)", elapsedMs(t0, t1), size, 1);

    printFooter();
    free(data);
    free(enc);
    free(dec);
}

static void benchStreaming() {
    printHeader("Streaming Engine Benchmark");

    const size_t size = 1024 * 1024;
    uint8_t* data = static_cast<uint8_t*>(malloc(size));
    uint8_t* enc = static_cast<uint8_t*>(malloc(size));
    uint8_t* dec = static_cast<uint8_t*>(malloc(size));
    for (size_t i = 0; i < size; i++) data[i] = static_cast<uint8_t>(i & 0xFF);

    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    uint8_t digest[32];
    size_t encLen = 0, decLen = 0;

    // Encrypt
    auto t0 = Clock::now();
    StreamingEngine::encryptBuffer(data, size, key, iv, enc, encLen, digest);
    auto t1 = Clock::now();
    printRow("Stream Enc (1MB)", elapsedMs(t0, t1), size, 1);

    // Decrypt
    bool verified = false;
    t0 = Clock::now();
    StreamingEngine::decryptBuffer(enc, encLen, key, iv, dec, decLen, digest, &verified);
    t1 = Clock::now();
    printRow("Stream Dec (1MB)", elapsedMs(t0, t1), size, 1);

    printFooter();
    free(data);
    free(enc);
    free(dec);
}

static void benchTimeLock() {
    printf("\n┌─────────────────────────────────────────────────────┐\n");
    printf("│ %-52s│\n", "Time-Lock Benchmark (PoW iterations)");
    printf("├──────────────────┬───────────┬───────────────────────┤\n");
    printf("│ %-16s │ %9s │ %21s │\n", "Iterations", "Time(ms)", "Keys/sec");
    printf("├──────────────────┼───────────┼───────────────────────┤\n");

    uint8_t key[32] = {0};
    uint8_t salt[16] = {0};

    for (uint64_t iters : {100u, 1000u, 10000u, 100000u}) {
        uint8_t locked[TimeLock::HEADER_SIZE + 32];
        size_t lockedLen = TimeLock::lock(key, 1000000, iters, salt, locked);

        uint8_t unlockedKey[32];
        auto t0 = Clock::now();
        TimeLock::unlock(locked, lockedLen, 1000001, unlockedKey);
        auto t1 = Clock::now();

        double ms = elapsedMs(t0, t1);
        double keysPerSec = 1000.0 / ms;
        printf("│ %-16llu │ %9.2f │ %19.0f │\n",
               (unsigned long long)iters, ms, keysPerSec);
    }
    printf("└──────────────────┴───────────┴───────────────────────┘\n");
}

// ─── Main ────────────────────────────────────────────────────────

int main() {
    printf("\n");
    printf("╔═════════════════════════════════════════════════════╗\n");
    printf("║   SecureVault — Performance Benchmarks              ║\n");
    printf("╚═════════════════════════════════════════════════════╝\n");

    benchSha256();
    benchAes256();
    benchEncryptionEngine();
    benchStreaming();
    benchTimeLock();

    printf("\n  Note: Results depend on CPU, compiler, and optimization level.\n");
    printf("  Built with C++14, -O3 optimization.\n\n");

    return 0;
}



