#include <napi.h>
#include "sha256.h"
#include "aes256.h"
#include "encryption_engine.h"
#include "time_lock.h"
#include "streaming_engine.h"
#include <cstring>
#include <string>
#include <chrono>

using namespace securevault;

// ============================================================================
// Helper: convert a Node Buffer to raw pointer + length (zero-copy read)
// ============================================================================
static inline const uint8_t* bufData(const Napi::Value& val) {
    return reinterpret_cast<const uint8_t*>(val.As<Napi::Buffer<uint8_t>>().Data());
}

static inline size_t bufLen(const Napi::Value& val) {
    return val.As<Napi::Buffer<uint8_t>>().Length();
}

// ============================================================================
// SHA-256: hash(data) -> Buffer(32)
// ============================================================================
Napi::Value Sha256Hash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected a Buffer argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* data = bufData(info[0]);
    size_t len = bufLen(info[0]);

    uint8_t digest[SHA256::DIGEST_SIZE];
    SHA256::hash(data, len, digest);

    return Napi::Buffer<uint8_t>::Copy(env, digest, SHA256::DIGEST_SIZE);
}

// ============================================================================
// Derive key from password: deriveKey(password, salt, iterations) -> Buffer(32)
// ============================================================================
Napi::Value DeriveKey(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsNumber()) {
        Napi::TypeError::New(env, "Expected (password: Buffer, salt: Buffer(16), iterations: number)").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* password = bufData(info[0]);
    size_t passwordLen = bufLen(info[0]);

    if (bufLen(info[1]) < 16) {
        Napi::TypeError::New(env, "Salt must be 16 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }
    const uint8_t* salt = bufData(info[1]);
    uint64_t iterations = info[2].As<Napi::Number>().Uint32Value();

    uint8_t key[32];
    EncryptionEngine::deriveKeyFromPassword(password, passwordLen, salt, iterations, key);

    return Napi::Buffer<uint8_t>::Copy(env, key, 32);
}

// ============================================================================
// Encrypt: encrypt(plaintext, key(32), iv(16)) -> Buffer
// ============================================================================
Napi::Value Encrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (plaintext: Buffer, key: Buffer(32), iv: Buffer(16))").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* plaintext = bufData(info[0]);
    size_t ptLen = bufLen(info[0]);

    if (bufLen(info[1]) < 32 || bufLen(info[2]) < 16) {
        Napi::TypeError::New(env, "Key must be 32 bytes, IV must be 16 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* key = bufData(info[1]);
    const uint8_t* iv  = bufData(info[2]);

    // Allocate output buffer (plaintext + header overhead)
    size_t outCapacity = ptLen + EncryptionEngine::HEADER_SIZE;
    auto outBuf = Napi::Buffer<uint8_t>::New(env, outCapacity);
    uint8_t* out = outBuf.Data();

    size_t outLen;
    EncryptionEngine::encrypt(plaintext, ptLen, key, iv, out, outLen);

    // outLen == ptLen + HEADER_SIZE == outCapacity, so return the full buffer
    return outBuf;
}

// ============================================================================
// Decrypt: decrypt(ciphertext, key(32)) -> Buffer
// ============================================================================
Napi::Value Decrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (ciphertext: Buffer, key: Buffer(32))").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* ciphertext = bufData(info[0]);
    size_t ctLen = bufLen(info[0]);

    if (bufLen(info[1]) < 32) {
        Napi::TypeError::New(env, "Key must be 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }
    const uint8_t* key = bufData(info[1]);

    if (ctLen < EncryptionEngine::HEADER_SIZE) {
        Napi::Error::New(env, "Ciphertext too short").ThrowAsJavaScriptException();
        return env.Null();
    }

    size_t ptLen = ctLen - EncryptionEngine::HEADER_SIZE;
    auto outBuf = Napi::Buffer<uint8_t>::New(env, ptLen);
    uint8_t* out = outBuf.Data();

    size_t actualLen;
    int result = EncryptionEngine::decrypt(ciphertext, ctLen, key, out, actualLen);

    if (result != 0) {
        std::string errMsg = "Decryption failed (error code: " + std::to_string(result) + ")";
        if (result == -4) {
            errMsg = "Integrity check failed — data may be tampered or wrong key";
        } else if (result == -3) {
            errMsg = "Data is time-locked — use decryptTimeLocked() instead";
        }
        Napi::Error::New(env, errMsg).ThrowAsJavaScriptException();
        return env.Null();
    }

    return outBuf;
}

// ============================================================================
// Encrypt with time-lock: encryptWithTimeLock(plaintext, key(32), iv(16), unlockTimestamp, iterations, salt(16)) -> Buffer
// ============================================================================
Napi::Value EncryptWithTimeLock(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 6 || !info[0].IsBuffer() || !info[1].IsBuffer() ||
        !info[2].IsBuffer() || !info[3].IsNumber() || !info[4].IsNumber() || !info[5].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (plaintext, key(32), iv(16), unlockTimestamp, iterations, salt(16))").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* plaintext = bufData(info[0]);
    size_t ptLen = bufLen(info[0]);

    if (bufLen(info[1]) < 32 || bufLen(info[2]) < 16 || bufLen(info[5]) < 16) {
        Napi::TypeError::New(env, "Key must be 32 bytes, IV must be 16 bytes, salt must be 16 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* key = bufData(info[1]);
    const uint8_t* iv  = bufData(info[2]);
    uint64_t unlockTs  = static_cast<uint64_t>(info[3].As<Napi::Number>().Int64Value());
    uint64_t iterations = static_cast<uint64_t>(info[4].As<Napi::Number>().Int64Value());
    const uint8_t* salt = bufData(info[5]);

    size_t outCapacity = ptLen + EncryptionEngine::HEADER_SIZE + TimeLock::HEADER_SIZE + 32;
    auto outBuf = Napi::Buffer<uint8_t>::New(env, outCapacity);
    uint8_t* out = outBuf.Data();

    size_t outLen;
    EncryptionEngine::encryptWithTimeLock(
        plaintext, ptLen, key, iv, unlockTs, iterations, salt, out, outLen
    );
 + TimeLock::HEADER_SIZE + 32 == outCapacity
    return outBuf;
}

// ============================================================================
// Decrypt time-locked: decryptTimeLocked(ciphertext, currentTimestamp) -> Buffer
// ============================================================================
Napi::Value DecryptTimeLocked(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 2 || !info[0].IsBuffer() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected (ciphertext: Buffer, currentTimestamp: number)").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* ciphertext = bufData(info[0]);
    size_t ctLen = bufLen(info[0]);
    uint64_t currentTs = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());

    if (ctLen < EncryptionEngine::HEADER_SIZE + TimeLock::HEADER_SIZE + 32) {
        Napi::Error::New(env, "Ciphertext too short for time-locked data").ThrowAsJavaScriptException();
        return env.Null();
    }

    size_t ptLen = ctLen - EncryptionEngine::HEADER_SIZE - TimeLock::HEADER_SIZE - 32;
    auto outBuf = Napi::Buffer<uint8_t>::New(env, ptLen);
    uint8_t* out = outBuf.Data();

    size_t actualLen;
    int result = EncryptionEngine::decryptTimeLocked(ciphertext, ctLen, currentTs, out, actualLen);

    if (result != 0) {
        std::string errMsg;
        switch (result) {
            case -3: errMsg = "Time not yet reached â€” cannot decrypt"; break;
            case -4: errMsg = "Integrity check failed â€” data may be tampered"; break;
            default: errMsg = "Decryption failed (error code: " + std::to_string(result) + ")"; break;
        }
        Napi::Error::New(env, errMsg).ThrowAsJavaScriptException();
        return env.Null();
    }

    return outBuf;
}

// ============================================================================
// Is time-locked: isTimeLocked(data) -> boolean
// ============================================================================
Napi::Value IsTimeLocked(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected a Buffer argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Boolean::New(env, EncryptionEngine::isTimeLocked(bufData(info[0]), bufLen(info[0])));
}

// ============================================================================
// Get unlock timestamp: getUnlockTimestamp(data) -> number
// ============================================================================
Napi::Value GetUnlockTimestamp(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Expected a Buffer argument").ThrowAsJavaScriptException();
        return env.Null();
    }

    return Napi::Number::New(env, static_cast<double>(EncryptionEngine::getUnlockTimestamp(bufData(info[0]), bufLen(info[0]))));
}

// ============================================================================
// Estimate iterations: estimateIterations(lockDurationSeconds) -> number
// ============================================================================
Napi::Value EstimateIterations(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number (lock duration in seconds)").ThrowAsJavaScriptException();
        return env.Null();
    }

    double seconds = info[0].As<Napi::Number>().DoubleValue();
    return Napi::Number::New(env, static_cast<double>(TimeLock::estimateIterations(seconds)));
}

// ============================================================================
// Streaming encrypt: streamEncrypt(plaintext, key(32), iv(16)) -> { data: Buffer, digest: Buffer(32) }
// ============================================================================
Napi::Value StreamEncrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 3 || !info[0].IsBuffer() || !info[1].IsBuffer() || !info[2].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (plaintext: Buffer, key: Buffer(32), iv: Buffer(16))").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* plaintext = bufData(info[0]);
    size_t ptLen = bufLen(info[0]);

    if (bufLen(info[1]) < 32 || bufLen(info[2]) < 16) {
        Napi::TypeError::New(env, "Key must be 32 bytes, IV must be 16 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* key = bufData(info[1]);
    const uint8_t* iv  = bufData(info[2]);

    auto outBuf = Napi::Buffer<uint8_t>::New(env, ptLen);
    uint8_t* out = outBuf.Data();

    size_t outLen;
    uint8_t digest[32];
    StreamingEngine::encryptBuffer(plaintext, ptLen, key, iv, out, outLen, digest);

    Napi::Object result = Napi::Object::New(env);
    result.Set("data", outBuf);
    result.Set("digest", Napi::Buffer<uint8_t>::Copy(env, digest, 32));
    return result;
}

// ============================================================================
// Streaming decrypt: streamDecrypt(ciphertext, key(32), iv(16), expectedDigest(32)) -> { data: Buffer, verified: boolean }
// ============================================================================
Napi::Value StreamDecrypt(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 4 || !info[0].IsBuffer() || !info[1].IsBuffer() ||
        !info[2].IsBuffer() || !info[3].IsBuffer()) {
        Napi::TypeError::New(env, "Expected (ciphertext, key(32), iv(16), expectedDigest(32))").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* ciphertext = bufData(info[0]);
    size_t ctLen = bufLen(info[0]);

    if (bufLen(info[1]) < 32 || bufLen(info[2]) < 16 || bufLen(info[3]) < 32) {
        Napi::TypeError::New(env, "Key must be 32, IV must be 16, digest must be 32 bytes").ThrowAsJavaScriptException();
        return env.Null();
    }

    const uint8_t* key = bufData(info[1]);
    const uint8_t* iv  = bufData(info[2]);
    const uint8_t* expectedDigest = bufData(info[3]);

    auto outBuf = Napi::Buffer<uint8_t>::New(env, ctLen);
    uint8_t* out = outBuf.Data();

    size_t outLen;
    bool verified = StreamingEngine::decryptBuffer(ciphertext, ctLen, key, iv, out, outLen, expectedDigest);

    Napi::Object result = Napi::Object::New(env);
    result.Set("data", outBuf);
    result.Set("verified", Napi::Boolean::New(env, verified));
    return result;
}

// ============================================================================
// Generate random bytes: randomBytes(length) -> Buffer
// Uses a simple XOR-shift PRNG seeded from high-resolution clock.
// (For production, replace with a CSPRNG â€” this is a dependency-free fallback.)
// ============================================================================
Napi::Value RandomBytes(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected a number (length)").ThrowAsJavaScriptException();
        return env.Null();
    }

    size_t length = info[0].As<Napi::Number>().Uint32Value();
    auto outBuf = Napi::Buffer<uint8_t>::New(env, length);
    uint8_t* out = outBuf.Data();

    // Seed from high-resolution clock
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
    uint64_t seed = static_cast<uint64_t>(std::chrono::nanoseconds(now).count());

    // XOR-shift128 PRNG
    uint64_t s = seed;
    for (size_t i = 0; i < length; ++i) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        out[i] = static_cast<uint8_t>(s & 0xFF);
    }

    return outBuf;
}

// ============================================================================
// Module initialization
// ============================================================================
Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
    exports.Set(Napi::String::New(env, "sha256"), Napi::Function::New(env, Sha256Hash));
    exports.Set(Napi::String::New(env, "deriveKey"), Napi::Function::New(env, DeriveKey));
    exports.Set(Napi::String::New(env, "encrypt"), Napi::Function::New(env, Encrypt));
    exports.Set(Napi::String::New(env, "decrypt"), Napi::Function::New(env, Decrypt));
    exports.Set(Napi::String::New(env, "encryptWithTimeLock"), Napi::Function::New(env, EncryptWithTimeLock));
    exports.Set(Napi::String::New(env, "decryptTimeLocked"), Napi::Function::New(env, DecryptTimeLocked));
    exports.Set(Napi::String::New(env, "isTimeLocked"), Napi::Function::New(env, IsTimeLocked));
    exports.Set(Napi::String::New(env, "getUnlockTimestamp"), Napi::Function::New(env, GetUnlockTimestamp));
    exports.Set(Napi::String::New(env, "estimateIterations"), Napi::Function::New(env, EstimateIterations));
    exports.Set(Napi::String::New(env, "streamEncrypt"), Napi::Function::New(env, StreamEncrypt));
    exports.Set(Napi::String::New(env, "streamDecrypt"), Napi::Function::New(env, StreamDecrypt));
    exports.Set(Napi::String::New(env, "randomBytes"), Napi::Function::New(env, RandomBytes));
    return exports;
}

NODE_API_MODULE(secure_vault, InitAll)


