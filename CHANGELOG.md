# Changelog

All notable changes to SecureVault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CMake build system with sanitizer support (ASan, UBSan)
- C++ unit test suite (SHA-256, AES-256, encryption engine, time-lock, streaming, fuzz)
- C++ integration tests
- C++ benchmark suite (throughput, latency, memory)
- GitHub Actions CI for Linux, Windows, and macOS
- GitHub Actions release workflow with pre-compiled binaries
- clang-format, clang-tidy, and cppcheck configuration
- Doxygen API documentation configuration
- CONTRIBUTING.md, SECURITY.md
- Python reference implementation for cross-language verification
- pkg-config support for system-wide installation

### Changed
- Upgraded C++ standard from C++17 to C++14 for broader compiler compatibility
- Removed unused `xtime()` function from AES-256
- Removed unused includes across multiple files
- Fixed N-API buffer handling in encrypt functions
- Added `node-addon-api` and `node-gyp` as explicit dependencies

### Fixed
- Missing `#include <string>` in addon.cpp
- Missing npm dependencies (node-addon-api, node-gyp)
- C++17 constexpr redefinition issue with out-of-class definitions
- Incorrect N-API Buffer subarray view in Encrypt/EncryptWithTimeLock

## [1.0.0] - 2025-07-17

### Added
- Custom SHA-256 implementation (bitwise operations, 64 rounds, NIST FIPS 180-4 verified)
- AES-256-CTR encryption (full Rijndael, 14-round key expansion, S-Box, MixColumns)
- Tamper-evident integrity verification via embedded SHA-256 digest
- Algorithmic time-locking with proof-of-work key wrapping
- Chunk-based streaming engine (64KB chunks with rolling hash)
- N-API bindings (12 exported functions with zero-copy buffer handling)
- High-level JavaScript API (encrypt, decrypt, time-lock, streaming, password-based)
- Node.js test suite (23 tests)
- Interactive demonstration script
- MIT License



