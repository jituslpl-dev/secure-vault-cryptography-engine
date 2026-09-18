# Contributing to SecureVault

Thank you for your interest in contributing to SecureVault! This document outlines the process for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Reporting Security Issues](#reporting-security-issues)

---

## Code of Conduct

Be respectful, constructive, and professional. We are committed to fostering an inclusive and welcoming community.

## Getting Started

### Prerequisites

- **C++ Compiler**: GCC 7+, Clang 6+, or MSVC 2019+ (C++14 support required)
- **CMake**: 3.16 or later
- **Node.js**: 18+ (for N-API addon builds)
- **Python**: 3.x (for node-gyp and demo scripts)

### Setup

```bash
# Clone the repository
git clone https://github.com/jituslpl-dev/secure-vault-cryptography-engine.git
cd secure-vault

# Create a build directory
mkdir build && cd build

# Configure with CMake
cmake .. -DSECUREVAULT_BUILD_TESTS=ON -DSECUREVAULT_BUILD_BENCHMARKS=ON

# Build
cmake --build . -j

# Run tests
ctest --output-on-failure
```

### Node.js Addon Setup

```bash
npm install        # Builds the native addon
npm test           # Runs the Node.js test suite
```

## Development Workflow

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes** following the code style guidelines below.

3. **Write tests** for any new functionality. All tests must pass.

4. **Run static analysis** before committing:
   ```bash
   # Format check
   find src -name '*.cpp' -o -name '*.h' | xargs clang-format --dry-run --Werror

   # Static analysis
   cppcheck --enable=warning,style,performance,portability --error-exitcode=1 src/
   ```

5. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add X support for Y"
   ```

6. **Push** and open a pull request.

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Type       | Description                              |
|------------|------------------------------------------|
| `feat`     | A new feature                            |
| `fix`      | A bug fix                               |
| `docs`     | Documentation only changes               |
| `style`    | Code style changes (formatting, etc.)    |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf`     | A code change that improves performance  |
| `test`     | Adding or correcting tests               |
| `chore`    | Build, CI, or tooling changes            |

Example: `feat: add AES-GCM mode support`

## Code Style

### C++ Code

- **Formatting**: Enforced by `.clang-format` (Google-based, 4-space indent, 100-char limit)
- **Static Analysis**: `.clang-tidy` checks for bugprone, cert, modernize, performance, and readability issues
- **C++ Standard**: C++14 (do not use C++17/20 features for portability)
- **Naming Conventions**:
  - Classes: `CamelCase` (e.g., `EncryptionEngine`)
  - Functions/methods: `camelBack` (e.g., `processCTR`)
  - Variables: `camelBack` (e.g., `roundKeys`)
  - Private members: `camelBack_` (trailing underscore)
  - Constants: `UPPER_CASE` or `kCamelCase`
  - Namespace: `lower_case` (e.g., `securevault`)

### JavaScript Code

- Use `'use strict'` in all files
- 2-space indentation
- Single quotes for strings
- Semicolons required

### Doxygen Comments

All public API functions must have Doxygen documentation:

```cpp
/**
 * @brief Encrypts data using AES-256-CTR mode.
 *
 * @param plaintext Pointer to the data to encrypt.
 * @param ptLen Length of the plaintext in bytes.
 * @param key 32-byte AES-256 key.
 * @param iv 16-byte initialization vector.
 * @param out Output buffer (must be at least ptLen + HEADER_SIZE bytes).
 * @param outLen Receives the actual output length.
 * @return 0 on success, negative error code on failure.
 */
static int encrypt(const uint8_t* plaintext, size_t ptLen,
                   const uint8_t key[32], const uint8_t iv[16],
                   uint8_t* out, size_t& outLen);
```

## Testing Requirements

### Unit Tests

Every new function or class must have unit tests in the `tests/` directory:

- `tests/test_sha256.cpp` — SHA-256 tests
- `tests/test_aes256.cpp` — AES-256 tests
- `tests/test_encryption_engine.cpp` — Encryption engine tests
- `tests/test_time_lock.cpp` — Time-lock tests
- `tests/test_streaming.cpp` — Streaming engine tests
- `tests/test_fuzz.cpp` — Fuzz tests for invalid/corrupted inputs

### Test Coverage

- All public API functions must be tested
- Edge cases (empty input, maximum size, null pointers) must be covered
- Error paths must be tested
- Known test vectors (NIST FIPS 180-4 for SHA-256, NIST SP 800-38A for AES-CTR) must be verified

### Running Tests

```bash
# C++ tests
cd build && ctest --output-on-failure

# Node.js tests
npm test

# Sanitizer tests
cmake .. -DSECUREVAULT_ENABLE_ASAN=ON -DSECUREVAULT_BUILD_TESTS=ON
cmake --build . -j && ctest --output-on-failure
```

## Pull Request Process

1. Ensure all tests pass (C++, Node.js, sanitizers)
2. Ensure `clang-format` and `clang-tidy` produce no warnings
3. Update the README.md and API documentation if needed
4. Add a changelog entry in CHANGELOG.md
5. Request review from a maintainer

### PR Checklist

- [ ] Code follows the style guidelines (clang-format passes)
- [ ] Static analysis passes (clang-tidy, cppcheck)
- [ ] Unit tests added/updated for new functionality
- [ ] All tests pass (C++, Node.js)
- [ ] Sanitizer tests pass (ASan, UBSan)
- [ ] Documentation updated (Doxygen comments, README)
- [ ] CHANGELOG.md updated

## Reporting Security Issues

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private security-advisory reporting workflow. See [SECURITY.md](SECURITY.md) for the full security policy.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.


