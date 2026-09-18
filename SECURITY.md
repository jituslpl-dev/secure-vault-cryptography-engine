# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in SecureVault, please report it responsibly:

1. Open the repository's **Security** tab and choose **Report a vulnerability**.
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Step                        | Target Time  |
|-----------------------------|--------------|
| Acknowledge receipt          | 48 hours     |
| Initial assessment           | 5 days       |
| Fix or mitigation            | 30 days      |
| Public disclosure            | 90 days      |

## Security Architecture

### Cryptographic Primitives

| Component  | Algorithm       | Standard Reference     |
|------------|-----------------|------------------------|
| Hashing    | SHA-256         | NIST FIPS 180-4        |
| Encryption | AES-256-CTR     | NIST SP 800-38A        |
| Key Derivation | PBKDF2-like (iterated SHA-256) | Custom (see notes) |
| Time-Locking | Proof-of-Work (iterated SHA-256) | Custom |

### Security Properties

- **Confidentiality**: AES-256-CTR provides strong confidentiality for data at rest
- **Integrity check**: An embedded SHA-256 digest detects accidental changes, but is unkeyed and is not cryptographic authentication
- **Wrong-key signal**: Most wrong keys fail the digest check; this is not a substitute for an AEAD authentication tag
- **Time-lock demonstration**: Proof-of-work key wrapping is combined with a caller-provided timestamp check; it does not provide a trusted or externally enforced release time

### Known Limitations

1. **Random Number Generation**: The current `randomBytes()` implementation uses an XOR-shift PRNG seeded from the high-resolution clock. **This is NOT cryptographically secure.** For production use, replace with a CSPRNG (e.g., `/dev/urandom` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on macOS).

2. **Key Derivation**: The PBKDF2-like key derivation uses iterated SHA-256 without HMAC construction. While computationally expensive, it is not a standard KDF. Consider migrating to Argon2id or PBKDF2-HMAC-SHA256 for production use.

3. **AES-CTR Mode**: CTR mode does not provide authentication. The integrity check (SHA-256 digest) is computed over the plaintext, not as an authenticated encryption mode. Consider AES-GCM for authenticated encryption.

4. **Side-Channel Resistance**: The implementation has not been hardened against timing or cache-based side-channel attacks. Do not use in environments where side-channel attacks are a concern.

5. **Key Management**: Keys are handled in memory as raw byte arrays. There is no secure key zeroization after use. Consider using `mlock` and `memset_explicit` for sensitive key material.

### Security Recommendations

- Always use a cryptographically secure random number generator for IVs and keys
- Use unique IVs for every encryption operation (never reuse an IV with the same key)
- Store keys in a secure key store (e.g., OS keychain, HSM)
- Use time-locking for time-sensitive data, not as a primary security mechanism
- Verify integrity checks on every decryption operation
- Zeroize key material after use

## Security Hardening Roadmap

- [ ] Replace XOR-shift PRNG with OS CSPRNG
- [ ] Add AES-GCM authenticated encryption mode
- [ ] Implement Argon2id key derivation
- [ ] Add constant-time comparison for integrity checks
- [ ] Add secure memory zeroization (`explicit_bzero`)
- [ ] Add key rotation support
- [ ] Formal security audit


