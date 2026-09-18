# SecureVault interview guide

## Thirty-second summary

SecureVault is an educational C++14 cryptography engine exposed to Node.js via
Node-API. It implements SHA-256 and AES-256-CTR from first principles, defines a
versioned encrypted-container format, supports chunked processing, and includes
native, JavaScript, and dependency-free Python test surfaces. The project is
valuable as a systems exercise; it intentionally documents why custom crypto
should not be deployed for real secrets.

## Architecture to explain

1. `lib/index.js` and `bin/cli.js` provide the JavaScript API and CLI.
2. `src/addon.cpp` validates JavaScript values and passes buffer views to C++.
3. `EncryptionEngine` owns the container layout and encryption pipeline.
4. `AES256` and `SHA256` implement the primitives without OpenSSL.
5. `StreamingEngine` processes bounded chunks while maintaining a digest.
6. `TimeLock` demonstrates iterative work and a timestamp gate.

## Strong discussion points

- Why CTR encryption and decryption use the same XOR operation.
- How the AES-256 key schedule expands 32 bytes into 15 round keys.
- Why SHA-256 padding includes the original message length.
- How a versioned binary header supports parsing and future migration.
- Why chunking bounds working memory for large inputs.
- Where native bindings need careful length, type, and ownership checks.
- Why known-answer vectors test correctness but do not constitute security
  certification.

## Security critique to volunteer

A strong interview answer should identify the limitations before being asked:

- XOR-shift output must never generate production keys or IVs.
- Iterated SHA-256 is not a replacement for Argon2id, scrypt, or a standard
  PBKDF2 construction.
- CTR mode needs a unique nonce and an authentication mechanism. An unkeyed
  plaintext digest is not an authentication tag; production designs should use
  a standard AEAD such as AES-GCM or ChaCha20-Poly1305.
- A caller-provided timestamp is easy to spoof, and the proof-of-work can be
  computed early, so this is not a cryptographically enforced release time.
- Table-based AES may leak information through timing or cache behavior.
- Sensitive key buffers are not locked or reliably zeroized.

## Sensible production redesign

Use a maintained cryptographic library, an OS CSPRNG, a versioned envelope with
algorithm identifiers, Argon2id or a standard password KDF, AEAD with associated
header data, strict nonce management, constant-time verification, key
zeroization where practical, and independent review. Preserve compatibility by
adding a new format version rather than silently changing version 1 semantics.

## Demo commands

```bash
python test/demo_python.py
python -m unittest discover -s tests -p "test_demo_python.py" -v
```

The Python surface is a portable behavioral reference. Native performance
claims should only be made after building and preserving benchmark output from
the machine and compiler configuration being discussed.
