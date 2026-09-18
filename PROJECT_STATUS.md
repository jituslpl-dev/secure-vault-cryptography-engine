# Project status and verification boundary

SecureVault is an educational systems-and-cryptography portfolio project. It
demonstrates implementing SHA-256 and AES-256-CTR in C++, exposing native code
through Node-API, designing a binary container, streaming large inputs, and
testing security-sensitive failure paths.

## Verified in this repository

- The dependency-free Python reference demo compiles and runs end to end.
- Automated Python tests cover SHA-256 known-answer vectors, AES-CTR round
  trips, tamper rejection, stream integrity, password derivation determinism,
  and the timestamp gate used by the time-lock demonstration.
- GitHub Actions repeats the reference tests on every push and pull request.
- The source archive contains the C++ core, Node-API binding, JavaScript API and
  CLI, CMake/node-gyp manifests, C++ tests, and JavaScript integration tests.

## Build boundary

The native addon requires a C++14 compiler, CMake or node-gyp, Node.js headers,
and the `node-addon-api` package. The current verification environment does not
include a native C++ toolchain, so this repository does not claim a successful
native build here. Follow the README build instructions in a suitable toolchain
and treat CI results as authoritative only for the jobs that actually ran.

## Security boundary

This is not production cryptography and must not protect real sensitive data.
In particular:

- The native addon's XOR-shift random generator is not a CSPRNG.
- The custom password derivation is not a standard password KDF.
- AES-CTR is malleable, and the stored plaintext SHA-256 digest is unkeyed; the
  format does not provide authenticated encryption.
- The timestamp is supplied by the caller, so the time gate is not a trusted
  clock. The proof-of-work can also be computed before the target time.
- The implementation has not been independently audited or hardened against
  timing, cache, fault-injection, or memory-disclosure attacks.

For an interview, present this as an exploration of low-level implementation,
testing, API design, and security tradeoffs—not as a replacement for audited
libraries and standard AEAD/KDF constructions.
