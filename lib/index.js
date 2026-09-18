'use strict';

// Load the native addon
let binding;
try {
  binding = require('../build/Release/secure_vault.node');
} catch (e) {
  try {
    binding = require('../build/Debug/secure_vault.node');
  } catch (e2) {
    throw new Error(
      'Native module not found. Run "npm install" or "npm run rebuild" to compile the C++ addon.\n' +
      e2.message
    );
  }
}

/**
 * SecureVault — High-level JavaScript API for the C++ encryption engine.
 *
 * Features:
 *   - Custom SHA-256 (dependency-free, bitwise C++ implementation)
 *   - AES-256-CTR encryption with zero-copy buffer handling
 *   - Tamper-evident integrity verification via embedded SHA-256 digest
 *   - Algorithmic time-locking with proof-of-work key unwrapping
 *   - Chunk-based streaming for large datasets
 *   - N-API bindings for minimal JS↔C++ overhead
 */

/**
 * Compute SHA-256 hash of data.
 * @param {Buffer} data - Input data to hash.
 * @returns {Buffer} 32-byte digest.
 */
function sha256(data) {
  return binding.sha256(data);
}

/**
 * Derive a 32-byte AES-256 key from a password.
 * @param {Buffer|string} password - Password (string is encoded as UTF-8).
 * @param {Buffer} salt - 16-byte salt.
 * @param {number} iterations - KDF iteration count (default: 100000).
 * @returns {Buffer} 32-byte derived key.
 */
function deriveKey(password, salt, iterations = 100000) {
  if (typeof password === 'string') {
    password = Buffer.from(password, 'utf8');
  }
  return binding.deriveKey(password, salt, iterations);
}

/**
 * Encrypt data with AES-256-CTR.
 * @param {Buffer} plaintext - Data to encrypt.
 * @param {Buffer} key - 32-byte key.
 * @param {Buffer} [iv] - 16-byte IV (auto-generated if omitted).
 * @returns {Buffer} Encrypted payload (includes header + integrity digest).
 */
function encrypt(plaintext, key, iv) {
  if (!iv) {
    iv = randomBytes(16);
  }
  return binding.encrypt(plaintext, key, iv);
}

/**
 * Decrypt data encrypted with encrypt().
 * @param {Buffer} ciphertext - Encrypted payload.
 * @param {Buffer} key - 32-byte key.
 * @returns {Buffer} Decrypted plaintext.
 * @throws {Error} If integrity check fails or key is wrong.
 */
function decrypt(ciphertext, key) {
  return binding.decrypt(ciphertext, key);
}

/**
 * Encrypt data with a time-lock.
 * The key is wrapped using a proof-of-work scheme and cannot be unwrapped
 * before the specified timestamp.
 *
 * @param {Buffer} plaintext - Data to encrypt.
 * @param {Buffer} key - 32-byte encryption key.
 * @param {Buffer} iv - 16-byte IV.
 * @param {number} unlockTimestamp - Unix timestamp (seconds) after which decryption is allowed.
 * @param {number} iterations - PoW iterations (use estimateIterations() to compute).
 * @param {Buffer} salt - 16-byte salt for time-lock key derivation.
 * @returns {Buffer} Time-locked encrypted payload.
 */
function encryptWithTimeLock(plaintext, key, iv, unlockTimestamp, iterations, salt) {
  return binding.encryptWithTimeLock(plaintext, key, iv, unlockTimestamp, iterations, salt);
}

/**
 * Decrypt time-locked data.
 * Performs the proof-of-work to unwrap the key, then decrypts.
 *
 * @param {Buffer} ciphertext - Time-locked encrypted payload.
 * @param {number} currentTimestamp - Current Unix timestamp (seconds).
 * @returns {Buffer} Decrypted plaintext.
 * @throws {Error} If time not yet reached or integrity check fails.
 */
function decryptTimeLocked(ciphertext, currentTimestamp) {
  return binding.decryptTimeLocked(ciphertext, currentTimestamp);
}

/**
 * Check if an encrypted payload is time-locked.
 * @param {Buffer} data - Encrypted payload.
 * @returns {boolean}
 */
function isTimeLocked(data) {
  return binding.isTimeLocked(data);
}

/**
 * Get the unlock timestamp from a time-locked payload.
 * @param {Buffer} data - Encrypted payload.
 * @returns {number} Unix timestamp (seconds), or 0 if not locked.
 */
function getUnlockTimestamp(data) {
  return binding.getUnlockTimestamp(data);
}

/**
 * Estimate the number of PoW iterations for a target lock duration.
 * @param {number} lockDurationSeconds - Desired lock duration in seconds.
 * @returns {number} Estimated iteration count.
 */
function estimateIterations(lockDurationSeconds) {
  return binding.estimateIterations(lockDurationSeconds);
}

/**
 * Encrypt data using the chunk-based streaming engine.
 * Returns ciphertext + SHA-256 digest for integrity verification.
 *
 * @param {Buffer} plaintext - Data to encrypt.
 * @param {Buffer} key - 32-byte key.
 * @param {Buffer} iv - 16-byte IV.
 * @returns {{ data: Buffer, digest: Buffer }} Encrypted data and integrity digest.
 */
function streamEncrypt(plaintext, key, iv) {
  return binding.streamEncrypt(plaintext, key, iv);
}

/**
 * Decrypt data using the chunk-based streaming engine.
 * Verifies integrity against the expected digest.
 *
 * @param {Buffer} ciphertext - Encrypted data.
 * @param {Buffer} key - 32-byte key.
 * @param {Buffer} iv - 16-byte IV.
 * @param {Buffer} expectedDigest - 32-byte SHA-256 digest from streamEncrypt.
 * @returns {{ data: Buffer, verified: boolean }} Decrypted data and verification status.
 */
function streamDecrypt(ciphertext, key, iv, expectedDigest) {
  return binding.streamDecrypt(ciphertext, key, iv, expectedDigest);
}

/**
 * Generate random bytes (XOR-shift PRNG seeded from high-resolution clock).
 * @param {number} length - Number of bytes to generate.
 * @returns {Buffer} Random bytes.
 */
function randomBytes(length) {
  return binding.randomBytes(length);
}

/**
 * High-level convenience: encrypt a file with a password.
 *
 * @param {Buffer} data - File data to encrypt.
 * @param {string} password - Password.
 * @returns {{ encrypted: Buffer, salt: Buffer, iv: Buffer }} Encrypted data + parameters.
 */
function encryptWithPassword(data, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(16);
  const key = deriveKey(password, salt, 100000);
  const encrypted = encrypt(data, key, iv);
  return { encrypted, salt, iv };
}

/**
 * High-level convenience: decrypt data encrypted with encryptWithPassword().
 *
 * @param {Buffer} encrypted - Encrypted payload.
 * @param {string} password - Password.
 * @param {Buffer} salt - 16-byte salt (from encryptWithPassword).
 * @returns {Buffer} Decrypted data.
 */
function decryptWithPassword(encrypted, password, salt) {
  const key = deriveKey(password, salt, 100000);
  return decrypt(encrypted, key);
}

module.exports = {
  // Core crypto
  sha256,
  deriveKey,
  encrypt,
  decrypt,

  // Time-locking
  encryptWithTimeLock,
  decryptTimeLocked,
  isTimeLocked,
  getUnlockTimestamp,
  estimateIterations,

  // Streaming
  streamEncrypt,
  streamDecrypt,

  // Utilities
  randomBytes,

  // High-level convenience
  encryptWithPassword,
  decryptWithPassword,

  // Raw native binding (for advanced use)
  _native: binding,
};



