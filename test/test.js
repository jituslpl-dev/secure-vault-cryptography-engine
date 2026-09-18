'use strict';

const assert = require('assert');
const crypto = require('crypto');
const secureVault = require('../lib/index.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

console.log('\n╔══════════════════════════════════════════════════╗');
console.log('║     SecureVault — Test Suite                     ║');
console.log('╚══════════════════════════════════════════════════╝\n');

// ─── SHA-256 Tests ──────────────────────────────────────────────
console.log('▸ SHA-256 Tests');

test('SHA-256 of empty string matches known vector', () => {
  const input = Buffer.alloc(0);
  const result = secureVault.sha256(input);
  const expected = crypto.createHash('sha256').update(input).digest();
  assert.strictEqual(result.toString('hex'), expected.toString('hex'));
  // Known: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  assert.strictEqual(
    result.toString('hex'),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
});

test('SHA-256 of "abc" matches known vector', () => {
  const input = Buffer.from('abc', 'utf8');
  const result = secureVault.sha256(input);
  assert.strictEqual(
    result.toString('hex'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

test('SHA-256 of large data matches Node crypto', () => {
  const input = crypto.randomBytes(10000);
  const result = secureVault.sha256(input);
  const expected = crypto.createHash('sha256').update(input).digest();
  assert.strictEqual(result.toString('hex'), expected.toString('hex'));
});

test('SHA-256 produces 32-byte digest', () => {
  const result = secureVault.sha256(Buffer.from('test'));
  assert.strictEqual(result.length, 32);
});

// ─── Key Derivation Tests ────────────────────────────────────────
console.log('\n▸ Key Derivation Tests');

test('deriveKey produces 32-byte key', () => {
  const salt = secureVault.randomBytes(16);
  const key = secureVault.deriveKey('mypassword', salt, 1000);
  assert.strictEqual(key.length, 32);
});

test('deriveKey is deterministic with same inputs', () => {
  const salt = Buffer.alloc(16, 0xAB);
  const key1 = secureVault.deriveKey('test123', salt, 500);
  const key2 = secureVault.deriveKey('test123', salt, 500);
  assert.deepStrictEqual(key1, key2);
});

test('deriveKey differs with different passwords', () => {
  const salt = Buffer.alloc(16, 0xAB);
  const key1 = secureVault.deriveKey('password1', salt, 500);
  const key2 = secureVault.deriveKey('password2', salt, 500);
  assert.notDeepStrictEqual(key1, key2);
});

// ─── Encrypt/Decrypt Tests ──────────────────────────────────────
console.log('\n▸ Encrypt/Decrypt Tests');

test('Encrypt then decrypt returns original data', () => {
  const plaintext = Buffer.from('Hello, SecureVault!', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const encrypted = secureVault.encrypt(plaintext, key, iv);
  const decrypted = secureVault.decrypt(encrypted, key);
  assert.deepStrictEqual(decrypted, plaintext);
});

test('Encrypt then decrypt with large data (1MB)', () => {
  const plaintext = crypto.randomBytes(1024 * 1024);
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const encrypted = secureVault.encrypt(plaintext, key, iv);
  const decrypted = secureVault.decrypt(encrypted, key);
  assert.deepStrictEqual(decrypted, plaintext);
});

test('Decryption with wrong key fails (integrity check)', () => {
  const plaintext = Buffer.from('Secret data', 'utf8');
  const key = secureVault.randomBytes(32);
  const wrongKey = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const encrypted = secureVault.encrypt(plaintext, key, iv);

  assert.throws(() => {
    secureVault.decrypt(encrypted, wrongKey);
  }, /Integrity check failed/);
});

test('Encrypted data differs from plaintext', () => {
  const plaintext = Buffer.from('This is a test message', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const encrypted = secureVault.encrypt(plaintext, key, iv);
  assert.notStrictEqual(encrypted.slice(55).toString('hex'), plaintext.toString('hex'));
});

test('Encrypt with password and decrypt with password', () => {
  const data = Buffer.from('Password-protected data', 'utf8');
  const { encrypted, salt } = secureVault.encryptWithPassword(data, 'mySecretPass');
  const decrypted = secureVault.decryptWithPassword(encrypted, 'mySecretPass', salt);
  assert.deepStrictEqual(decrypted, data);
});

test('Decrypt with wrong password fails', () => {
  const data = Buffer.from('Password-protected data', 'utf8');
  const { encrypted, salt } = secureVault.encryptWithPassword(data, 'correctPassword');
  assert.throws(() => {
    secureVault.decryptWithPassword(encrypted, 'wrongPassword', salt);
  });
});

// ─── Streaming Tests ─────────────────────────────────────────────
console.log('\n▸ Streaming Engine Tests');

test('Stream encrypt/decrypt round-trip', () => {
  const plaintext = crypto.randomBytes(256 * 1024); // 256KB
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);

  const { data: encrypted, digest } = secureVault.streamEncrypt(plaintext, key, iv);
  const { data: decrypted, verified } = secureVault.streamDecrypt(encrypted, key, iv, digest);

  assert.strictEqual(verified, true);
  assert.deepStrictEqual(decrypted, plaintext);
});

test('Stream integrity verification detects tampering', () => {
  const plaintext = Buffer.from('Stream test data', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);

  const { data: encrypted, digest } = secureVault.streamEncrypt(plaintext, key, iv);

  // Tamper with the encrypted data
  encrypted[0] ^= 0xFF;

  const { verified } = secureVault.streamDecrypt(encrypted, key, iv, digest);
  assert.strictEqual(verified, false);
});

// ─── Time-Lock Tests ─────────────────────────────────────────────
console.log('\n▸ Time-Lock Tests');

test('Time-locked data is detected as time-locked', () => {
  const plaintext = Buffer.from('Time-locked secret', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const salt = secureVault.randomBytes(16);
  const unlockTs = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  const iterations = 1000;

  const encrypted = secureVault.encryptWithTimeLock(plaintext, key, iv, unlockTs, iterations, salt);
  assert.strictEqual(secureVault.isTimeLocked(encrypted), true);
});

test('Non-time-locked data is not detected as time-locked', () => {
  const plaintext = Buffer.from('Regular data', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const encrypted = secureVault.encrypt(plaintext, key, iv);
  assert.strictEqual(secureVault.isTimeLocked(encrypted), false);
});

test('Time-locked data cannot be decrypted before unlock time', () => {
  const plaintext = Buffer.from('Future secret', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const salt = secureVault.randomBytes(16);
  const unlockTs = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
  const iterations = 1000;

  const encrypted = secureVault.encryptWithTimeLock(plaintext, key, iv, unlockTs, iterations, salt);

  const now = Math.floor(Date.now() / 1000);
  assert.throws(() => {
    secureVault.decryptTimeLocked(encrypted, now);
  }, /Time not yet reached/);
});

test('Time-locked data can be decrypted after unlock time', () => {
  const plaintext = Buffer.from('Unlocked secret', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const salt = secureVault.randomBytes(16);
  const unlockTs = Math.floor(Date.now() / 1000) - 1; // Already unlocked
  const iterations = 1000;

  const encrypted = secureVault.encryptWithTimeLock(plaintext, key, iv, unlockTs, iterations, salt);
  const now = Math.floor(Date.now() / 1000);
  const decrypted = secureVault.decryptTimeLocked(encrypted, now);
  assert.deepStrictEqual(decrypted, plaintext);
});

test('getUnlockTimestamp returns correct value', () => {
  const plaintext = Buffer.from('test', 'utf8');
  const key = secureVault.randomBytes(32);
  const iv = secureVault.randomBytes(16);
  const salt = secureVault.randomBytes(16);
  const unlockTs = Math.floor(Date.now() / 1000) + 7200; // 2 hours from now

  const encrypted = secureVault.encryptWithTimeLock(plaintext, key, iv, unlockTs, 1000, salt);
  const retrieved = secureVault.getUnlockTimestamp(encrypted);
  assert.strictEqual(retrieved, unlockTs);
});

test('estimateIterations returns reasonable value', () => {
  const iters = secureVault.estimateIterations(1.0); // 1 second
  assert.ok(iters > 0);
  assert.ok(iters >= 100000); // At least 100K iterations for 1 second
});

// ─── Utility Tests ──────────────────────────────────────────────
console.log('\n▸ Utility Tests');

test('randomBytes produces correct length', () => {
  const bytes = secureVault.randomBytes(64);
  assert.strictEqual(bytes.length, 64);
});

test('randomBytes produces different values on each call', () => {
  const a = secureVault.randomBytes(32);
  const b = secureVault.randomBytes(32);
  assert.notDeepStrictEqual(a, b);
});

// ─── Summary ────────────────────────────────────────────────────
console.log('\n════════════════════════════════════════════════════');
console.log(`  Results: ${passed} passed, ${failed} failed`);
console.log('════════════════════════════════════════════════════\n');

process.exit(failed > 0 ? 1 : 0);



