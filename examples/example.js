'use strict';

const secureVault = require('../lib/index.js');

console.log('╔══════════════════════════════════════════════════╗');
console.log('║   SecureVault — Live Demonstration               ║');
console.log('╚══════════════════════════════════════════════════╝\n');

// ─── 1. SHA-256 Hashing ──────────────────────────────────────────
console.log('━━━ 1. SHA-256 Hashing ━━━━━━━━━━━━━━━━━━━━━━━━━━');
const message = Buffer.from('The quick brown fox jumps over the lazy dog', 'utf8');
const digest = secureVault.sha256(message);
console.log('  Input:    "The quick brown fox jumps over the lazy dog"');
console.log('  SHA-256: ', digest.toString('hex'));
console.log();

// ─── 2. Basic Encryption ────────────────────────────────────────
console.log('━━━ 2. AES-256-CTR Encryption ━━━━━━━━━━━━━━━━━━');
const plaintext = Buffer.from('This is top-secret data that needs protection!', 'utf8');
const key = secureVault.randomBytes(32);
const iv = secureVault.randomBytes(16);

console.log('  Plaintext:', plaintext.toString('utf8'));
const encrypted = secureVault.encrypt(plaintext, key, iv);
console.log('  Encrypted:', encrypted.toString('hex').substring(0, 64) + '...');
console.log('  Size:    ', encrypted.length, 'bytes (header: 55 + data:', plaintext.length, ')');

const decrypted = secureVault.decrypt(encrypted, key);
console.log('  Decrypted:', decrypted.toString('utf8'));
console.log('  ✓ Round-trip verified:', decrypted.equals(plaintext));
console.log();

// ─── 3. Password-Based Encryption ───────────────────────────────
console.log('━━━ 3. Password-Based Encryption ━━━━━━━━━━━━━━━');
const fileData = Buffer.from('Confidential file contents — for authorized eyes only.', 'utf8');
const { encrypted: enc, salt } = secureVault.encryptWithPassword(fileData, 'My$tr0ngP@ss!');

console.log('  Password: "My$tr0ngP@ss!"');
console.log('  Salt:    ', salt.toString('hex'));
console.log('  Encrypted:', enc.length, 'bytes');

const dec = secureVault.decryptWithPassword(enc, 'My$tr0ngP@ss!', salt);
console.log('  Decrypted:', dec.toString('utf8'));
console.log('  ✓ Password encryption verified:', dec.equals(fileData));
console.log();

// ─── 4. Streaming Encryption (Large Data) ───────────────────────
console.log('━━━ 4. Streaming Encryption (1MB) ━━━━━━━━━━━━━━━');
const largeData = Buffer.alloc(1024 * 1024);
for (let i = 0; i < largeData.length; i++) {
  largeData[i] = i & 0xFF;
}

const streamKey = secureVault.randomBytes(32);
const streamIv = secureVault.randomBytes(16);

const start = Date.now();
const { data: streamEnc, digest: streamDigest } = secureVault.streamEncrypt(largeData, streamKey, streamIv);
const encTime = Date.now() - start;

const start2 = Date.now();
const { data: streamDec, verified } = secureVault.streamDecrypt(streamEnc, streamKey, streamIv, streamDigest);
const decTime = Date.now() - start2;

console.log('  Data size: 1 MB');
console.log('  Encrypt time:', encTime, 'ms');
console.log('  Decrypt time:', decTime, 'ms');
console.log('  Throughput:  ', Math.round(1024 / (encTime + decTime) * 1000), 'MB/s');
console.log('  Integrity:   ', verified ? '✓ Verified' : '✗ FAILED');
console.log('  Round-trip:  ', streamDec.equals(largeData) ? '✓ Verified' : '✗ FAILED');
console.log();

// ─── 5. Time-Locked Encryption ──────────────────────────────────
console.log('━━━ 5. Time-Locked Encryption ━━━━━━━━━━━━━━━━━━━');
const secretData = Buffer.from('This data is locked until the future arrives!', 'utf8');
const tlKey = secureVault.randomBytes(32);
const tlIv = secureVault.randomBytes(16);
const tlSalt = secureVault.randomBytes(16);

const now = Math.floor(Date.now() / 1000);
const unlockTime = now + 10; // 10 seconds in the future
const iterations = 5000; // Small for demo

console.log('  Secret:   "This data is locked until the future arrives!"');
console.log('  Lock until:', new Date(unlockTime * 1000).toISOString());
console.log('  PoW iterations:', iterations);

const tlEncrypted = secureVault.encryptWithTimeLock(
  secretData, tlKey, tlIv, unlockTime, iterations, tlSalt
);
console.log('  Time-locked:', secureVault.isTimeLocked(tlEncrypted) ? 'Yes' : 'No');
console.log('  Encrypted size:', tlEncrypted.length, 'bytes');

// Try to decrypt now (should fail)
try {
  secureVault.decryptTimeLocked(tlEncrypted, now);
  console.log('  ✗ ERROR: Should have failed!');
} catch (e) {
  console.log('  ✓ Correctly refused decryption before unlock time');
}

// Decrypt with future timestamp
const futureTs = now + 3600;
const tlDecrypted = secureVault.decryptTimeLocked(tlEncrypted, futureTs);
console.log('  Decrypted: ', tlDecrypted.toString('utf8'));
console.log('  ✓ Time-lock verified:', tlDecrypted.equals(secretData));
console.log();

// ─── 6. Tamper Detection ────────────────────────────────────────
console.log('━━━ 6. Tamper Detection ━━━━━━━━━━━━━━━━━━━━━━━━');
const tamperData = Buffer.from('Original untampered data', 'utf8');
const tamperKey = secureVault.randomBytes(32);
const tamperIv = secureVault.randomBytes(16);
const tampered = secureVault.encrypt(tamperData, tamperKey, tamperIv);

// Flip a bit in the ciphertext
tampered[60] ^= 0x01;

try {
  secureVault.decrypt(tampered, tamperKey);
  console.log('  ✗ ERROR: Tampered data was accepted!');
} catch (e) {
  console.log('  ✓ Tamper detected:', e.message);
}
console.log();

console.log('════════════════════════════════════════════════════');
console.log('  All demonstrations completed successfully! ✅');
console.log('════════════════════════════════════════════════════\n');



