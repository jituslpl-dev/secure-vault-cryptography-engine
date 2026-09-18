#!/usr/bin/env node
'use strict';

/**
 * SecureVault CLI — Command-line interface for file encryption/decryption.
 *
 * Usage:
 *   securevault encrypt <file> [--password <pass>] [--output <file>]
 *   securevault decrypt <file> --password <pass> [--output <file>]
 *   securevault hash <file>
 *   securevault info <file>
 *   securevault --help
 *   securevault --version
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const VERSION = '1.0.0';

// ─── Colors (ANSI) ───────────────────────────────────────────────
const C = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m',
};

function color(text, c) {
    return c + text + C.reset;
}

// ─── Help ────────────────────────────────────────────────────────
function showHelp() {
    const banner = `
${color('╔══════════════════════════════════════════════════════════════╗', C.cyan)}
${color('║', C.cyan)}  ${color('�� SecureVault', C.bold)} ${color('v' + VERSION, C.dim)}${' '.repeat(44)}${color('║', C.cyan)}
${color('║', C.cyan)}  ${color('High-throughput secure file encryption engine', C.dim)}${' '.repeat(13)}${color('║', C.cyan)}
${color('╚══════════════════════════════════════════════════════════════╝', C.cyan)}

${color('USAGE', C.bold)}
  ${color('securevault', C.cyan)} <command> [options] [arguments]

${color('COMMANDS', C.bold)}
  ${color('encrypt', C.green)} <file>      Encrypt a file
  ${color('decrypt', C.green)} <file>      Decrypt a file
  ${color('hash', C.green)} <file>         Compute SHA-256 hash of a file
  ${color('info', C.green)} <file>         Show info about an encrypted file
  ${color('benchmark', C.green)}           Run performance benchmarks
  ${color('help', C.green)}                Show this help message

${color('OPTIONS', C.bold)}
  ${color('-p, --password', C.yellow)} <pass>  Password for encryption/decryption
  ${color('-o, --output', C.yellow)} <file>    Output file path
  ${color('-t, --time-lock', C.yellow)} <sec>  Time-lock duration in seconds
  ${color('-v, --verbose', C.yellow)}          Verbose output
  ${color('--version', C.yellow)}              Show version number

${color('EXAMPLES', C.bold)}
  ${color('# Encrypt a file with a password', C.dim)}
  securevault encrypt secret.txt --password mySecret123

  ${color('# Encrypt and time-lock for 1 hour', C.dim)}
  securevault encrypt secret.txt --password mySecret123 --time-lock 3600

  ${color('# Decrypt a file', C.dim)}
  securevault decrypt secret.txt.enc --password mySecret123

  ${color('# Hash a file', C.dim)}
  securevault hash document.pdf

  ${color('# Show info about an encrypted file', C.dim)}
  securevault info secret.txt.enc

${color('ALGORITHMS', C.bold)}
  ${color('SHA-256', C.cyan)}    Custom bitwise implementation (NIST FIPS 180-4)
  ${color('AES-256', C.cyan)}    Full Rijndael in CTR mode (NIST FIPS 197, SP 800-38A)
  ${color('Time-Lock', C.cyan)}  Proof-of-work key wrapping via iterated SHA-256

${color('SECURITY', C.bold)}
  This is an educational/portfolio project. See SECURITY.md for limitations.
  Do not use for protecting real sensitive data without a security audit.
`;
    console.log(banner);
}

// ─── Utility Functions ───────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function promptPassword(prompt) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
        });
        rl.question(prompt, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

function error(msg) {
    console.error(color('✗ Error: ', C.red) + msg);
    process.exit(1);
}

function success(msg) {
    console.log(color('✓ ', C.green) + msg);
}

function info(msg) {
    console.log(color('  ', C.dim) + msg);
}

// ─── Commands ────────────────────────────────────────────────────

async function cmdEncrypt(args) {
    const file = args.positional[0];
    if (!file) error('No input file specified. Use: securevault encrypt <file>');

    if (!fs.existsSync(file)) {
        error(`File not found: ${file}`);
    }

    let password = args.options.password || args.options.p;
    if (!password) {
        password = await promptPassword(color('Enter password: ', C.cyan));
        if (!password) error('Password is required');
    }

    const outputFile = args.options.output || args.options.o || (file + '.enc');
    const timeLockSeconds = args.options['time-lock'] || args.options.t;

    let secureVault;
    try {
        secureVault = require('../lib/index.js');
    } catch (e) {
        error('Native module not built. Run: npm install');
    }

    const data = fs.readFileSync(file);
    console.log(color('\n�� Encrypting...', C.cyan));
    info(`Input:  ${file} (${formatBytes(data.length)})`);
    info(`Output: ${outputFile}`);

    if (timeLockSeconds) {
        const iterations = secureVault.estimateIterations(parseFloat(timeLockSeconds));
        const unlockTime = Math.floor(Date.now() / 1000) + parseInt(timeLockSeconds);
        const salt = secureVault.randomBytes(16);
        const key = secureVault.deriveKey(password, salt, 100000);
        const iv = secureVault.randomBytes(16);

        info(`Time-lock: ${timeLockSeconds}s (${iterations} PoW iterations)`);
        info(`Unlock at: ${new Date(unlockTime * 1000).toISOString()}`);

        const encrypted = secureVault.encryptWithTimeLock(data, key, iv, unlockTime, iterations, salt);

        // Write salt + iv + encrypted data
        const output = Buffer.concat([salt, iv, encrypted]);
        fs.writeFileSync(outputFile, output);

        success(`Encrypted ${formatBytes(data.length)} → ${formatBytes(output.length)}`);
        info(`Salt: ${salt.toString('hex')}`);
    } else {
        const { encrypted, salt, iv } = secureVault.encryptWithPassword(data, password);
        const output = Buffer.concat([salt, iv, encrypted]);
        fs.writeFileSync(outputFile, output);

        success(`Encrypted ${formatBytes(data.length)} → ${formatBytes(output.length)}`);
    }
    console.log();
}

async function cmdDecrypt(args) {
    const file = args.positional[0];
    if (!file) error('No input file specified. Use: securevault decrypt <file>');

    if (!fs.existsSync(file)) {
        error(`File not found: ${file}`);
    }

    let password = args.options.password || args.options.p;
    if (!password) {
        password = await promptPassword(color('Enter password: ', C.cyan));
        if (!password) error('Password is required');
    }

    const outputFile = args.options.output || args.options.o ||
        file.replace(/\.enc$/, '') + '.dec';

    let secureVault;
    try {
        secureVault = require('../lib/index.js');
    } catch (e) {
        error('Native module not built. Run: npm install');
    }

    const fileData = fs.readFileSync(file);

    // Extract salt (16B) + IV (16B) + encrypted payload
    if (fileData.length < 32) {
        error('File too short to be a SecureVault encrypted file');
    }

    const salt = fileData.slice(0, 16);
    const iv = fileData.slice(16, 32);
    const encrypted = fileData.slice(32);

    console.log(color('\n�� Decrypting...', C.cyan));
    info(`Input:  ${file} (${formatBytes(fileData.length)})`);
    info(`Output: ${outputFile}`);

    // Check if time-locked
    if (secureVault.isTimeLocked(encrypted)) {
        const unlockTs = secureVault.getUnlockTimestamp(encrypted);
        const now = Math.floor(Date.now() / 1000);

        if (now < unlockTs) {
            error(`Data is time-locked until ${new Date(unlockTs * 1000).toISOString()}`);
        }

        info('Time-lock expired — performing proof-of-work...');

        const start = Date.now();
        try {
            const decrypted = secureVault.decryptTimeLocked(encrypted, now);
            fs.writeFileSync(outputFile, decrypted);
            const powTime = Date.now() - start;
            success(`Decrypted ${formatBytes(encrypted.length)} → ${formatBytes(decrypted.length)}`);
            info(`Proof-of-work: ${powTime}ms`);
        } catch (e) {
            error(`Decryption failed: ${e.message}`);
        }
    } else {
        try {
            const decrypted = secureVault.decryptWithPassword(encrypted, password, salt);
            fs.writeFileSync(outputFile, decrypted);
            success(`Decrypted ${formatBytes(encrypted.length)} → ${formatBytes(decrypted.length)}`);
        } catch (e) {
            error(`Decryption failed: ${e.message}`);
        }
    }
    console.log();
}

async function cmdHash(args) {
    const file = args.positional[0];
    if (!file) error('No input file specified. Use: securevault hash <file>');

    if (!fs.existsSync(file)) {
        error(`File not found: ${file}`);
    }

    let secureVault;
    try {
        secureVault = require('../lib/index.js');
    } catch (e) {
        error('Native module not built. Run: npm install');
    }

    const data = fs.readFileSync(file);
    const hash = secureVault.sha256(data);

    console.log(color('\n# SHA-256 Hash', C.cyan));
    info(`File: ${file} (${formatBytes(data.length)})`);
    console.log(color(`  Hash: `, C.dim) + color(hash.toString('hex'), C.yellow));
    console.log();
}

async function cmdInfo(args) {
    const file = args.positional[0];
    if (!file) error('No input file specified. Use: securevault info <file>');

    if (!fs.existsSync(file)) {
        error(`File not found: ${file}`);
    }

    let secureVault;
    try {
        secureVault = require('../lib/index.js');
    } catch (e) {
        error('Native module not built. Run: npm install');
    }

    const fileData = fs.readFileSync(file);
    console.log(color('\n�� File Information', C.cyan));
    info(`File:     ${file}`);
    info(`Size:     ${formatBytes(fileData.length)}`);

    if (fileData.length >= 32) {
        const salt = fileData.slice(0, 16);
        const iv = fileData.slice(16, 32);
        const encrypted = fileData.slice(32);

        info(`Salt:     ${salt.toString('hex')}`);
        info(`IV:       ${iv.toString('hex')}`);
        info(`Payload:  ${formatBytes(encrypted.length)}`);

        if (secureVault.isTimeLocked(encrypted)) {
            const unlockTs = secureVault.getUnlockTimestamp(encrypted);
            info(`Locked:   ${color('Yes', C.yellow)}`);
            info(`Unlock:   ${new Date(unlockTs * 1000).toISOString()}`);
        } else {
            info(`Locked:   No`);
        }
    } else {
        info('Not a valid SecureVault file');
    }
    console.log();
}

async function cmdBenchmark() {
    let secureVault;
    try {
        secureVault = require('../lib/index.js');
    } catch (e) {
        error('Native module not built. Run: npm install');
    }

    console.log(color('\n⚡ SecureVault Benchmarks\n', C.cyan));

    // SHA-256
    const data1MB = Buffer.alloc(1024 * 1024, 0x42);
    const t0 = Date.now();
    secureVault.sha256(data1MB);
    const shaTime = Date.now() - t0;
    console.log(color('SHA-256 (1MB):', C.bold) + ` ${shaTime}ms (${(1024 / shaTime * 1000).toFixed(0)} MB/s)`);

    // Encrypt
    const key = secureVault.randomBytes(32);
    const iv = secureVault.randomBytes(16);
    const t1 = Date.now();
    const enc = secureVault.encrypt(data1MB, key, iv);
    const encTime = Date.now() - t1;
    console.log(color('Encrypt (1MB):', C.bold) + ` ${encTime}ms (${(1024 / encTime * 1000).toFixed(0)} MB/s)`);

    // Decrypt
    const t2 = Date.now();
    secureVault.decrypt(enc, key);
    const decTime = Date.now() - t2;
    console.log(color('Decrypt (1MB):', C.bold) + ` ${decTime}ms (${(1024 / decTime * 1000).toFixed(0)} MB/s)`);

    // Stream
    const t3 = Date.now();
    const { data: streamEnc, digest } = secureVault.streamEncrypt(data1MB, key, iv);
    const streamEncTime = Date.now() - t3;
    console.log(color('Stream Enc (1MB):', C.bold) + ` ${streamEncTime}ms (${(1024 / streamEncTime * 1000).toFixed(0)} MB/s)`);

    const t4 = Date.now();
    secureVault.streamDecrypt(streamEnc, key, iv, digest);
    const streamDecTime = Date.now() - t4;
    console.log(color('Stream Dec (1MB):', C.bold) + ` ${streamDecTime}ms (${(1024 / streamDecTime * 1000).toFixed(0)} MB/s)`);
    console.log();
}

// ─── Argument Parsing ────────────────────────────────────────────

function parseArgs(argv) {
    const positional = [];
    const options = {};
    let i = 0;

    while (i < argv.length) {
        const arg = argv[i];
        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            if (i + 1 < argv.length && !argv[i + 1].startsWith('-')) {
                options[key] = argv[++i];
            } else {
                options[key] = true;
            }
        } else if (arg.startsWith('-') && arg.length > 1) {
            const key = arg.slice(1);
            if (i + 1 < argv.length && !argv[i + 1].startsWith('-')) {
                options[key] = argv[++i];
            } else {
                options[key] = true;
            }
        } else {
            positional.push(arg);
        }
        i++;
    }

    return { positional, options };
}

// ─── Main ────────────────────────────────────────────────────────

async function main() {
    const argv = process.argv.slice(2);

    if (argv.length === 0 || argv[0] === 'help' || argv[0] === '--help' || argv[0] === '-h') {
        showHelp();
        return;
    }

    if (argv[0] === '--version' || argv[0] === '-v') {
        console.log(`SecureVault v${VERSION}`);
        return;
    }

    const command = argv[0];
    const args = parseArgs(argv.slice(1));

    try {
        switch (command) {
            case 'encrypt':
                await cmdEncrypt(args);
                break;
            case 'decrypt':
                await cmdDecrypt(args);
                break;
            case 'hash':
                await cmdHash(args);
                break;
            case 'info':
                await cmdInfo(args);
                break;
            case 'benchmark':
                await cmdBenchmark();
                break;
            default:
                error(`Unknown command: ${command}. Run 'securevault help' for usage.`);
        }
    } catch (e) {
        error(e.message);
    }
}

main();



