/**
 * WASI Module Test Suite
 *
 * Tests the pure WASI build of hd-wallet-wasm using Node.js WASI support.
 * This validates the same module that Go/wazero and other WASI runtimes use.
 */

import { readFile } from 'fs/promises';
import { WASI } from 'wasi';
import { argv, env } from 'process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { randomBytes } from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, '../../build-wasi-pure/hd-wallet.wasm');

// Test utilities
let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  \x1b[32m✓\x1b[0m ${name}`);
        passed++;
    } catch (e) {
        console.log(`  \x1b[31m✗\x1b[0m ${name}`);
        console.log(`    Error: ${e.message}`);
        failed++;
    }
}

function assertEqual(actual, expected, msg = '') {
    if (actual !== expected) {
        throw new Error(`${msg}: expected ${expected}, got ${actual}`);
    }
}

function assertNotEqual(actual, expected, msg = '') {
    if (actual === expected) {
        throw new Error(`${msg}: expected different value, got ${actual}`);
    }
}

function toHex(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Load and instantiate WASI module
async function loadModule() {
    const wasi = new WASI({
        version: 'preview1',
        args: argv,
        env,
    });

    const wasmBytes = await readFile(WASM_PATH);
    const module = await WebAssembly.compile(wasmBytes);
    const instance = await WebAssembly.instantiate(module, {
        wasi_snapshot_preview1: wasi.wasiImport,
    });

    // Initialize the module (reactor pattern)
    if (instance.exports._initialize) {
        instance.exports._initialize();
    }

    return instance.exports;
}

// Helper to read string from WASM memory
function readString(memory, ptr, maxLen = 512) {
    const view = new Uint8Array(memory.buffer, ptr, maxLen);
    let end = view.indexOf(0);
    if (end === -1) end = maxLen;
    return new TextDecoder().decode(view.slice(0, end));
}

// Helper to write bytes to WASM memory
function writeBytes(memory, ptr, bytes) {
    const view = new Uint8Array(memory.buffer, ptr, bytes.length);
    view.set(bytes);
}

// Helper to read bytes from WASM memory
function readBytes(memory, ptr, len) {
    return new Uint8Array(memory.buffer, ptr, len).slice();
}

async function runTests() {
    console.log('\n\x1b[1mWASI Module Test Suite\x1b[0m\n');

    let wasm;
    try {
        wasm = await loadModule();
    } catch (e) {
        console.error(`Failed to load WASM module: ${e.message}`);
        console.error('Make sure to build the WASI module first: cd build-wasi-pure && make');
        process.exit(1);
    }

    const { memory } = wasm;

    // Version test
    console.log('\x1b[1mVersion:\x1b[0m');
    test('get version', () => {
        const version = wasm.hd_get_version();
        assertEqual(version, 0x00010005, 'Version should be 0.1.5');
    });

    // Entropy tests
    console.log('\n\x1b[1mEntropy Management:\x1b[0m');
    test('initial entropy status is 0', () => {
        const status = wasm.hd_get_entropy_status();
        assertEqual(status, 0, 'Initial status');
    });

    test('inject entropy', () => {
        const entropyPtr = wasm.hd_alloc(64);
        const entropy = randomBytes(64);
        writeBytes(memory, entropyPtr, entropy);
        wasm.hd_inject_entropy(entropyPtr, 64);
        wasm.hd_dealloc(entropyPtr);

        const status = wasm.hd_get_entropy_status();
        assertEqual(status, 2, 'Status after injection');
    });

    // Mnemonic tests
    console.log('\n\x1b[1mBIP-39 Mnemonic:\x1b[0m');

    test('generate 12-word mnemonic', () => {
        const outputPtr = wasm.hd_alloc(512);
        const result = wasm.hd_mnemonic_generate(outputPtr, 512, 12, 0);

        if (result < 0) throw new Error(`Generation failed: ${result}`);

        const mnemonic = readString(memory, outputPtr);
        const words = mnemonic.split(' ');
        assertEqual(words.length, 12, 'Word count');

        wasm.hd_dealloc(outputPtr);
    });

    test('generate 24-word mnemonic', () => {
        const outputPtr = wasm.hd_alloc(512);
        const result = wasm.hd_mnemonic_generate(outputPtr, 512, 24, 0);

        if (result < 0) throw new Error(`Generation failed: ${result}`);

        const mnemonic = readString(memory, outputPtr);
        const words = mnemonic.split(' ');
        assertEqual(words.length, 24, 'Word count');

        wasm.hd_dealloc(outputPtr);
    });

    const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

    test('validate valid mnemonic', () => {
        const mnemonicPtr = wasm.hd_alloc(TEST_MNEMONIC.length + 1);
        writeBytes(memory, mnemonicPtr, new TextEncoder().encode(TEST_MNEMONIC + '\0'));

        const result = wasm.hd_mnemonic_validate(mnemonicPtr, 0);
        assertEqual(result, 0, 'Should be valid');

        wasm.hd_dealloc(mnemonicPtr);
    });

    test('reject invalid checksum', () => {
        const invalid = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
        const mnemonicPtr = wasm.hd_alloc(invalid.length + 1);
        writeBytes(memory, mnemonicPtr, new TextEncoder().encode(invalid + '\0'));

        const result = wasm.hd_mnemonic_validate(mnemonicPtr, 0);
        assertNotEqual(result, 0, 'Should be invalid');

        wasm.hd_dealloc(mnemonicPtr);
    });

    test('mnemonic to seed', () => {
        const mnemonicPtr = wasm.hd_alloc(TEST_MNEMONIC.length + 1);
        writeBytes(memory, mnemonicPtr, new TextEncoder().encode(TEST_MNEMONIC + '\0'));

        const seedPtr = wasm.hd_alloc(64);
        const result = wasm.hd_mnemonic_to_seed(mnemonicPtr, 0, seedPtr, 64);
        assertEqual(result, 0, 'Should succeed');

        const seed = readBytes(memory, seedPtr, 64);
        // Known seed for "abandon...about" with empty passphrase
        const expectedPrefix = '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1';
        assertEqual(toHex(seed).substring(0, 64), expectedPrefix, 'Seed prefix');

        wasm.hd_dealloc(mnemonicPtr);
        wasm.hd_dealloc(seedPtr);
    });

    test('mnemonic to seed with passphrase', () => {
        const mnemonicPtr = wasm.hd_alloc(TEST_MNEMONIC.length + 1);
        writeBytes(memory, mnemonicPtr, new TextEncoder().encode(TEST_MNEMONIC + '\0'));

        const passphrase = 'TREZOR';
        const passphrasePtr = wasm.hd_alloc(passphrase.length + 1);
        writeBytes(memory, passphrasePtr, new TextEncoder().encode(passphrase + '\0'));

        const seedPtr = wasm.hd_alloc(64);
        const result = wasm.hd_mnemonic_to_seed(mnemonicPtr, passphrasePtr, seedPtr, 64);
        assertEqual(result, 0, 'Should succeed');

        const seed = readBytes(memory, seedPtr, 64);
        // Known seed with TREZOR passphrase
        const expectedPrefix = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf14163';
        assertEqual(toHex(seed).substring(0, expectedPrefix.length), expectedPrefix, 'Seed with passphrase');

        wasm.hd_dealloc(mnemonicPtr);
        wasm.hd_dealloc(passphrasePtr);
        wasm.hd_dealloc(seedPtr);
    });

    // SLIP-10 Ed25519 tests
    console.log('\n\x1b[1mSLIP-10 Ed25519:\x1b[0m');

    test('derive master key from seed', () => {
        // Create seed from test mnemonic
        const mnemonicPtr = wasm.hd_alloc(TEST_MNEMONIC.length + 1);
        writeBytes(memory, mnemonicPtr, new TextEncoder().encode(TEST_MNEMONIC + '\0'));
        const seedPtr = wasm.hd_alloc(64);
        wasm.hd_mnemonic_to_seed(mnemonicPtr, 0, seedPtr, 64);

        const path = "m/44'/501'/0'/0'";  // Solana path
        const pathPtr = wasm.hd_alloc(path.length + 1);
        writeBytes(memory, pathPtr, new TextEncoder().encode(path + '\0'));

        const keyPtr = wasm.hd_alloc(32);
        const chainCodePtr = wasm.hd_alloc(32);

        const result = wasm.hd_slip10_ed25519_derive_path(seedPtr, 64, pathPtr, keyPtr, chainCodePtr);
        assertEqual(result, 0, 'Should succeed');

        const key = readBytes(memory, keyPtr, 32);
        assertEqual(key.length, 32, 'Key length');

        // Key should not be all zeros
        const keySum = key.reduce((a, b) => a + b, 0);
        assertNotEqual(keySum, 0, 'Key should not be zero');

        wasm.hd_dealloc(mnemonicPtr);
        wasm.hd_dealloc(seedPtr);
        wasm.hd_dealloc(pathPtr);
        wasm.hd_dealloc(keyPtr);
        wasm.hd_dealloc(chainCodePtr);
    });

    test('derive Ed25519 public key', () => {
        // Use a known seed
        const seed = new Uint8Array(32);
        for (let i = 0; i < 32; i++) seed[i] = i;

        const seedPtr = wasm.hd_alloc(32);
        writeBytes(memory, seedPtr, seed);

        const pubkeyPtr = wasm.hd_alloc(32);
        const result = wasm.hd_ed25519_pubkey_from_seed(seedPtr, pubkeyPtr, 32);
        assertEqual(result, 0, 'Should succeed');

        const pubkey = readBytes(memory, pubkeyPtr, 32);
        assertEqual(pubkey.length, 32, 'Public key length');

        wasm.hd_dealloc(seedPtr);
        wasm.hd_dealloc(pubkeyPtr);
    });

    // Ed25519 signing tests
    console.log('\n\x1b[1mEd25519 Signing:\x1b[0m');

    test('sign and verify message', () => {
        // Create a deterministic seed
        const seed = new Uint8Array(32);
        for (let i = 0; i < 32; i++) seed[i] = i;

        const seedPtr = wasm.hd_alloc(32);
        writeBytes(memory, seedPtr, seed);

        // Get public key
        const pubkeyPtr = wasm.hd_alloc(32);
        wasm.hd_ed25519_pubkey_from_seed(seedPtr, pubkeyPtr, 32);

        // Message to sign
        const message = new TextEncoder().encode('Hello, WASI!');
        const messagePtr = wasm.hd_alloc(message.length);
        writeBytes(memory, messagePtr, message);

        // Sign
        const sigPtr = wasm.hd_alloc(64);
        const signResult = wasm.hd_ed25519_sign(seedPtr, 32, messagePtr, message.length, sigPtr, 64);
        assertEqual(signResult, 64, 'Signature length');

        // Verify
        const verifyResult = wasm.hd_ed25519_verify(pubkeyPtr, 32, messagePtr, message.length, sigPtr, 64);
        assertEqual(verifyResult, 1, 'Should verify');

        wasm.hd_dealloc(seedPtr);
        wasm.hd_dealloc(pubkeyPtr);
        wasm.hd_dealloc(messagePtr);
        wasm.hd_dealloc(sigPtr);
    });

    test('reject invalid signature', () => {
        const seed = new Uint8Array(32);
        for (let i = 0; i < 32; i++) seed[i] = i;

        const seedPtr = wasm.hd_alloc(32);
        writeBytes(memory, seedPtr, seed);

        const pubkeyPtr = wasm.hd_alloc(32);
        wasm.hd_ed25519_pubkey_from_seed(seedPtr, pubkeyPtr, 32);

        const message = new TextEncoder().encode('Hello, WASI!');
        const messagePtr = wasm.hd_alloc(message.length);
        writeBytes(memory, messagePtr, message);

        // Create invalid signature (all zeros)
        const sigPtr = wasm.hd_alloc(64);
        writeBytes(memory, sigPtr, new Uint8Array(64));

        const verifyResult = wasm.hd_ed25519_verify(pubkeyPtr, 32, messagePtr, message.length, sigPtr, 64);
        assertEqual(verifyResult, 0, 'Should not verify');

        wasm.hd_dealloc(seedPtr);
        wasm.hd_dealloc(pubkeyPtr);
        wasm.hd_dealloc(messagePtr);
        wasm.hd_dealloc(sigPtr);
    });

    // X25519 tests
    console.log('\n\x1b[1mX25519 ECDH:\x1b[0m');

    test('derive X25519 public key', () => {
        const privkey = new Uint8Array(32);
        for (let i = 0; i < 32; i++) privkey[i] = i + 1;

        const privkeyPtr = wasm.hd_alloc(32);
        writeBytes(memory, privkeyPtr, privkey);

        const pubkeyPtr = wasm.hd_alloc(32);
        const result = wasm.hd_x25519_pubkey(privkeyPtr, pubkeyPtr, 32);
        assertEqual(result, 0, 'Should succeed');

        const pubkey = readBytes(memory, pubkeyPtr, 32);
        assertEqual(pubkey.length, 32, 'Public key length');

        wasm.hd_dealloc(privkeyPtr);
        wasm.hd_dealloc(pubkeyPtr);
    });

    test('X25519 key exchange', () => {
        // Alice's keys
        const alicePriv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) alicePriv[i] = i + 1;

        const alicePrivPtr = wasm.hd_alloc(32);
        writeBytes(memory, alicePrivPtr, alicePriv);

        const alicePubPtr = wasm.hd_alloc(32);
        wasm.hd_x25519_pubkey(alicePrivPtr, alicePubPtr, 32);

        // Bob's keys
        const bobPriv = new Uint8Array(32);
        for (let i = 0; i < 32; i++) bobPriv[i] = 32 - i;

        const bobPrivPtr = wasm.hd_alloc(32);
        writeBytes(memory, bobPrivPtr, bobPriv);

        const bobPubPtr = wasm.hd_alloc(32);
        wasm.hd_x25519_pubkey(bobPrivPtr, bobPubPtr, 32);

        // Alice computes shared secret
        const aliceSharedPtr = wasm.hd_alloc(32);
        const aliceResult = wasm.hd_ecdh_x25519(alicePrivPtr, bobPubPtr, aliceSharedPtr, 32);
        assertEqual(aliceResult, 0, 'Alice ECDH should succeed');

        // Bob computes shared secret
        const bobSharedPtr = wasm.hd_alloc(32);
        const bobResult = wasm.hd_ecdh_x25519(bobPrivPtr, alicePubPtr, bobSharedPtr, 32);
        assertEqual(bobResult, 0, 'Bob ECDH should succeed');

        // Shared secrets should match
        const aliceShared = readBytes(memory, aliceSharedPtr, 32);
        const bobShared = readBytes(memory, bobSharedPtr, 32);
        assertEqual(toHex(aliceShared), toHex(bobShared), 'Shared secrets should match');

        wasm.hd_dealloc(alicePrivPtr);
        wasm.hd_dealloc(alicePubPtr);
        wasm.hd_dealloc(bobPrivPtr);
        wasm.hd_dealloc(bobPubPtr);
        wasm.hd_dealloc(aliceSharedPtr);
        wasm.hd_dealloc(bobSharedPtr);
    });

    // Memory management tests
    console.log('\n\x1b[1mMemory Management:\x1b[0m');

    test('allocate and deallocate', () => {
        const ptr = wasm.hd_alloc(1024);
        assertNotEqual(ptr, 0, 'Allocation should succeed');
        wasm.hd_dealloc(ptr);
    });

    test('secure wipe', () => {
        const ptr = wasm.hd_alloc(32);
        const data = new Uint8Array(32);
        for (let i = 0; i < 32; i++) data[i] = 0xff;
        writeBytes(memory, ptr, data);

        wasm.hd_secure_wipe(ptr, 32);

        const wiped = readBytes(memory, ptr, 32);
        const sum = wiped.reduce((a, b) => a + b, 0);
        assertEqual(sum, 0, 'Memory should be zeroed');

        wasm.hd_dealloc(ptr);
    });

    // Summary
    console.log('\n\x1b[1mSummary:\x1b[0m');
    console.log(`  Total: ${passed + failed}`);
    if (failed === 0) {
        console.log(`  \x1b[32mPassed: ${passed}\x1b[0m`);
        console.log('\n\x1b[32mAll WASI tests passed!\x1b[0m\n');
    } else {
        console.log(`  \x1b[32mPassed: ${passed}\x1b[0m`);
        console.log(`  \x1b[31mFailed: ${failed}\x1b[0m`);
        process.exit(1);
    }
}

runTests().catch(e => {
    console.error('Test error:', e);
    process.exit(1);
});
