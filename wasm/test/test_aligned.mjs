/**
 * Test suite for Aligned Binary API
 *
 * Tests the efficient batch operations for key derivation, signing, and verification.
 */

import init from '../src/index.mjs';

// Test data
const TEST_SEED = new Uint8Array(64);
// Initialize with deterministic values for testing
for (let i = 0; i < 64; i++) {
  TEST_SEED[i] = i;
}

async function runTests() {
  console.log('=== Aligned Binary API Tests ===\n');

  let passed = 0;
  let failed = 0;

  function test(name, fn) {
    try {
      fn();
      console.log(`PASS: ${name}`);
      passed++;
    } catch (e) {
      console.log(`FAIL: ${name}`);
      console.log(`  Error: ${e.message}`);
      failed++;
    }
  }

  function assertEqual(actual, expected, msg = '') {
    if (actual !== expected) {
      throw new Error(`${msg}: expected ${expected}, got ${actual}`);
    }
  }

  function assertArrayEqual(actual, expected, msg = '') {
    if (actual.length !== expected.length) {
      throw new Error(`${msg}: length mismatch (${actual.length} vs ${expected.length})`);
    }
    for (let i = 0; i < actual.length; i++) {
      if (actual[i] !== expected[i]) {
        throw new Error(`${msg}: mismatch at index ${i}`);
      }
    }
  }

  // Initialize module
  console.log('Initializing HD Wallet WASM module...\n');
  const wallet = await init();

  // Inject entropy for deterministic tests
  wallet.injectEntropy(TEST_SEED);

  // Get version
  console.log(`Version: ${wallet.getVersion()}`);
  console.log(`Crypto++: ${wallet.hasCryptopp()}`);
  console.log();

  // Create master key
  const masterKey = wallet.hdkey.fromSeed(TEST_SEED);
  console.log(`Master xpub: ${masterKey.toXpub().slice(0, 40)}...`);
  console.log();

  // ==========================================================================
  // Aligned API Tests
  // ==========================================================================

  console.log('--- Aligned API Access ---');

  test('aligned property exists', () => {
    assertEqual(typeof wallet.aligned, 'object', 'aligned should be an object');
  });

  test('keyDeriver exists', () => {
    assertEqual(typeof wallet.aligned.keyDeriver, 'object', 'keyDeriver should exist');
  });

  test('signer exists', () => {
    assertEqual(typeof wallet.aligned.signer, 'object', 'signer should exist');
  });

  console.log('\n--- Batch Key Derivation ---');

  test('deriveBatch returns array', () => {
    const keys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 0, 5);
    assertEqual(Array.isArray(keys), true, 'should return array');
    assertEqual(keys.length, 5, 'should return 5 keys');
  });

  test('deriveBatch keys have correct indices', () => {
    const keys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 10, 3);
    assertEqual(keys[0].index, 10, 'first key index');
    assertEqual(keys[1].index, 11, 'second key index');
    assertEqual(keys[2].index, 12, 'third key index');
  });

  test('deriveBatch keys have public keys', () => {
    const keys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 0, 2);
    assertEqual(keys[0].publicKey !== null, true, 'should have public key');
    assertEqual(keys[0].publicKey.length, 33, 'public key should be 33 bytes');
  });

  test('deriveBatch keys have private keys', () => {
    const keys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 0, 2);
    assertEqual(keys[0].privateKey !== null, true, 'should have private key');
    assertEqual(keys[0].privateKey.length, 32, 'private key should be 32 bytes');
  });

  test('deriveBatch matches regular derivation', () => {
    const batchKeys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 0, 3);
    for (let i = 0; i < 3; i++) {
      const regularKey = masterKey.deriveChild(i);
      assertArrayEqual(
        batchKeys[i].publicKey,
        regularKey.publicKey(),
        `key ${i} public key mismatch`
      );
    }
  });

  test('deriveBatch hardened derivation', () => {
    const keys = wallet.aligned.keyDeriver.deriveBatch(masterKey, 0, 2, true);
    // Hardened derivation should also work
    assertEqual(keys.length, 2, 'should return 2 keys');
    assertEqual(keys[0].publicKey !== null, true, 'should have public key');
  });

  console.log('\n--- Streaming Key Derivation ---');

  test('streamKeys yields batches', () => {
    let batchCount = 0;
    let keyCount = 0;
    for (const batch of wallet.aligned.keyDeriver.streamKeys(masterKey, 0, 10)) {
      batchCount++;
      keyCount += batch.length;
      if (batchCount >= 2) break; // Only test first 2 batches
    }
    assertEqual(batchCount, 2, 'should yield 2 batches');
    assertEqual(keyCount, 20, 'should yield 20 keys total');
  });

  console.log('\n--- Struct Sizes ---');

  test('derivedKeyEntrySize is valid', () => {
    const size = wallet.aligned.derivedKeyEntrySize;
    assertEqual(typeof size, 'number', 'should be a number');
    assertEqual(size > 0, true, 'should be positive');
  });

  test('extendedKeyDataSize is valid', () => {
    const size = wallet.aligned.extendedKeyDataSize;
    assertEqual(typeof size, 'number', 'should be a number');
    assertEqual(size > 0, true, 'should be positive');
  });

  // ==========================================================================
  // Summary
  // ==========================================================================

  console.log('\n=== Test Summary ===');
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${passed + failed}`);

  // Cleanup
  masterKey.wipe();

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});
