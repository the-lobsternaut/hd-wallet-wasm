/**
 * HD Wallet WASM - Isomorphic Environment Tests
 * Verifies the single-file ES module works in Node.js without node: import errors
 */

import { testAsync, assert, assertEqual, bytesToHex } from './test_all.mjs';

// Test: Module loads successfully
await testAsync('init() loads WASM module', async () => {
  const { default: init } = await import('../src/index.mjs');
  const wallet = await init();
  assert(wallet, 'Module should initialize');
  assert(wallet.mnemonic, 'Module should have mnemonic API');
  assert(wallet.hdkey, 'Module should have hdkey API');
  assert(wallet.curves, 'Module should have curves API');
});

// Test: Single-file build has no node: imports
await testAsync('dist/hd-wallet.js contains no node: protocol imports', async () => {
  const fs = await import('fs');
  const content = fs.readFileSync(new URL('../dist/hd-wallet.js', import.meta.url), 'utf-8');
  const nodeImports = content.match(/['"]node:[a-z]+['"]/g) || [];
  assertEqual(nodeImports.length, 0, `Found node: imports: ${nodeImports.join(', ')}`);
});

// Test: Direct WASM module import works
await testAsync('direct dist/hd-wallet.js import works', async () => {
  const { default: HDWalletWasm } = await import('../dist/hd-wallet.js');
  assert(typeof HDWalletWasm === 'function', 'Should export a factory function');
  const wasm = await HDWalletWasm();
  assert(wasm, 'Factory should return initialized module');
  assert(typeof wasm.ccall === 'function', 'Should have ccall');
});

// Test: Full workflow (mnemonic -> seed -> key derivation)
await testAsync('full wallet workflow works', async () => {
  const { default: init } = await import('../src/index.mjs');
  const wallet = await init();

  // Inject entropy
  const entropy = new Uint8Array(32);
  crypto.getRandomValues(entropy);
  wallet.injectEntropy(entropy);

  // Generate mnemonic
  const mnemonic = wallet.mnemonic.generate(12);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 12, 'Should generate 12 words');

  // Validate
  assert(wallet.mnemonic.validate(mnemonic), 'Mnemonic should be valid');

  // To seed
  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  // Create HD key
  const masterKey = wallet.hdkey.fromSeed(seed);
  assert(masterKey, 'Should create master key');

  // Derive child
  const child = masterKey.derivePath("m/44'/0'/0'/0/0");
  assert(child, 'Should derive child key');
  const pubkey = child.publicKey();
  assert(pubkey.length === 33, 'Public key should be 33 bytes (compressed)');
});

// Test: Package exports structure
await testAsync('package exports are correct', async () => {
  const mod = await import('../src/index.mjs');
  assert(typeof mod.default === 'function', 'Should have default export (init)');
  assert(typeof mod.createHDWallet === 'function', 'Should export createHDWallet');
  assert(typeof mod.HDKey === 'function', 'Should export HDKey class');
  assert(mod.Curve, 'Should export Curve enum');
  assert(mod.CoinType, 'Should export CoinType enum');
  assert(mod.Language, 'Should export Language enum');
});
