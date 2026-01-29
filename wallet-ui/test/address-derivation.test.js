import { describe, it, expect } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import {
  toHexCompact,
  toHex,
  hexToBytes,
  ensureUint8Array,
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  deriveEthAddress,
  deriveSuiAddress,
  deriveMonadAddress,
  deriveCardanoAddress,
  generateAddresses,
  generateAddressForCoin,
  truncateAddress,
} from '../src/address-derivation.js';

// =============================================================================
// Test Fixtures
// =============================================================================

// Known secp256k1 private key for deterministic tests
const SECP256K1_PRIVKEY = hexToBytes(
  'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35'
);
const SECP256K1_PUBKEY = secp256k1.getPublicKey(SECP256K1_PRIVKEY, true);
const SECP256K1_PUBKEY_UNCOMPRESSED = secp256k1.getPublicKey(SECP256K1_PRIVKEY, false);

// Known ed25519 private key
const ED25519_PRIVKEY = hexToBytes(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
);
const ED25519_PUBKEY = ed25519.getPublicKey(ED25519_PRIVKEY);

// =============================================================================
// Utility Tests
// =============================================================================

describe('Utility Helpers', () => {
  it('toHexCompact converts bytes to hex', () => {
    expect(toHexCompact(new Uint8Array([0, 1, 15, 255]))).toBe('00010fff');
  });

  it('toHex is alias for toHexCompact', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    expect(toHex(bytes)).toBe(toHexCompact(bytes));
    expect(toHex(bytes)).toBe('deadbeef');
  });

  it('hexToBytes converts hex to Uint8Array', () => {
    const bytes = hexToBytes('deadbeef');
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(4);
    expect(bytes[0]).toBe(0xde);
    expect(bytes[3]).toBe(0xef);
  });

  it('hexToBytes and toHexCompact roundtrip', () => {
    const hex = 'a1b2c3d4e5f6';
    expect(toHexCompact(hexToBytes(hex))).toBe(hex);
  });

  it('ensureUint8Array handles Uint8Array input', () => {
    const arr = new Uint8Array([1, 2, 3]);
    expect(ensureUint8Array(arr)).toBe(arr);
  });

  it('ensureUint8Array handles plain object (localStorage deserialization)', () => {
    const obj = { 0: 1, 1: 2, 2: 3 };
    const result = ensureUint8Array(obj);
    expect(result).toBeInstanceOf(Uint8Array);
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  it('truncateAddress shortens long addresses', () => {
    const addr = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
    expect(truncateAddress(addr)).toBe('1A1zP1eP...DivfNa');
  });

  it('truncateAddress leaves short strings unchanged', () => {
    expect(truncateAddress('short')).toBe('short');
  });
});

// =============================================================================
// Bitcoin Address Tests
// =============================================================================

describe('Bitcoin Address Generation', () => {
  it('generates a valid P2PKH address from compressed pubkey', () => {
    const addr = generateBtcAddress(SECP256K1_PUBKEY);
    expect(addr).toMatch(/^1[1-9A-HJ-NP-Za-km-z]{25,34}$/);
  });

  it('generates deterministic address', () => {
    const addr1 = generateBtcAddress(SECP256K1_PUBKEY);
    const addr2 = generateBtcAddress(SECP256K1_PUBKEY);
    expect(addr1).toBe(addr2);
  });

  it('different keys produce different addresses', () => {
    const otherPriv = hexToBytes(
      '0000000000000000000000000000000000000000000000000000000000000001'
    );
    const otherPub = secp256k1.getPublicKey(otherPriv, true);
    expect(generateBtcAddress(SECP256K1_PUBKEY)).not.toBe(
      generateBtcAddress(otherPub)
    );
  });
});

// =============================================================================
// Ethereum Address Tests
// =============================================================================

describe('Ethereum Address Generation', () => {
  it('generates address with 0x prefix', () => {
    const addr = generateEthAddress(SECP256K1_PUBKEY);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('generates deterministic address', () => {
    const addr1 = generateEthAddress(SECP256K1_PUBKEY);
    const addr2 = generateEthAddress(SECP256K1_PUBKEY);
    expect(addr1).toBe(addr2);
  });

  it('deriveEthAddress handles compressed key (33 bytes)', () => {
    const addr = deriveEthAddress(SECP256K1_PUBKEY);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('deriveEthAddress handles uncompressed key (65 bytes)', () => {
    const addr = deriveEthAddress(SECP256K1_PUBKEY_UNCOMPRESSED);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('deriveEthAddress handles raw key (64 bytes)', () => {
    const raw64 = SECP256K1_PUBKEY_UNCOMPRESSED.slice(1); // remove 04 prefix
    const addr = deriveEthAddress(raw64);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('compressed and uncompressed produce same address', () => {
    const fromCompressed = deriveEthAddress(SECP256K1_PUBKEY);
    const fromUncompressed = deriveEthAddress(SECP256K1_PUBKEY_UNCOMPRESSED);
    expect(fromCompressed).toBe(fromUncompressed);
  });

  it('deriveEthAddress returns null for invalid key length', () => {
    expect(deriveEthAddress(new Uint8Array(10))).toBeNull();
  });
});

// =============================================================================
// Solana Address Tests
// =============================================================================

describe('Solana Address Generation', () => {
  it('generates a Base58 address', () => {
    const addr = generateSolAddress(ED25519_PUBKEY);
    expect(addr).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
    expect(addr.length).toBeGreaterThan(30);
  });

  it('generates deterministic address', () => {
    expect(generateSolAddress(ED25519_PUBKEY)).toBe(
      generateSolAddress(ED25519_PUBKEY)
    );
  });
});

// =============================================================================
// SUI Address Tests
// =============================================================================

describe('SUI Address Generation', () => {
  it('generates address with 0x prefix', () => {
    const addr = deriveSuiAddress(ED25519_PUBKEY, 'ed25519');
    expect(addr).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('different schemes produce different addresses', () => {
    const ed = deriveSuiAddress(ED25519_PUBKEY, 'ed25519');
    const secp = deriveSuiAddress(ED25519_PUBKEY, 'secp256k1');
    expect(ed).not.toBe(secp);
  });

  it('defaults to ed25519 scheme', () => {
    const withDefault = deriveSuiAddress(ED25519_PUBKEY);
    const withExplicit = deriveSuiAddress(ED25519_PUBKEY, 'ed25519');
    expect(withDefault).toBe(withExplicit);
  });
});

// =============================================================================
// Monad Address Tests
// =============================================================================

describe('Monad Address Generation', () => {
  it('generates address with 0x prefix from compressed key', () => {
    const addr = deriveMonadAddress(SECP256K1_PUBKEY);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('generates address from uncompressed key', () => {
    const addr = deriveMonadAddress(SECP256K1_PUBKEY_UNCOMPRESSED);
    expect(addr).toMatch(/^0x[0-9a-f]{40}$/);
  });

  it('compressed and uncompressed produce same address', () => {
    const c = deriveMonadAddress(SECP256K1_PUBKEY);
    const u = deriveMonadAddress(SECP256K1_PUBKEY_UNCOMPRESSED);
    expect(c).toBe(u);
  });

  it('throws for invalid key length', () => {
    expect(() => deriveMonadAddress(new Uint8Array(10))).toThrow();
  });
});

// =============================================================================
// Cardano Address Tests
// =============================================================================

describe('Cardano Address Generation', () => {
  it('generates bech32 address with addr prefix', () => {
    const addr = deriveCardanoAddress(ED25519_PUBKEY);
    expect(addr).toMatch(/^addr1[a-z0-9]+$/);
  });

  it('generates deterministic address', () => {
    expect(deriveCardanoAddress(ED25519_PUBKEY)).toBe(
      deriveCardanoAddress(ED25519_PUBKEY)
    );
  });
});

// =============================================================================
// Composite Address Generation
// =============================================================================

describe('generateAddresses', () => {
  it('generates btc, eth, and sol from wallet keys', () => {
    const wallet = {
      secp256k1: { publicKey: SECP256K1_PUBKEY },
      ed25519: { publicKey: ED25519_PUBKEY },
    };
    const addrs = generateAddresses(wallet);
    expect(addrs.btc).toMatch(/^1/);
    expect(addrs.eth).toMatch(/^0x/);
    expect(addrs.sol).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
  });
});

describe('generateAddressForCoin', () => {
  it('generates BTC address for coin type 0', () => {
    const addr = generateAddressForCoin(SECP256K1_PUBKEY, 0);
    expect(addr).toMatch(/^1/);
  });

  it('generates ETH address for coin type 60', () => {
    const addr = generateAddressForCoin(SECP256K1_PUBKEY, 60);
    expect(addr).toMatch(/^0x/);
  });

  it('returns hex for unknown coin type', () => {
    const addr = generateAddressForCoin(SECP256K1_PUBKEY, 99999);
    expect(addr).toMatch(/^[0-9a-f]+$/);
  });
});
