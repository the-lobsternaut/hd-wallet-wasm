import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { hexToBytes } from '../src/address-derivation.js';

// =============================================================================
// Test Fixtures — mirrors the onLogin callback contract from app.js login()
// =============================================================================

// Deterministic ed25519 key pair (simulates SDN coin-type 1957 signing key)
const SDN_PRIVKEY = hexToBytes(
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
);
const SDN_PUBKEY = ed25519.getPublicKey(SDN_PRIVKEY);

/**
 * Replicates the `sign` method attached to the onLogin callback payload.
 * See app.js login() — the callback receives { xpub, signingPublicKey, sign }.
 */
async function callbackSign(message, privateKey) {
  const msgBytes = typeof message === 'string'
    ? new TextEncoder().encode(message)
    : message;
  return ed25519.sign(msgBytes, privateKey);
}

// =============================================================================
// onLogin Callback Shape
// =============================================================================

describe('onLogin callback payload shape', () => {
  it('signingPublicKey is a 32-byte Uint8Array', () => {
    expect(SDN_PUBKEY).toBeInstanceOf(Uint8Array);
    expect(SDN_PUBKEY.length).toBe(32);
  });

  it('sign function returns a 64-byte ed25519 signature', async () => {
    const sig = await callbackSign('hello', SDN_PRIVKEY);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
  });
});

// =============================================================================
// sign() — string messages
// =============================================================================

describe('onLogin sign() with string messages', () => {
  it('produces a verifiable signature for a string', async () => {
    const message = 'authenticate me';
    const sig = await callbackSign(message, SDN_PRIVKEY);
    const msgBytes = new TextEncoder().encode(message);
    expect(ed25519.verify(sig, msgBytes, SDN_PUBKEY)).toBe(true);
  });

  it('produces deterministic signatures', async () => {
    const sig1 = await callbackSign('deterministic', SDN_PRIVKEY);
    const sig2 = await callbackSign('deterministic', SDN_PRIVKEY);
    expect(sig1).toEqual(sig2);
  });

  it('different messages produce different signatures', async () => {
    const sig1 = await callbackSign('message-a', SDN_PRIVKEY);
    const sig2 = await callbackSign('message-b', SDN_PRIVKEY);
    expect(sig1).not.toEqual(sig2);
  });

  it('handles empty string', async () => {
    const sig = await callbackSign('', SDN_PRIVKEY);
    const msgBytes = new TextEncoder().encode('');
    expect(ed25519.verify(sig, msgBytes, SDN_PUBKEY)).toBe(true);
  });

  it('handles unicode strings', async () => {
    const message = 'héllo wörld 🌍';
    const sig = await callbackSign(message, SDN_PRIVKEY);
    const msgBytes = new TextEncoder().encode(message);
    expect(ed25519.verify(sig, msgBytes, SDN_PUBKEY)).toBe(true);
  });
});

// =============================================================================
// sign() — Uint8Array messages
// =============================================================================

describe('onLogin sign() with Uint8Array messages', () => {
  it('signs raw bytes and produces verifiable signature', async () => {
    const msgBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const sig = await callbackSign(msgBytes, SDN_PRIVKEY);
    expect(ed25519.verify(sig, msgBytes, SDN_PUBKEY)).toBe(true);
  });

  it('string and equivalent bytes produce the same signature', async () => {
    const str = 'hello';
    const bytes = new TextEncoder().encode(str);
    const sigStr = await callbackSign(str, SDN_PRIVKEY);
    const sigBytes = await callbackSign(bytes, SDN_PRIVKEY);
    expect(sigStr).toEqual(sigBytes);
  });
});

// =============================================================================
// Signature verification — negative cases
// =============================================================================

describe('onLogin signature verification', () => {
  it('rejects signature with wrong public key', async () => {
    const otherPriv = hexToBytes(
      'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7'
    );
    const otherPub = ed25519.getPublicKey(otherPriv);
    const sig = await callbackSign('test', SDN_PRIVKEY);
    const msgBytes = new TextEncoder().encode('test');
    expect(ed25519.verify(sig, msgBytes, otherPub)).toBe(false);
  });

  it('rejects signature with tampered message', async () => {
    const sig = await callbackSign('original', SDN_PRIVKEY);
    const tampered = new TextEncoder().encode('tampered');
    expect(ed25519.verify(sig, tampered, SDN_PUBKEY)).toBe(false);
  });
});
