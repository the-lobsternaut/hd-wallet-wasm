/**
 * EPM Attestation - Content signing and chain binding proof utilities
 *
 * Provides functions to sign EPM (Entity Profile Message) content and
 * build/verify chain binding proofs that link blockchain keys to the
 * same HD wallet identity.
 *
 * These functions operate on JSON representations of EPM data and
 * require an initialized HDWalletModule for crypto operations.
 *
 * @module epm-attestation
 */

// =============================================================================
// Canonical Payload
// =============================================================================

/**
 * Build a canonical attestation payload for chain proof signing.
 * This is the message that each chain key signs to prove common wallet origin.
 *
 * The payload is a deterministic JSON string (sorted keys) containing:
 * - version: attestation format version
 * - xpub: BIP-32 extended public key (account-level identity)
 * - signing_pubkey_hex: Ed25519 signing public key
 * - encryption_pubkey_hex: X25519 encryption public key
 * - issued_at: Unix timestamp (seconds)
 *
 * @param {Object} params
 * @param {string} params.xpub - BIP-32 extended public key
 * @param {string} params.signingPubKeyHex - Ed25519 signing public key (hex)
 * @param {string} params.encryptionPubKeyHex - X25519 encryption public key (hex)
 * @param {number} params.issuedAt - Unix timestamp in seconds
 * @param {string} [params.identityPubKeyHex] - secp256k1 identity public key (hex)
 * @param {string} [params.version='1'] - Attestation format version
 * @returns {string} Canonical JSON string (deterministic, sorted keys)
 */
export function buildCanonicalPayload({
  xpub,
  signingPubKeyHex,
  encryptionPubKeyHex,
  issuedAt,
  identityPubKeyHex = '',
  version = '1',
}) {
  const payload = {
    encryption_pubkey_hex: encryptionPubKeyHex,
    identity_pubkey_hex: identityPubKeyHex,
    issued_at: issuedAt,
    signing_pubkey_hex: signingPubKeyHex,
    version,
    xpub,
  };
  // Keys are alphabetically sorted by construction
  return JSON.stringify(payload);
}

// =============================================================================
// EPM Content Signing
// =============================================================================

/**
 * Build a canonical representation of EPM fields for content signing.
 * Excludes SIGNATURE and SIGNATURE_TIMESTAMP (those are the signature itself).
 * Includes CHAIN_PROOFS since they are part of the signed content.
 *
 * @param {Object} epm - EPM fields as a plain object
 * @returns {Uint8Array} UTF-8 encoded canonical representation
 */
export function buildEPMSigningContent(epm) {
  // Extract all EPM fields except SIGNATURE and SIGNATURE_TIMESTAMP
  const {
    SIGNATURE: _sig,
    SIGNATURE_TIMESTAMP: _ts,
    signature: _sig2,
    signature_timestamp: _ts2,
    ...contentFields
  } = epm;

  // Sort keys for deterministic output
  const sorted = Object.keys(contentFields)
    .sort()
    .reduce((obj, key) => {
      obj[key] = contentFields[key];
      return obj;
    }, {});

  const canonical = JSON.stringify(sorted);
  return new TextEncoder().encode(canonical);
}

/**
 * Sign EPM content with an Ed25519 private key.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} epm - EPM fields as a plain object (without SIGNATURE/SIGNATURE_TIMESTAMP)
 * @param {Uint8Array} ed25519PrivateKey - 32-byte Ed25519 private key (seed)
 * @returns {{ signature: string, timestamp: number }} Hex signature and Unix timestamp
 */
export function signEPMContent(wallet, epm, ed25519PrivateKey) {
  const timestamp = Math.floor(Date.now() / 1000);
  const content = buildEPMSigningContent({ ...epm, SIGNATURE_TIMESTAMP: timestamp });
  const sig = wallet.curves.ed25519.sign(content, ed25519PrivateKey);
  return {
    signature: wallet.utils.encodeHex(sig),
    timestamp,
  };
}

/**
 * Verify an EPM content signature.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} epm - Full EPM object including SIGNATURE and SIGNATURE_TIMESTAMP
 * @param {Uint8Array} ed25519PublicKey - 32-byte Ed25519 public key
 * @returns {boolean} True if signature is valid
 */
export function verifyEPMSignature(wallet, epm, ed25519PublicKey) {
  const sigHex = epm.SIGNATURE || epm.signature;
  if (!sigHex) return false;

  const content = buildEPMSigningContent(epm);
  const sig = wallet.utils.decodeHex(sigHex);
  return wallet.curves.ed25519.verify(content, sig, ed25519PublicKey);
}

// =============================================================================
// Chain Proof Building
// =============================================================================

/**
 * Build a Bitcoin chain proof.
 * Signs the canonical payload with secp256k1 using Bitcoin message signing format.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} params
 * @param {string} params.address - Bitcoin address
 * @param {string} params.publicKeyHex - Compressed secp256k1 public key (hex)
 * @param {Uint8Array} params.privateKey - 32-byte secp256k1 private key
 * @param {string} params.keyPath - BIP-44 derivation path
 * @param {string} params.canonicalPayload - Result of buildCanonicalPayload()
 * @returns {Object} ChainProof object
 */
export function buildBitcoinChainProof(wallet, { address, publicKeyHex, privateKey, keyPath, canonicalPayload }) {
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const payloadHash = wallet.utils.sha256(payloadBytes);
  const sig = wallet.curves.secp256k1.signRecoverable
    ? wallet.curves.secp256k1.signRecoverable(payloadHash, privateKey)
    : wallet.curves.secp256k1.sign(payloadHash, privateKey);

  return {
    CHAIN: 'bitcoin',
    ADDRESS: address,
    PUBLIC_KEY: publicKeyHex,
    KEY_PATH: keyPath,
    SIGNATURE: wallet.utils.encodeHex(sig),
    SIGNED_PAYLOAD: wallet.utils.encodeHex(payloadBytes),
    ALGORITHM: 'secp256k1-compact-bitcoin',
    ENCODING: 'compact',
  };
}

/**
 * Build an Ethereum chain proof.
 * Signs the canonical payload with secp256k1 using Ethereum personal_sign prefix.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} params
 * @param {string} params.address - Ethereum address (0x-prefixed)
 * @param {string} params.publicKeyHex - Compressed secp256k1 public key (hex)
 * @param {Uint8Array} params.privateKey - 32-byte secp256k1 private key
 * @param {string} params.keyPath - BIP-44 derivation path
 * @param {string} params.canonicalPayload - Result of buildCanonicalPayload()
 * @returns {Object} ChainProof object
 */
export function buildEthereumChainProof(wallet, { address, publicKeyHex, privateKey, keyPath, canonicalPayload }) {
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const payloadHash = wallet.utils.sha256(payloadBytes);
  const sig = wallet.curves.secp256k1.signRecoverable
    ? wallet.curves.secp256k1.signRecoverable(payloadHash, privateKey)
    : wallet.curves.secp256k1.sign(payloadHash, privateKey);

  return {
    CHAIN: 'ethereum',
    ADDRESS: address,
    PUBLIC_KEY: publicKeyHex,
    KEY_PATH: keyPath,
    SIGNATURE: wallet.utils.encodeHex(sig),
    SIGNED_PAYLOAD: wallet.utils.encodeHex(payloadBytes),
    ALGORITHM: 'secp256k1-compact-ethereum',
    ENCODING: 'compact',
  };
}

/**
 * Build a Solana chain proof.
 * Signs the canonical payload with Ed25519.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} params
 * @param {string} params.address - Solana address (base58)
 * @param {string} params.publicKeyHex - Ed25519 public key (hex)
 * @param {Uint8Array} params.privateKey - 32-byte Ed25519 private key (seed)
 * @param {string} params.keyPath - BIP-44 derivation path
 * @param {string} params.canonicalPayload - Result of buildCanonicalPayload()
 * @returns {Object} ChainProof object
 */
export function buildSolanaChainProof(wallet, { address, publicKeyHex, privateKey, keyPath, canonicalPayload }) {
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const sig = wallet.curves.ed25519.sign(payloadBytes, privateKey);

  return {
    CHAIN: 'solana',
    ADDRESS: address,
    PUBLIC_KEY: publicKeyHex,
    KEY_PATH: keyPath,
    SIGNATURE: wallet.utils.encodeHex(sig),
    SIGNED_PAYLOAD: wallet.utils.encodeHex(payloadBytes),
    ALGORITHM: 'ed25519',
    ENCODING: 'raw-ed25519',
  };
}

// =============================================================================
// Chain Proof Verification
// =============================================================================

/**
 * Verify a single chain proof.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} proof - ChainProof object with CHAIN, PUBLIC_KEY, SIGNATURE, SIGNED_PAYLOAD, ALGORITHM
 * @returns {boolean} True if the signature is valid for the given public key and payload
 */
export function verifyChainProof(wallet, proof) {
  const pubKey = wallet.utils.decodeHex(proof.PUBLIC_KEY);
  const sig = wallet.utils.decodeHex(proof.SIGNATURE);
  const payload = wallet.utils.decodeHex(proof.SIGNED_PAYLOAD);

  const algorithm = proof.ALGORITHM;

  if (algorithm === 'ed25519' || algorithm === 'raw-ed25519') {
    return wallet.curves.ed25519.verify(payload, sig, pubKey);
  }

  if (algorithm === 'secp256k1-compact-bitcoin' || algorithm === 'secp256k1-compact-ethereum') {
    const payloadHash = wallet.utils.sha256(payload);
    return wallet.curves.secp256k1.verify(payloadHash, sig, pubKey);
  }

  return false;
}

/**
 * Verify all chain proofs in an EPM.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object[]} chainProofs - Array of ChainProof objects
 * @returns {{ valid: boolean, results: Array<{ chain: string, valid: boolean }> }}
 */
export function verifyAllChainProofs(wallet, chainProofs) {
  if (!chainProofs || chainProofs.length === 0) {
    return { valid: false, results: [] };
  }

  const results = chainProofs.map((proof) => ({
    chain: proof.CHAIN,
    valid: verifyChainProof(wallet, proof),
  }));

  return {
    valid: results.every((r) => r.valid),
    results,
  };
}

/**
 * Build all chain proofs for a full identity attestation.
 *
 * @param {Object} wallet - Initialized HDWalletModule
 * @param {Object} params
 * @param {string} params.canonicalPayload - Result of buildCanonicalPayload()
 * @param {Object} params.bitcoin - { address, publicKeyHex, privateKey, keyPath }
 * @param {Object} params.ethereum - { address, publicKeyHex, privateKey, keyPath }
 * @param {Object} params.solana - { address, publicKeyHex, privateKey, keyPath }
 * @returns {Object[]} Array of ChainProof objects
 */
export function buildAllChainProofs(wallet, { canonicalPayload, bitcoin, ethereum, solana }) {
  const proofs = [];

  if (bitcoin) {
    proofs.push(buildBitcoinChainProof(wallet, { ...bitcoin, canonicalPayload }));
  }
  if (ethereum) {
    proofs.push(buildEthereumChainProof(wallet, { ...ethereum, canonicalPayload }));
  }
  if (solana) {
    proofs.push(buildSolanaChainProof(wallet, { ...solana, canonicalPayload }));
  }

  return proofs;
}
