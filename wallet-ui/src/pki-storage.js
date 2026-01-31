/**
 * PKI Storage Module
 *
 * Encrypted persistence for trust policies, organizations, and PKI state.
 * Uses AES-256-GCM via WebCrypto. Supports EME FlatBuffer export/import
 * and vCard X-TRUST-POLICY embedding.
 */

import { buildEME, parseEME, bufferToBase64, base64ToBuffer } from './sds-bridge.js';

const PKI_STORAGE_KEY = 'wallet_pki_data';

// =============================================================================
// In-Memory State
// =============================================================================

let _state = null;

function emptyState() {
  return {
    organizations: [],
    identities: [],
    policies: [],
    certificates: [],
    version: 1,
    updatedAt: Date.now(),
  };
}

export function getState() {
  if (!_state) _state = emptyState();
  return _state;
}

export function clearState() {
  _state = null;
}

// =============================================================================
// Encrypt / Decrypt helpers (WebCrypto AES-256-GCM)
// =============================================================================

async function encrypt(data, keyMaterial) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(data));

  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt']
  );

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, cryptoKey, plaintext
  );

  return { ciphertext: new Uint8Array(ciphertext), iv };
}

async function decrypt(ciphertext, iv, keyMaterial) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyMaterial, { name: 'AES-GCM' }, false, ['decrypt']
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, cryptoKey, ciphertext
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}

// =============================================================================
// Derive a PKI-specific key from wallet key material
// =============================================================================

async function derivePKIKey(walletKeyMaterial) {
  const salt = new TextEncoder().encode('pki-storage-v1');
  const ikm = await crypto.subtle.importKey(
    'raw', walletKeyMaterial, 'HKDF', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('pki-enc') },
    ikm, 256
  );
  return new Uint8Array(bits);
}

// =============================================================================
// localStorage Persistence (encrypted)
// =============================================================================

/**
 * Save current PKI state encrypted to localStorage.
 * @param {Uint8Array} walletKeyMaterial — 32-byte key material from wallet auth
 */
export async function saveState(walletKeyMaterial) {
  const state = getState();
  state.updatedAt = Date.now();
  const key = await derivePKIKey(walletKeyMaterial);
  const { ciphertext, iv } = await encrypt(state, key);

  localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify({
    ct: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv),
  }));
}

/**
 * Load PKI state from encrypted localStorage.
 * @param {Uint8Array} walletKeyMaterial
 * @returns {Object} PKI state
 */
export async function loadState(walletKeyMaterial) {
  const raw = localStorage.getItem(PKI_STORAGE_KEY);
  if (!raw) {
    _state = emptyState();
    return _state;
  }
  const { ct, iv } = JSON.parse(raw);
  const key = await derivePKIKey(walletKeyMaterial);
  try {
    _state = await decrypt(base64ToBuffer(ct), base64ToBuffer(iv), key);
  } catch {
    _state = emptyState();
  }
  return _state;
}

// =============================================================================
// EME Export / Import (encrypted FlatBuffer)
// =============================================================================

/**
 * Export a trust policy (or full PKI state) as an EME FlatBuffer.
 * @param {Object} data — policy or full state object
 * @param {Uint8Array} encryptionKey — 32-byte AES key (user-provided or derived)
 * @returns {Uint8Array} EME FlatBuffer binary
 */
export async function exportAsEME(data, encryptionKey) {
  const { ciphertext, iv } = await encrypt(data, encryptionKey);
  return buildEME(ciphertext, {
    iv: bufferToBase64(iv),
    cipherSuite: 'AES-256-GCM',
  });
}

/**
 * Import from an EME FlatBuffer.
 * @param {Uint8Array} emeBuffer — EME FlatBuffer binary
 * @param {Uint8Array} decryptionKey — 32-byte AES key
 * @returns {Object} Decrypted data
 */
export async function importFromEME(emeBuffer, decryptionKey) {
  const eme = parseEME(emeBuffer);
  const iv = base64ToBuffer(eme.iv);
  return decrypt(eme.ciphertext, iv, decryptionKey);
}

// =============================================================================
// Password-based EME (PBKDF2 → AES key)
// =============================================================================

/**
 * Derive AES-256 key from a password via PBKDF2.
 * @returns {{ key: Uint8Array, salt: Uint8Array }}
 */
export async function deriveKeyFromPassword(password, existingSalt) {
  const salt = existingSalt || crypto.getRandomValues(new Uint8Array(16));
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
    km, 256
  );
  return { key: new Uint8Array(bits), salt };
}

/**
 * Export data as password-protected EME.
 */
export async function exportAsPasswordEME(data, password) {
  const { key, salt } = await deriveKeyFromPassword(password);
  const { ciphertext, iv } = await encrypt(data, key);
  return buildEME(ciphertext, {
    iv: bufferToBase64(iv),
    cipherSuite: 'AES-256-GCM',
    kdfParams: JSON.stringify({ alg: 'PBKDF2', hash: 'SHA-256', iterations: 100000, salt: bufferToBase64(salt) }),
  });
}

/**
 * Import from password-protected EME.
 */
export async function importFromPasswordEME(emeBuffer, password) {
  const eme = parseEME(emeBuffer);
  const kdf = JSON.parse(eme.kdfParams);
  const { key } = await deriveKeyFromPassword(password, base64ToBuffer(kdf.salt));
  const iv = base64ToBuffer(eme.iv);
  return decrypt(eme.ciphertext, iv, key);
}

// =============================================================================
// vCard X-TRUST-POLICY embedding
// =============================================================================

/**
 * Encode PKI policies as base64 EME for vCard embedding.
 */
export async function encodePoliciesForVCard(policies, encryptionKey) {
  const emeBytes = await exportAsEME({ policies }, encryptionKey);
  return bufferToBase64(emeBytes);
}

/**
 * Decode PKI policies from vCard X-TRUST-POLICY value.
 */
export async function decodePoliciesFromVCard(base64Value, decryptionKey) {
  const emeBytes = base64ToBuffer(base64Value);
  const data = await importFromEME(emeBytes, decryptionKey);
  return data.policies || [];
}

// =============================================================================
// JSON Export/Import (plaintext, for debugging)
// =============================================================================

export function exportAsJSON(data) {
  return JSON.stringify(data, null, 2);
}

export function importFromJSON(jsonStr) {
  return JSON.parse(jsonStr);
}
