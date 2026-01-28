/**
 * WebCrypto Bridge - Hardware-accelerated cryptographic operations
 *
 * These functions use the browser's native WebCrypto API for
 * hardware-accelerated, constant-time cryptographic operations.
 *
 * All functions are async because WebCrypto is Promise-based.
 */

/**
 * Check if WebCrypto is available
 * @returns {boolean}
 */
export function isWebCryptoAvailable() {
  return typeof globalThis.crypto !== 'undefined' &&
         typeof globalThis.crypto.subtle !== 'undefined';
}

/**
 * AES-GCM Encryption using WebCrypto
 * @param {Uint8Array} key - AES key (128, 192, or 256 bits = 16, 24, or 32 bytes)
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} iv - Initialization vector (12 bytes recommended for GCM)
 * @param {Uint8Array} [aad] - Additional authenticated data (optional)
 * @returns {Promise<{ciphertext: Uint8Array, tag: Uint8Array}>}
 */
export async function aesGcmEncrypt(key, plaintext, iv, aad = null) {
  if (!isWebCryptoAvailable()) {
    throw new Error('WebCrypto not available');
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const algorithmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 128 // 16 bytes
  };

  if (aad && aad.length > 0) {
    algorithmParams.additionalData = aad;
  }

  const encrypted = await crypto.subtle.encrypt(
    algorithmParams,
    cryptoKey,
    plaintext
  );

  // WebCrypto returns ciphertext + tag combined
  const fullResult = new Uint8Array(encrypted);
  const ciphertext = fullResult.slice(0, fullResult.length - 16);
  const tag = fullResult.slice(fullResult.length - 16);

  return { ciphertext, tag };
}

/**
 * AES-GCM Decryption using WebCrypto
 * @param {Uint8Array} key - AES key (128, 192, or 256 bits)
 * @param {Uint8Array} ciphertext - Encrypted data
 * @param {Uint8Array} tag - Authentication tag (16 bytes)
 * @param {Uint8Array} iv - Initialization vector used during encryption
 * @param {Uint8Array} [aad] - Additional authenticated data (must match encryption)
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 * @throws {Error} If decryption fails (invalid tag, wrong key, etc.)
 */
export async function aesGcmDecrypt(key, ciphertext, tag, iv, aad = null) {
  if (!isWebCryptoAvailable()) {
    throw new Error('WebCrypto not available');
  }

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  // Reconstruct the full ciphertext + tag format WebCrypto expects
  const encrypted = new Uint8Array(ciphertext.length + tag.length);
  encrypted.set(ciphertext, 0);
  encrypted.set(tag, ciphertext.length);

  const algorithmParams = {
    name: 'AES-GCM',
    iv: iv,
    tagLength: 128
  };

  if (aad && aad.length > 0) {
    algorithmParams.additionalData = aad;
  }

  try {
    const decrypted = await crypto.subtle.decrypt(
      algorithmParams,
      cryptoKey,
      encrypted
    );
    return new Uint8Array(decrypted);
  } catch (err) {
    throw new Error('AES-GCM decryption failed: authentication tag mismatch or invalid data');
  }
}

/**
 * HKDF using WebCrypto (SHA-256)
 * @param {Uint8Array} ikm - Input keying material
 * @param {Uint8Array} salt - Salt value (can be empty Uint8Array)
 * @param {Uint8Array} info - Context/application-specific info (can be empty)
 * @param {number} length - Desired output length in bytes
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function hkdfSha256(ikm, salt, info, length) {
  if (!isWebCryptoAvailable()) {
    throw new Error('WebCrypto not available');
  }

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt.length > 0 ? salt : new Uint8Array(32), // WebCrypto requires non-empty salt
      info: info
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * HKDF using WebCrypto (SHA-384)
 * @param {Uint8Array} ikm - Input keying material
 * @param {Uint8Array} salt - Salt value
 * @param {Uint8Array} info - Context/application-specific info
 * @param {number} length - Desired output length in bytes
 * @returns {Promise<Uint8Array>} Derived key material
 */
export async function hkdfSha384(ikm, salt, info, length) {
  if (!isWebCryptoAvailable()) {
    throw new Error('WebCrypto not available');
  }

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    ikm,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-384',
      salt: salt.length > 0 ? salt : new Uint8Array(48),
      info: info
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of random bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export function getRandomBytes(length) {
  if (!isWebCryptoAvailable()) {
    throw new Error('WebCrypto not available');
  }
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate a random AES-GCM IV (12 bytes recommended)
 * @returns {Uint8Array} 12-byte IV
 */
export function generateIv() {
  return getRandomBytes(12);
}

/**
 * Generate a random AES key
 * @param {number} [bits=256] - Key size in bits (128, 192, or 256)
 * @returns {Uint8Array} Random key
 */
export function generateAesKey(bits = 256) {
  if (![128, 192, 256].includes(bits)) {
    throw new Error('AES key size must be 128, 192, or 256 bits');
  }
  return getRandomBytes(bits / 8);
}
