/**
 * HD Wallet WASM - JavaScript ES6 Wrapper
 *
 * Comprehensive HD wallet implementation with:
 * - BIP-32/39/44/49/84 support
 * - Multi-curve cryptography (secp256k1, Ed25519, P-256, P-384, X25519)
 * - Multi-chain support (Bitcoin, Ethereum, Solana, Cosmos, Polkadot)
 * - Hardware wallet abstraction (requires bridge)
 * - Transaction building and signing
 *
 * @module hd-wallet-wasm
 * @version 0.1.0
 */

// Import aligned API for batch operations
import { AlignedAPI } from './aligned.mjs';

// =============================================================================
// Enums (matching TypeScript definitions)
// =============================================================================

/**
 * Elliptic curve types
 * @readonly
 * @enum {number}
 */
export const Curve = Object.freeze({
  SECP256K1: 0,
  ED25519: 1,
  P256: 2,
  P384: 3,
  X25519: 4
});

/**
 * SLIP-44 coin types
 * @readonly
 * @enum {number}
 */
export const CoinType = Object.freeze({
  BITCOIN: 0,
  BITCOIN_TESTNET: 1,
  LITECOIN: 2,
  DOGECOIN: 3,
  ETHEREUM: 60,
  ETHEREUM_CLASSIC: 61,
  COSMOS: 118,
  STELLAR: 148,
  BITCOIN_CASH: 145,
  POLKADOT: 354,
  KUSAMA: 434,
  SOLANA: 501,
  BINANCE: 714,
  CARDANO: 1815
});

/**
 * BIP-39 wordlist languages
 * @readonly
 * @enum {number}
 */
export const Language = Object.freeze({
  ENGLISH: 0,
  JAPANESE: 1,
  KOREAN: 2,
  SPANISH: 3,
  CHINESE_SIMPLIFIED: 4,
  CHINESE_TRADITIONAL: 5,
  FRENCH: 6,
  ITALIAN: 7,
  CZECH: 8,
  PORTUGUESE: 9
});

/**
 * WASI feature flags
 * @readonly
 * @enum {number}
 */
export const WasiFeature = Object.freeze({
  RANDOM: 0,
  FILESYSTEM: 1,
  NETWORK: 2,
  USB_HID: 3,
  CLOCK: 4,
  ENVIRONMENT: 5
});

/**
 * WASI warning codes
 * @readonly
 * @enum {number}
 */
export const WasiWarning = Object.freeze({
  NONE: 0,
  NEEDS_ENTROPY: 1,
  NEEDS_BRIDGE: 2,
  NOT_AVAILABLE_WASI: 3,
  DISABLED_FIPS: 4,
  NEEDS_CAPABILITY: 5
});

/**
 * Entropy status
 * @readonly
 * @enum {number}
 */
export const EntropyStatus = Object.freeze({
  NOT_INITIALIZED: 0,
  INITIALIZED: 1,
  SUFFICIENT: 2
});

/**
 * Bitcoin address types
 * @readonly
 * @enum {number}
 */
export const BitcoinAddressType = Object.freeze({
  P2PKH: 0,
  P2SH: 1,
  P2WPKH: 2,
  P2WSH: 3,
  P2TR: 4
});

/**
 * Network type
 * @readonly
 * @enum {number}
 */
export const Network = Object.freeze({
  MAINNET: 0,
  TESTNET: 1
});

// =============================================================================
// Error handling
// =============================================================================

/**
 * HD Wallet error codes
 * @readonly
 * @enum {number}
 */
const ErrorCode = Object.freeze({
  OK: 0,
  UNKNOWN: 1,
  INVALID_ARGUMENT: 2,
  NOT_SUPPORTED: 3,
  OUT_OF_MEMORY: 4,
  INTERNAL: 5,
  NO_ENTROPY: 100,
  INSUFFICIENT_ENTROPY: 101,
  INVALID_WORD: 200,
  INVALID_CHECKSUM: 201,
  INVALID_MNEMONIC_LENGTH: 202,
  INVALID_ENTROPY_LENGTH: 203,
  INVALID_SEED: 300,
  INVALID_PATH: 301,
  INVALID_CHILD_INDEX: 302,
  HARDENED_FROM_PUBLIC: 303,
  INVALID_EXTENDED_KEY: 304,
  INVALID_PRIVATE_KEY: 400,
  INVALID_PUBLIC_KEY: 401,
  INVALID_SIGNATURE: 402,
  VERIFICATION_FAILED: 403,
  KEY_DERIVATION_FAILED: 404,
  INVALID_TRANSACTION: 500,
  INSUFFICIENT_FUNDS: 501,
  INVALID_ADDRESS: 502,
  DEVICE_NOT_CONNECTED: 600,
  DEVICE_COMM_ERROR: 601,
  USER_CANCELLED: 602,
  DEVICE_BUSY: 603,
  DEVICE_NOT_SUPPORTED: 604,
  BRIDGE_NOT_SET: 700,
  BRIDGE_FAILED: 701,
  NEEDS_BRIDGE: 702,
  FIPS_NOT_ALLOWED: 800
});

/**
 * Error message map
 */
const ERROR_MESSAGES = {
  [ErrorCode.OK]: 'Success',
  [ErrorCode.UNKNOWN]: 'Unknown error',
  [ErrorCode.INVALID_ARGUMENT]: 'Invalid argument',
  [ErrorCode.NOT_SUPPORTED]: 'Operation not supported',
  [ErrorCode.OUT_OF_MEMORY]: 'Out of memory',
  [ErrorCode.INTERNAL]: 'Internal error',
  [ErrorCode.NO_ENTROPY]: 'No entropy available - call injectEntropy() first',
  [ErrorCode.INSUFFICIENT_ENTROPY]: 'Insufficient entropy',
  [ErrorCode.INVALID_WORD]: 'Invalid mnemonic word',
  [ErrorCode.INVALID_CHECKSUM]: 'Invalid mnemonic checksum',
  [ErrorCode.INVALID_MNEMONIC_LENGTH]: 'Invalid mnemonic length',
  [ErrorCode.INVALID_ENTROPY_LENGTH]: 'Invalid entropy length',
  [ErrorCode.INVALID_SEED]: 'Invalid seed',
  [ErrorCode.INVALID_PATH]: 'Invalid derivation path',
  [ErrorCode.INVALID_CHILD_INDEX]: 'Invalid child index',
  [ErrorCode.HARDENED_FROM_PUBLIC]: 'Cannot derive hardened child from public key',
  [ErrorCode.INVALID_EXTENDED_KEY]: 'Invalid extended key format',
  [ErrorCode.INVALID_PRIVATE_KEY]: 'Invalid private key',
  [ErrorCode.INVALID_PUBLIC_KEY]: 'Invalid public key',
  [ErrorCode.INVALID_SIGNATURE]: 'Invalid signature',
  [ErrorCode.VERIFICATION_FAILED]: 'Signature verification failed',
  [ErrorCode.KEY_DERIVATION_FAILED]: 'Key derivation failed',
  [ErrorCode.INVALID_TRANSACTION]: 'Invalid transaction',
  [ErrorCode.INSUFFICIENT_FUNDS]: 'Insufficient funds',
  [ErrorCode.INVALID_ADDRESS]: 'Invalid address',
  [ErrorCode.DEVICE_NOT_CONNECTED]: 'Hardware device not connected',
  [ErrorCode.DEVICE_COMM_ERROR]: 'Hardware device communication error',
  [ErrorCode.USER_CANCELLED]: 'Operation cancelled by user',
  [ErrorCode.DEVICE_BUSY]: 'Hardware device busy',
  [ErrorCode.DEVICE_NOT_SUPPORTED]: 'Operation not supported by this device',
  [ErrorCode.BRIDGE_NOT_SET]: 'Bridge callback not set',
  [ErrorCode.BRIDGE_FAILED]: 'Bridge callback failed',
  [ErrorCode.NEEDS_BRIDGE]: 'Feature requires WASI bridge',
  [ErrorCode.FIPS_NOT_ALLOWED]: 'Algorithm not allowed in FIPS mode'
};

/**
 * HD Wallet Error class
 */
class HDWalletError extends Error {
  /**
   * @param {number} code - Error code
   * @param {string} [message] - Optional custom message
   */
  constructor(code, message) {
    super(message || ERROR_MESSAGES[code] || `Error code: ${code}`);
    this.name = 'HDWalletError';
    this.code = code;
  }
}

/**
 * Check result and throw if error
 * @param {number} result - Result code from WASM function
 * @throws {HDWalletError} If result is non-zero
 */
function checkResult(result) {
  if (result !== 0) {
    throw new HDWalletError(result);
  }
}

// =============================================================================
// Memory Helpers
// =============================================================================

/**
 * Allocate memory and copy data
 * @param {WebAssembly.Module} wasm - WASM module
 * @param {Uint8Array} data - Data to copy
 * @returns {number} Pointer to allocated memory
 */
function allocAndCopy(wasm, data) {
  const ptr = wasm._hd_alloc(data.length);
  if (!ptr) throw new HDWalletError(ErrorCode.OUT_OF_MEMORY);
  wasm.HEAPU8.set(data, ptr);
  return ptr;
}

/**
 * Allocate memory for string and copy
 * @param {WebAssembly.Module} wasm - WASM module
 * @param {string} str - String to copy
 * @returns {number} Pointer to allocated memory
 */
function allocString(wasm, str) {
  const len = wasm.lengthBytesUTF8(str) + 1;
  const ptr = wasm._hd_alloc(len);
  if (!ptr) throw new HDWalletError(ErrorCode.OUT_OF_MEMORY);
  wasm.stringToUTF8(str, ptr, len);
  return ptr;
}

/**
 * Read bytes from WASM memory
 * @param {WebAssembly.Module} wasm - WASM module
 * @param {number} ptr - Pointer to memory
 * @param {number} len - Number of bytes to read
 * @returns {Uint8Array} Copy of the data
 */
function readBytes(wasm, ptr, len) {
  return new Uint8Array(wasm.HEAPU8.buffer, ptr, len).slice();
}

/**
 * Read null-terminated string from WASM memory
 * @param {WebAssembly.Module} wasm - WASM module
 * @param {number} ptr - Pointer to string
 * @returns {string} JavaScript string
 */
function readString(wasm, ptr) {
  return wasm.UTF8ToString(ptr);
}

// =============================================================================
// HDKey Class
// =============================================================================

/**
 * BIP-32 HD Key
 * Represents a node in the HD key derivation tree.
 */
class HDKey {
  /**
   * @param {WebAssembly.Module} wasm - WASM module
   * @param {number} handle - Native key handle
   * @param {string} [path='m'] - Derivation path
   */
  constructor(wasm, handle, path = 'm') {
    /** @private */
    this._wasm = wasm;
    /** @private */
    this._handle = handle;
    /** @private */
    this._path = path;
    /** @private */
    this._destroyed = false;
  }

  /**
   * Derivation path
   * @type {string}
   */
  get path() {
    return this._path;
  }

  /**
   * Key depth in derivation tree
   * @type {number}
   */
  get depth() {
    this._checkDestroyed();
    return this._wasm._hd_key_get_depth(this._handle);
  }

  /**
   * Parent fingerprint
   * @type {number}
   */
  get parentFingerprint() {
    this._checkDestroyed();
    return this._wasm._hd_key_get_parent_fingerprint(this._handle);
  }

  /**
   * Child index
   * @type {number}
   */
  get childIndex() {
    this._checkDestroyed();
    return this._wasm._hd_key_get_child_index(this._handle);
  }

  /**
   * Is this a neutered (public-only) key?
   * @type {boolean}
   */
  get isNeutered() {
    this._checkDestroyed();
    return this._wasm._hd_key_is_neutered(this._handle) !== 0;
  }

  /**
   * Elliptic curve (currently always secp256k1)
   * @type {number}
   */
  get curve() {
    return Curve.SECP256K1;
  }

  /**
   * Check if key has been destroyed
   * @private
   */
  _checkDestroyed() {
    if (this._destroyed) {
      throw new HDWalletError(ErrorCode.INVALID_ARGUMENT, 'Key has been destroyed');
    }
  }

  /**
   * Get private key bytes
   * @returns {Uint8Array} 32-byte private key
   * @throws {HDWalletError} If key is neutered
   */
  privateKey() {
    this._checkDestroyed();
    const ptr = this._wasm._hd_alloc(32);
    try {
      const result = this._wasm._hd_key_get_private(this._handle, ptr, 32);
      checkResult(result);
      return readBytes(this._wasm, ptr, 32);
    } finally {
      this._wasm._hd_dealloc(ptr);
    }
  }

  /**
   * Get compressed public key bytes
   * @returns {Uint8Array} 33-byte compressed public key
   */
  publicKey() {
    this._checkDestroyed();
    const ptr = this._wasm._hd_alloc(33);
    try {
      const result = this._wasm._hd_key_get_public(this._handle, ptr, 33);
      checkResult(result);
      return readBytes(this._wasm, ptr, 33);
    } finally {
      this._wasm._hd_dealloc(ptr);
    }
  }

  /**
   * Get uncompressed public key bytes
   * @returns {Uint8Array} 65-byte uncompressed public key
   */
  publicKeyUncompressed() {
    this._checkDestroyed();
    const compressed = this.publicKey();
    const inPtr = allocAndCopy(this._wasm, compressed);
    const outPtr = this._wasm._hd_alloc(65);
    try {
      const result = this._wasm._hd_curve_decompress_pubkey(inPtr, Curve.SECP256K1, outPtr, 65);
      checkResult(result);
      return readBytes(this._wasm, outPtr, 65);
    } finally {
      this._wasm._hd_dealloc(inPtr);
      this._wasm._hd_dealloc(outPtr);
    }
  }

  /**
   * Get chain code bytes
   * @returns {Uint8Array} 32-byte chain code
   */
  chainCode() {
    this._checkDestroyed();
    const ptr = this._wasm._hd_alloc(32);
    try {
      const result = this._wasm._hd_key_get_chain_code(this._handle, ptr, 32);
      checkResult(result);
      return readBytes(this._wasm, ptr, 32);
    } finally {
      this._wasm._hd_dealloc(ptr);
    }
  }

  /**
   * Get key fingerprint
   * @returns {number} Fingerprint (first 4 bytes of HASH160 of public key)
   */
  fingerprint() {
    this._checkDestroyed();
    return this._wasm._hd_key_get_fingerprint(this._handle);
  }

  /**
   * Derive child key at index
   * @param {number} index - Child index
   * @returns {HDKey} Derived child key
   */
  deriveChild(index) {
    this._checkDestroyed();
    const childHandle = this._wasm._hd_key_derive_child(this._handle, index);
    if (!childHandle) {
      throw new HDWalletError(ErrorCode.KEY_DERIVATION_FAILED);
    }
    const childPath = `${this._path}/${index}`;
    return new HDKey(this._wasm, childHandle, childPath);
  }

  /**
   * Derive hardened child key
   * @param {number} index - Child index (will be hardened)
   * @returns {HDKey} Derived child key
   */
  deriveHardened(index) {
    this._checkDestroyed();
    const childHandle = this._wasm._hd_key_derive_hardened(this._handle, index);
    if (!childHandle) {
      throw new HDWalletError(ErrorCode.KEY_DERIVATION_FAILED);
    }
    const childPath = `${this._path}/${index}'`;
    return new HDKey(this._wasm, childHandle, childPath);
  }

  /**
   * Derive key at path
   * @param {string} path - Derivation path (e.g., "m/44'/60'/0'/0/0")
   * @returns {HDKey} Derived key
   */
  derivePath(path) {
    this._checkDestroyed();
    const pathPtr = allocString(this._wasm, path);
    try {
      const childHandle = this._wasm._hd_key_derive_path(this._handle, pathPtr);
      if (!childHandle) {
        throw new HDWalletError(ErrorCode.INVALID_PATH);
      }
      // Compute resulting path
      let resultPath = path;
      if (path.startsWith('m/') || path === 'm') {
        resultPath = path;
      } else if (path.startsWith('/')) {
        resultPath = this._path + path;
      } else {
        resultPath = this._path + '/' + path;
      }
      return new HDKey(this._wasm, childHandle, resultPath);
    } finally {
      this._wasm._hd_dealloc(pathPtr);
    }
  }

  /**
   * Get neutered (public-only) version
   * @returns {HDKey} Neutered key
   */
  neutered() {
    this._checkDestroyed();
    const neuteredHandle = this._wasm._hd_key_neutered(this._handle);
    if (!neuteredHandle) {
      throw new HDWalletError(ErrorCode.INTERNAL);
    }
    return new HDKey(this._wasm, neuteredHandle, this._path);
  }

  /**
   * Serialize as extended private key (xprv)
   * @returns {string} Base58Check-encoded xprv
   * @throws {HDWalletError} If key is neutered
   */
  toXprv() {
    this._checkDestroyed();
    const ptr = this._wasm._hd_alloc(128);
    try {
      const result = this._wasm._hd_key_serialize_xprv(this._handle, ptr, 128);
      checkResult(result);
      return readString(this._wasm, ptr);
    } finally {
      this._wasm._hd_dealloc(ptr);
    }
  }

  /**
   * Serialize as extended public key (xpub)
   * @returns {string} Base58Check-encoded xpub
   */
  toXpub() {
    this._checkDestroyed();
    const ptr = this._wasm._hd_alloc(128);
    try {
      const result = this._wasm._hd_key_serialize_xpub(this._handle, ptr, 128);
      checkResult(result);
      return readString(this._wasm, ptr);
    } finally {
      this._wasm._hd_dealloc(ptr);
    }
  }

  /**
   * Securely wipe key from memory
   */
  wipe() {
    if (!this._destroyed && this._handle) {
      this._wasm._hd_key_wipe(this._handle);
      this._wasm._hd_key_destroy(this._handle);
      this._handle = null;
      this._destroyed = true;
    }
  }

  /**
   * Clone key
   * @returns {HDKey} Independent copy
   */
  clone() {
    this._checkDestroyed();
    const clonedHandle = this._wasm._hd_key_clone(this._handle);
    if (!clonedHandle) {
      throw new HDWalletError(ErrorCode.OUT_OF_MEMORY);
    }
    return new HDKey(this._wasm, clonedHandle, this._path);
  }
}

// =============================================================================
// Module Initialization
// =============================================================================

/**
 * WASM module loader URL resolver
 * @param {string} [wasmPath] - Optional path to WASM file
 * @returns {Promise<Function>} WASM module factory
 */
async function loadWasmModule(wasmPath) {
  // Try to import the Emscripten-generated module
  let HDWalletWasm;

  try {
    // Try dynamic import (works in Node.js and bundlers)
    const module = await import('../dist/hd-wallet.js');
    HDWalletWasm = module.default;
  } catch (e) {
    // Fallback for browsers without ES module support
    if (typeof window !== 'undefined' && window.HDWalletWasm) {
      HDWalletWasm = window.HDWalletWasm;
    } else {
      throw new Error(
        'Failed to load HD Wallet WASM module. ' +
        'Make sure hd-wallet.js is accessible or set it on window.HDWalletWasm'
      );
    }
  }

  // Initialize the WASM module
  const wasmOptions = {};
  if (wasmPath) {
    wasmOptions.locateFile = (path) => {
      if (path.endsWith('.wasm')) {
        return wasmPath;
      }
      return path;
    };
  }

  return HDWalletWasm(wasmOptions);
}

/**
 * Create the HD Wallet module instance
 * @param {Object} wasm - Initialized WASM module
 * @returns {Object} HDWalletModule API
 */
function createModule(wasm) {
  // ==========================================================================
  // Mnemonic API
  // ==========================================================================

  /**
   * BIP-39 Mnemonic API
   * @type {Object}
   */
  const mnemonic = {
    /**
     * Generate a random mnemonic phrase
     * @param {number} [wordCount=24] - Number of words (12, 15, 18, 21, or 24)
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {string} Mnemonic phrase
     * @throws {HDWalletError} If entropy not available
     */
    generate(wordCount = 24, language = Language.ENGLISH) {
      const ptr = wasm._hd_alloc(1024);
      try {
        const result = wasm._hd_mnemonic_generate(ptr, 1024, wordCount, language);
        checkResult(result);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(ptr);
      }
    },

    /**
     * Validate a mnemonic phrase
     * @param {string} mnemonicStr - Mnemonic phrase to validate
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {boolean} True if valid
     */
    validate(mnemonicStr, language = Language.ENGLISH) {
      const ptr = allocString(wasm, mnemonicStr);
      try {
        const result = wasm._hd_mnemonic_validate(ptr, language);
        return result === 0;
      } finally {
        wasm._hd_dealloc(ptr);
      }
    },

    /**
     * Convert mnemonic to 64-byte seed
     * @param {string} mnemonicStr - Mnemonic phrase
     * @param {string} [passphrase=''] - Optional passphrase
     * @returns {Uint8Array} 64-byte seed
     */
    toSeed(mnemonicStr, passphrase = '') {
      const mnemonicPtr = allocString(wasm, mnemonicStr);
      const passphrasePtr = allocString(wasm, passphrase);
      const seedPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_mnemonic_to_seed(mnemonicPtr, passphrasePtr, seedPtr, 64);
        checkResult(result);
        return readBytes(wasm, seedPtr, 64);
      } finally {
        wasm._hd_secure_wipe(seedPtr, 64);
        wasm._hd_dealloc(mnemonicPtr);
        wasm._hd_dealloc(passphrasePtr);
        wasm._hd_dealloc(seedPtr);
      }
    },

    /**
     * Convert mnemonic to entropy bytes
     * @param {string} mnemonicStr - Mnemonic phrase
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {Uint8Array} Entropy bytes
     */
    toEntropy(mnemonicStr, language = Language.ENGLISH) {
      const mnemonicPtr = allocString(wasm, mnemonicStr);
      const entropyPtr = wasm._hd_alloc(33);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, 33, 'i32');
        const result = wasm._hd_mnemonic_to_entropy(mnemonicPtr, language, entropyPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return readBytes(wasm, entropyPtr, size);
      } finally {
        wasm._hd_dealloc(mnemonicPtr);
        wasm._hd_dealloc(entropyPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    /**
     * Convert entropy to mnemonic
     * @param {Uint8Array} entropy - Entropy bytes (16, 20, 24, 28, or 32 bytes)
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {string} Mnemonic phrase
     */
    fromEntropy(entropy, language = Language.ENGLISH) {
      const entropyPtr = allocAndCopy(wasm, entropy);
      const outputPtr = wasm._hd_alloc(1024);
      try {
        const result = wasm._hd_entropy_to_mnemonic(entropyPtr, entropy.length, language, outputPtr, 1024);
        checkResult(result);
        return readString(wasm, outputPtr);
      } finally {
        wasm._hd_dealloc(entropyPtr);
        wasm._hd_dealloc(outputPtr);
      }
    },

    /**
     * Get wordlist for language
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {string[]} Array of 2048 words
     */
    getWordlist(language = Language.ENGLISH) {
      const ptr = wasm._hd_mnemonic_get_wordlist(language);
      const json = readString(wasm, ptr);
      return JSON.parse(json);
    },

    /**
     * Get word suggestions for autocomplete
     * @param {string} prefix - Word prefix
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @param {number} [maxSuggestions=5] - Maximum suggestions
     * @returns {string[]} Suggested words
     */
    suggestWords(prefix, language = Language.ENGLISH, maxSuggestions = 5) {
      const prefixPtr = allocString(wasm, prefix);
      const outputPtr = wasm._hd_alloc(1024);
      try {
        wasm._hd_mnemonic_suggest_word(prefixPtr, language, outputPtr, 1024, maxSuggestions);
        const text = readString(wasm, outputPtr);
        // C API returns newline-separated words
        return text ? text.split('\n').filter(w => w.length > 0) : [];
      } finally {
        wasm._hd_dealloc(prefixPtr);
        wasm._hd_dealloc(outputPtr);
      }
    },

    /**
     * Check if word is in wordlist
     * @param {string} word - Word to check
     * @param {number} [language=Language.ENGLISH] - Wordlist language
     * @returns {boolean} True if word is in wordlist
     */
    checkWord(word, language = Language.ENGLISH) {
      const wordPtr = allocString(wasm, word);
      try {
        const result = wasm._hd_mnemonic_check_word(wordPtr, language);
        return result >= 0;
      } finally {
        wasm._hd_dealloc(wordPtr);
      }
    }
  };

  // ==========================================================================
  // HDKey API
  // ==========================================================================

  /**
   * BIP-32 HD Key API
   * @type {Object}
   */
  const hdkey = {
    /**
     * Create master key from seed
     * @param {Uint8Array} seed - 16-64 byte seed (BIP-32 allows 128-512 bits)
     * @param {number} [curve=Curve.SECP256K1] - Elliptic curve
     * @returns {HDKey} Master HD key
     */
    fromSeed(seed, curve = Curve.SECP256K1) {
      // BIP-32 allows 128-512 bits (16-64 bytes)
      if (seed.length < 16 || seed.length > 64) {
        throw new HDWalletError(ErrorCode.INVALID_SEED, 'Seed must be 16-64 bytes');
      }
      const seedPtr = allocAndCopy(wasm, seed);
      try {
        const handle = wasm._hd_key_from_seed(seedPtr, seed.length, curve);
        if (!handle) {
          throw new HDWalletError(ErrorCode.INVALID_SEED);
        }
        return new HDKey(wasm, handle, 'm');
      } finally {
        wasm._hd_secure_wipe(seedPtr, seed.length);
        wasm._hd_dealloc(seedPtr);
      }
    },

    /**
     * Parse extended private key
     * @param {string} xprv - Base58Check-encoded xprv
     * @returns {HDKey} HD key
     */
    fromXprv(xprv) {
      const xprvPtr = allocString(wasm, xprv);
      try {
        const handle = wasm._hd_key_from_xprv(xprvPtr);
        if (!handle) {
          throw new HDWalletError(ErrorCode.INVALID_EXTENDED_KEY);
        }
        return new HDKey(wasm, handle);
      } finally {
        wasm._hd_dealloc(xprvPtr);
      }
    },

    /**
     * Parse extended public key
     * @param {string} xpub - Base58Check-encoded xpub
     * @returns {HDKey} HD key (neutered)
     */
    fromXpub(xpub) {
      const xpubPtr = allocString(wasm, xpub);
      try {
        const handle = wasm._hd_key_from_xpub(xpubPtr);
        if (!handle) {
          throw new HDWalletError(ErrorCode.INVALID_EXTENDED_KEY);
        }
        return new HDKey(wasm, handle);
      } finally {
        wasm._hd_dealloc(xpubPtr);
      }
    },

    /**
     * Build BIP-44 path
     * @param {number} purpose - Purpose (44, 49, 84)
     * @param {number} coinType - SLIP-44 coin type
     * @param {number} [account=0] - Account index
     * @param {number} [change=0] - Change (0=external, 1=internal)
     * @param {number} [index=0] - Address index
     * @returns {string} Derivation path
     */
    buildPath(purpose, coinType, account = 0, change = 0, index = 0) {
      const ptr = wasm._hd_alloc(128);
      try {
        const result = wasm._hd_path_build(ptr, 128, purpose, coinType, account, change, index);
        checkResult(result);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(ptr);
      }
    },

    /**
     * Parse BIP-44 path
     * @param {string} path - Derivation path
     * @returns {Object} Parsed path components
     */
    parsePath(path) {
      const pathPtr = allocString(wasm, path);
      const purposePtr = wasm._hd_alloc(4);
      const coinTypePtr = wasm._hd_alloc(4);
      const accountPtr = wasm._hd_alloc(4);
      const changePtr = wasm._hd_alloc(4);
      const indexPtr = wasm._hd_alloc(4);
      try {
        const result = wasm._hd_path_parse(pathPtr, purposePtr, coinTypePtr, accountPtr, changePtr, indexPtr);
        checkResult(result);
        return {
          purpose: wasm.getValue(purposePtr, 'i32'),
          coinType: wasm.getValue(coinTypePtr, 'i32'),
          account: wasm.getValue(accountPtr, 'i32'),
          change: wasm.getValue(changePtr, 'i32'),
          index: wasm.getValue(indexPtr, 'i32')
        };
      } finally {
        wasm._hd_dealloc(pathPtr);
        wasm._hd_dealloc(purposePtr);
        wasm._hd_dealloc(coinTypePtr);
        wasm._hd_dealloc(accountPtr);
        wasm._hd_dealloc(changePtr);
        wasm._hd_dealloc(indexPtr);
      }
    }
  };

  // ==========================================================================
  // Curves API
  // ==========================================================================

  /**
   * Multi-curve cryptography API
   * @type {Object}
   */
  const curves = {
    /**
     * Derive public key from private key
     * @param {Uint8Array} privateKey - Private key bytes
     * @param {number} curve - Curve type
     * @returns {Uint8Array} Compressed public key
     */
    publicKeyFromPrivate(privateKey, curve) {
      const privPtr = allocAndCopy(wasm, privateKey);
      const pubPtr = wasm._hd_alloc(65);
      try {
        const result = wasm._hd_curve_pubkey_from_privkey(privPtr, curve, pubPtr, 65);
        checkResult(result);
        return readBytes(wasm, pubPtr, 33);
      } finally {
        wasm._hd_secure_wipe(privPtr, privateKey.length);
        wasm._hd_dealloc(privPtr);
        wasm._hd_dealloc(pubPtr);
      }
    },

    /**
     * Compress public key
     * @param {Uint8Array} publicKey - Uncompressed public key (65 bytes)
     * @param {number} curve - Curve type
     * @returns {Uint8Array} Compressed public key (33 bytes)
     */
    compressPublicKey(publicKey, curve) {
      const inPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(33);
      try {
        const result = wasm._hd_curve_compress_pubkey(inPtr, curve, outPtr, 33);
        checkResult(result);
        return readBytes(wasm, outPtr, 33);
      } finally {
        wasm._hd_dealloc(inPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    /**
     * Decompress public key
     * @param {Uint8Array} publicKey - Compressed public key (33 bytes)
     * @param {number} curve - Curve type
     * @returns {Uint8Array} Uncompressed public key (65 bytes)
     */
    decompressPublicKey(publicKey, curve) {
      const inPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(65);
      try {
        const result = wasm._hd_curve_decompress_pubkey(inPtr, curve, outPtr, 65);
        checkResult(result);
        return readBytes(wasm, outPtr, 65);
      } finally {
        wasm._hd_dealloc(inPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    /**
     * secp256k1 ECDSA operations
     */
    secp256k1: {
      /**
       * Sign message with secp256k1
       * @param {Uint8Array} message - Message to sign (typically 32-byte hash)
       * @param {Uint8Array} privateKey - 32-byte private key
       * @returns {Uint8Array} Signature
       */
      sign(message, privateKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const keyPtr = allocAndCopy(wasm, privateKey);
        const sigPtr = wasm._hd_alloc(72);
        try {
          const len = wasm._hd_secp256k1_sign(msgPtr, message.length, keyPtr, sigPtr, 72);
          if (len < 0) throw new HDWalletError(len);
          return readBytes(wasm, sigPtr, len);
        } finally {
          wasm._hd_secure_wipe(keyPtr, 32);
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(keyPtr);
          wasm._hd_dealloc(sigPtr);
        }
      },

      /**
       * Sign message with recovery ID
       * @param {Uint8Array} message - Message to sign
       * @param {Uint8Array} privateKey - Private key
       * @returns {Object} { signature: Uint8Array, recoveryId: number }
       */
      signRecoverable(message, privateKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const keyPtr = allocAndCopy(wasm, privateKey);
        const sigPtr = wasm._hd_alloc(65);
        try {
          const recoveryId = wasm._hd_secp256k1_sign_recoverable(msgPtr, message.length, keyPtr, sigPtr, 65);
          if (recoveryId < 0) throw new HDWalletError(recoveryId);
          return {
            signature: readBytes(wasm, sigPtr, 64),
            recoveryId
          };
        } finally {
          wasm._hd_secure_wipe(keyPtr, 32);
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(keyPtr);
          wasm._hd_dealloc(sigPtr);
        }
      },

      /**
       * Verify secp256k1 signature
       * @param {Uint8Array} message - Original message
       * @param {Uint8Array} signature - Signature to verify
       * @param {Uint8Array} publicKey - Public key
       * @returns {boolean} True if valid
       */
      verify(message, signature, publicKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const sigPtr = allocAndCopy(wasm, signature);
        const pubPtr = allocAndCopy(wasm, publicKey);
        try {
          const result = wasm._hd_secp256k1_verify(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length);
          return result === 1;
        } finally {
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(sigPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      /**
       * Recover public key from signature
       * @param {Uint8Array} message - Original message
       * @param {Uint8Array} signature - Signature
       * @param {number} recoveryId - Recovery ID (0-3)
       * @returns {Uint8Array} Recovered public key
       */
      recover(message, signature, recoveryId) {
        const msgPtr = allocAndCopy(wasm, message);
        const sigPtr = allocAndCopy(wasm, signature);
        const pubPtr = wasm._hd_alloc(65);
        try {
          const result = wasm._hd_secp256k1_recover(msgPtr, message.length, sigPtr, signature.length, recoveryId, pubPtr, 65);
          checkResult(result);
          return readBytes(wasm, pubPtr, 65);
        } finally {
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(sigPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      /**
       * ECDH shared secret
       * @param {Uint8Array} privateKey - Own private key
       * @param {Uint8Array} publicKey - Other party's public key
       * @returns {Uint8Array} Shared secret
       */
      ecdh(privateKey, publicKey) {
        const privPtr = allocAndCopy(wasm, privateKey);
        const pubPtr = allocAndCopy(wasm, publicKey);
        const secretPtr = wasm._hd_alloc(32);
        try {
          const result = wasm._hd_ecdh_secp256k1(privPtr, pubPtr, publicKey.length, secretPtr, 32);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, secretPtr, 32);
        } finally {
          wasm._hd_secure_wipe(privPtr, 32);
          wasm._hd_secure_wipe(secretPtr, 32);
          wasm._hd_dealloc(privPtr);
          wasm._hd_dealloc(pubPtr);
          wasm._hd_dealloc(secretPtr);
        }
      }
    },

    /**
     * Ed25519 EdDSA operations
     */
    ed25519: {
      /**
       * Derive Ed25519 public key from 32-byte seed
       * @param {Uint8Array} seed - 32-byte seed (will be expanded internally)
       * @returns {Uint8Array} 32-byte public key
       */
      publicKeyFromSeed(seed) {
        const seedPtr = allocAndCopy(wasm, seed);
        const pubPtr = wasm._hd_alloc(32);
        try {
          const result = wasm._hd_ed25519_pubkey_from_seed(seedPtr, pubPtr, 32);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, pubPtr, 32);
        } finally {
          wasm._hd_secure_wipe(seedPtr, 32);
          wasm._hd_dealloc(seedPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      /**
       * Sign message with Ed25519
       * @param {Uint8Array} message - Message to sign
       * @param {Uint8Array} privateKey - 32-byte private key
       * @returns {Uint8Array} 64-byte signature
       */
      sign(message, privateKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const keyPtr = allocAndCopy(wasm, privateKey);
        const sigPtr = wasm._hd_alloc(64);
        try {
          const len = wasm._hd_ed25519_sign(msgPtr, message.length, keyPtr, sigPtr, 64);
          if (len < 0) throw new HDWalletError(len);
          return readBytes(wasm, sigPtr, 64);
        } finally {
          wasm._hd_secure_wipe(keyPtr, 32);
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(keyPtr);
          wasm._hd_dealloc(sigPtr);
        }
      },

      /**
       * Verify Ed25519 signature
       * @param {Uint8Array} message - Original message
       * @param {Uint8Array} signature - 64-byte signature
       * @param {Uint8Array} publicKey - 32-byte public key
       * @returns {boolean} True if valid
       */
      verify(message, signature, publicKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const sigPtr = allocAndCopy(wasm, signature);
        const pubPtr = allocAndCopy(wasm, publicKey);
        try {
          const result = wasm._hd_ed25519_verify(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length);
          return result === 1;
        } finally {
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(sigPtr);
          wasm._hd_dealloc(pubPtr);
        }
      }
    },

    /**
     * P-256 (secp256r1) ECDSA operations
     */
    p256: {
      sign(message, privateKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const keyPtr = allocAndCopy(wasm, privateKey);
        const sigPtr = wasm._hd_alloc(72);
        try {
          const len = wasm._hd_p256_sign(msgPtr, message.length, keyPtr, sigPtr, 72);
          if (len < 0) throw new HDWalletError(len);
          return readBytes(wasm, sigPtr, len);
        } finally {
          wasm._hd_secure_wipe(keyPtr, 32);
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(keyPtr);
          wasm._hd_dealloc(sigPtr);
        }
      },

      verify(message, signature, publicKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const sigPtr = allocAndCopy(wasm, signature);
        const pubPtr = allocAndCopy(wasm, publicKey);
        try {
          const result = wasm._hd_p256_verify(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length);
          return result === 1;
        } finally {
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(sigPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      ecdh(privateKey, publicKey) {
        const privPtr = allocAndCopy(wasm, privateKey);
        const pubPtr = allocAndCopy(wasm, publicKey);
        const secretPtr = wasm._hd_alloc(32);
        try {
          const result = wasm._hd_ecdh_p256(privPtr, pubPtr, publicKey.length, secretPtr, 32);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, secretPtr, 32);
        } finally {
          wasm._hd_secure_wipe(privPtr, 32);
          wasm._hd_secure_wipe(secretPtr, 32);
          wasm._hd_dealloc(privPtr);
          wasm._hd_dealloc(pubPtr);
          wasm._hd_dealloc(secretPtr);
        }
      }
    },

    /**
     * P-384 (secp384r1) ECDSA operations
     */
    p384: {
      sign(message, privateKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const keyPtr = allocAndCopy(wasm, privateKey);
        const sigPtr = wasm._hd_alloc(104);
        try {
          const len = wasm._hd_p384_sign(msgPtr, message.length, keyPtr, sigPtr, 104);
          if (len < 0) throw new HDWalletError(len);
          return readBytes(wasm, sigPtr, len);
        } finally {
          wasm._hd_secure_wipe(keyPtr, 48);
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(keyPtr);
          wasm._hd_dealloc(sigPtr);
        }
      },

      verify(message, signature, publicKey) {
        const msgPtr = allocAndCopy(wasm, message);
        const sigPtr = allocAndCopy(wasm, signature);
        const pubPtr = allocAndCopy(wasm, publicKey);
        try {
          const result = wasm._hd_p384_verify(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length);
          return result === 1;
        } finally {
          wasm._hd_dealloc(msgPtr);
          wasm._hd_dealloc(sigPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      ecdh(privateKey, publicKey) {
        const privPtr = allocAndCopy(wasm, privateKey);
        const pubPtr = allocAndCopy(wasm, publicKey);
        const secretPtr = wasm._hd_alloc(48);
        try {
          const result = wasm._hd_ecdh_p384(privPtr, pubPtr, publicKey.length, secretPtr, 48);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, secretPtr, 48);
        } finally {
          wasm._hd_secure_wipe(privPtr, 48);
          wasm._hd_secure_wipe(secretPtr, 48);
          wasm._hd_dealloc(privPtr);
          wasm._hd_dealloc(pubPtr);
          wasm._hd_dealloc(secretPtr);
        }
      }
    },

    /**
     * X25519 key exchange
     */
    x25519: {
      /**
       * Derive X25519 public key from private key
       * @param {Uint8Array} privateKey - 32-byte private key
       * @returns {Uint8Array} 32-byte public key
       */
      publicKey(privateKey) {
        const privPtr = allocAndCopy(wasm, privateKey);
        const pubPtr = wasm._hd_alloc(32);
        try {
          const result = wasm._hd_x25519_pubkey(privPtr, pubPtr, 32);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, pubPtr, 32);
        } finally {
          wasm._hd_secure_wipe(privPtr, 32);
          wasm._hd_dealloc(privPtr);
          wasm._hd_dealloc(pubPtr);
        }
      },

      /**
       * Perform X25519 ECDH key exchange
       * @param {Uint8Array} privateKey - Our 32-byte private key
       * @param {Uint8Array} publicKey - Their 32-byte public key
       * @returns {Uint8Array} 32-byte shared secret
       */
      ecdh(privateKey, publicKey) {
        const privPtr = allocAndCopy(wasm, privateKey);
        const pubPtr = allocAndCopy(wasm, publicKey);
        const secretPtr = wasm._hd_alloc(32);
        try {
          const result = wasm._hd_ecdh_x25519(privPtr, pubPtr, secretPtr, 32);
          if (result < 0) throw new HDWalletError(result);
          return readBytes(wasm, secretPtr, 32);
        } finally {
          wasm._hd_secure_wipe(privPtr, 32);
          wasm._hd_secure_wipe(secretPtr, 32);
          wasm._hd_dealloc(privPtr);
          wasm._hd_dealloc(pubPtr);
          wasm._hd_dealloc(secretPtr);
        }
      }
    }
  };

  // ==========================================================================
  // Bitcoin API
  // ==========================================================================

  /**
   * Bitcoin API
   * @type {Object}
   */
  const bitcoin = {
    /**
     * Get Bitcoin address from public key
     * @param {Uint8Array} publicKey - Public key
     * @param {number} type - Address type (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
     * @param {number} [network=Network.MAINNET] - Network
     * @returns {string} Bitcoin address
     */
    getAddress(publicKey, type, network = Network.MAINNET) {
      const pubPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(128);
      try {
        let result;
        switch (type) {
          case BitcoinAddressType.P2PKH:
            result = wasm._hd_btc_get_address_p2pkh(pubPtr, publicKey.length, network, outPtr, 128);
            break;
          case BitcoinAddressType.P2SH:
            result = wasm._hd_btc_get_address_p2sh(pubPtr, publicKey.length, network, outPtr, 128);
            break;
          case BitcoinAddressType.P2WPKH:
            result = wasm._hd_btc_get_address_p2wpkh(pubPtr, publicKey.length, network, outPtr, 128);
            break;
          case BitcoinAddressType.P2WSH:
            result = wasm._hd_btc_get_address_p2wsh(pubPtr, publicKey.length, network, outPtr, 128);
            break;
          case BitcoinAddressType.P2TR:
            result = wasm._hd_btc_get_address_taproot(pubPtr, publicKey.length, network, outPtr, 128);
            break;
          default:
            throw new HDWalletError(ErrorCode.INVALID_ARGUMENT, 'Invalid address type');
        }
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(pubPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    /**
     * Validate Bitcoin address
     * @param {string} address - Address to validate
     * @returns {boolean} True if valid
     */
    validateAddress(address) {
      const addrPtr = allocString(wasm, address);
      try {
        const result = wasm._hd_btc_validate_address(addrPtr);
        return result === 0;
      } finally {
        wasm._hd_dealloc(addrPtr);
      }
    },

    /**
     * Decode Bitcoin address
     * @param {string} address - Address to decode
     * @returns {Object} { type, hash, network }
     */
    decodeAddress(address) {
      const addrPtr = allocString(wasm, address);
      const typePtr = wasm._hd_alloc(4);
      const hashPtr = wasm._hd_alloc(32);
      const hashLenPtr = wasm._hd_alloc(4);
      const networkPtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(hashLenPtr, 32, 'i32');
        const result = wasm._hd_btc_decode_address(addrPtr, typePtr, hashPtr, hashLenPtr, networkPtr);
        checkResult(result);
        const hashLen = wasm.getValue(hashLenPtr, 'i32');
        return {
          type: wasm.getValue(typePtr, 'i32'),
          hash: readBytes(wasm, hashPtr, hashLen),
          network: wasm.getValue(networkPtr, 'i32')
        };
      } finally {
        wasm._hd_dealloc(addrPtr);
        wasm._hd_dealloc(typePtr);
        wasm._hd_dealloc(hashPtr);
        wasm._hd_dealloc(hashLenPtr);
        wasm._hd_dealloc(networkPtr);
      }
    },

    /**
     * Sign message (Bitcoin Signed Message format)
     * @param {string} message - Message to sign
     * @param {Uint8Array} privateKey - Private key
     * @returns {string} Base64-encoded signature
     */
    signMessage(message, privateKey) {
      const msgPtr = allocString(wasm, message);
      const keyPtr = allocAndCopy(wasm, privateKey);
      const sigPtr = wasm._hd_alloc(256);
      try {
        const result = wasm._hd_btc_sign_message(msgPtr, keyPtr, sigPtr, 256);
        checkResult(result);
        return readString(wasm, sigPtr);
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(sigPtr);
      }
    },

    /**
     * Verify signed message
     * @param {string} message - Original message
     * @param {string} signature - Base64-encoded signature
     * @param {string} address - Expected address
     * @returns {boolean} True if valid
     */
    verifyMessage(message, signature, address) {
      const msgPtr = allocString(wasm, message);
      const sigPtr = allocString(wasm, signature);
      const addrPtr = allocString(wasm, address);
      try {
        const result = wasm._hd_btc_verify_message(msgPtr, sigPtr, addrPtr);
        return result === 1;
      } finally {
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(sigPtr);
        wasm._hd_dealloc(addrPtr);
      }
    },

    /**
     * Transaction builder
     */
    tx: {
      create() {
        const handle = wasm._hd_btc_tx_create();
        if (!handle) throw new HDWalletError(ErrorCode.NOT_SUPPORTED);

        return {
          _handle: handle,

          addInput(txid, vout, sequence = 0xffffffff) {
            const txidPtr = allocString(wasm, txid);
            try {
              const result = wasm._hd_btc_tx_add_input(this._handle, txidPtr, vout, sequence);
              checkResult(result);
            } finally {
              wasm._hd_dealloc(txidPtr);
            }
            return this;
          },

          addOutput(address, amount) {
            const addrPtr = allocString(wasm, address);
            try {
              const result = wasm._hd_btc_tx_add_output(this._handle, addrPtr, BigInt(amount));
              checkResult(result);
            } finally {
              wasm._hd_dealloc(addrPtr);
            }
            return this;
          },

          sign(inputIndex, privateKey, redeemScript) {
            const keyPtr = allocAndCopy(wasm, privateKey);
            const scriptPtr = redeemScript ? allocAndCopy(wasm, redeemScript) : 0;
            try {
              const result = wasm._hd_btc_tx_sign(this._handle, inputIndex, keyPtr, scriptPtr, redeemScript?.length || 0);
              checkResult(result);
            } finally {
              wasm._hd_secure_wipe(keyPtr, 32);
              wasm._hd_dealloc(keyPtr);
              if (scriptPtr) wasm._hd_dealloc(scriptPtr);
            }
            return this;
          },

          serialize() {
            const outPtr = wasm._hd_alloc(65536);
            const sizePtr = wasm._hd_alloc(4);
            try {
              wasm.setValue(sizePtr, 65536, 'i32');
              const result = wasm._hd_btc_tx_serialize(this._handle, outPtr, sizePtr);
              checkResult(result);
              const size = wasm.getValue(sizePtr, 'i32');
              return readBytes(wasm, outPtr, size);
            } finally {
              wasm._hd_dealloc(outPtr);
              wasm._hd_dealloc(sizePtr);
            }
          },

          getTxid() {
            const ptr = wasm._hd_btc_tx_get_txid(this._handle);
            return readString(wasm, ptr);
          },

          getSize() {
            return wasm._hd_btc_tx_get_size(this._handle);
          },

          getVsize() {
            return wasm._hd_btc_tx_get_vsize(this._handle);
          },

          destroy() {
            if (this._handle) {
              wasm._hd_btc_tx_destroy(this._handle);
              this._handle = null;
            }
          }
        };
      }
    }
  };

  // ==========================================================================
  // Ethereum API
  // ==========================================================================

  /**
   * Ethereum API
   * @type {Object}
   */
  const ethereum = {
    /**
     * Get Ethereum address from public key
     * @param {Uint8Array} publicKey - Uncompressed public key (65 bytes)
     * @returns {string} Ethereum address (with 0x prefix)
     */
    getAddress(publicKey) {
      const pubPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_eth_get_address(pubPtr, publicKey.length, outPtr, 64);
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(pubPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    /**
     * Get checksummed address (EIP-55)
     * @param {string} address - Address to checksum
     * @returns {string} Checksummed address
     */
    getChecksumAddress(address) {
      const addrPtr = allocString(wasm, address);
      const outPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_eth_get_address_checksum(addrPtr, outPtr, 64);
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(addrPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    /**
     * Validate Ethereum address
     * @param {string} address - Address to validate
     * @returns {boolean} True if valid
     */
    validateAddress(address) {
      const addrPtr = allocString(wasm, address);
      try {
        const result = wasm._hd_eth_validate_address(addrPtr);
        return result === 0;
      } finally {
        wasm._hd_dealloc(addrPtr);
      }
    },

    /**
     * Sign message (EIP-191)
     * @param {string} message - Message to sign
     * @param {Uint8Array} privateKey - Private key
     * @returns {string} Hex-encoded signature
     */
    signMessage(message, privateKey) {
      const msgPtr = allocString(wasm, message);
      const keyPtr = allocAndCopy(wasm, privateKey);
      const sigPtr = wasm._hd_alloc(256);
      try {
        const result = wasm._hd_eth_sign_message(msgPtr, keyPtr, sigPtr, 256);
        checkResult(result);
        return readString(wasm, sigPtr);
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(sigPtr);
      }
    },

    /**
     * Sign typed data (EIP-712)
     * @param {Object} typedData - Typed data object
     * @param {Uint8Array} privateKey - Private key
     * @returns {string} Hex-encoded signature
     */
    signTypedData(typedData, privateKey) {
      const jsonPtr = allocString(wasm, JSON.stringify(typedData));
      const keyPtr = allocAndCopy(wasm, privateKey);
      const sigPtr = wasm._hd_alloc(256);
      try {
        const result = wasm._hd_eth_sign_typed_data(jsonPtr, keyPtr, sigPtr, 256);
        checkResult(result);
        return readString(wasm, sigPtr);
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(jsonPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(sigPtr);
      }
    },

    /**
     * Verify message signature and recover address
     * @param {string} message - Original message
     * @param {string} signature - Hex-encoded signature
     * @returns {string} Recovered address
     */
    verifyMessage(message, signature) {
      const msgPtr = allocString(wasm, message);
      const sigPtr = allocString(wasm, signature);
      const addrPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_eth_verify_message(msgPtr, sigPtr, addrPtr, 64);
        checkResult(result);
        return readString(wasm, addrPtr);
      } finally {
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(sigPtr);
        wasm._hd_dealloc(addrPtr);
      }
    },

    /**
     * Transaction builder
     */
    tx: {
      create(params) {
        // Implementation placeholder
        throw new HDWalletError(ErrorCode.NOT_SUPPORTED);
      },

      createEIP1559(params) {
        // Implementation placeholder
        throw new HDWalletError(ErrorCode.NOT_SUPPORTED);
      }
    }
  };

  // ==========================================================================
  // Cosmos API
  // ==========================================================================

  /**
   * Cosmos/Tendermint API
   * @type {Object}
   */
  const cosmos = {
    getAddress(publicKey, prefix = 'cosmos') {
      const pubPtr = allocAndCopy(wasm, publicKey);
      const prefixPtr = allocString(wasm, prefix);
      const outPtr = wasm._hd_alloc(128);
      try {
        const result = wasm._hd_cosmos_get_address(pubPtr, publicKey.length, prefixPtr, outPtr, 128);
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(pubPtr);
        wasm._hd_dealloc(prefixPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    validateAddress(address) {
      const addrPtr = allocString(wasm, address);
      try {
        return wasm._hd_cosmos_validate_address(addrPtr) === 0;
      } finally {
        wasm._hd_dealloc(addrPtr);
      }
    },

    signAmino(doc, privateKey) {
      const docPtr = allocString(wasm, JSON.stringify(doc));
      const keyPtr = allocAndCopy(wasm, privateKey);
      const outPtr = wasm._hd_alloc(1024);
      try {
        const result = wasm._hd_cosmos_sign_amino(docPtr, keyPtr, outPtr, 1024);
        checkResult(result);
        return JSON.parse(readString(wasm, outPtr));
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(docPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    signDirect(bodyBytes, authInfoBytes, chainId, accountNumber, privateKey) {
      const bodyPtr = allocAndCopy(wasm, bodyBytes);
      const authPtr = allocAndCopy(wasm, authInfoBytes);
      const chainPtr = allocString(wasm, chainId);
      const keyPtr = allocAndCopy(wasm, privateKey);
      const outPtr = wasm._hd_alloc(1024);
      try {
        const result = wasm._hd_cosmos_sign_direct(
          bodyPtr, bodyBytes.length,
          authPtr, authInfoBytes.length,
          chainPtr, BigInt(accountNumber),
          keyPtr, outPtr, 1024
        );
        checkResult(result);
        return JSON.parse(readString(wasm, outPtr));
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(bodyPtr);
        wasm._hd_dealloc(authPtr);
        wasm._hd_dealloc(chainPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    verify(signature, message, publicKey) {
      const sigPtr = allocAndCopy(wasm, signature);
      const msgPtr = allocAndCopy(wasm, message);
      const pubPtr = allocAndCopy(wasm, publicKey);
      try {
        return wasm._hd_cosmos_verify(sigPtr, signature.length, msgPtr, message.length, pubPtr, publicKey.length) === 1;
      } finally {
        wasm._hd_dealloc(sigPtr);
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(pubPtr);
      }
    }
  };

  // ==========================================================================
  // Solana API
  // ==========================================================================

  /**
   * Solana API
   * @type {Object}
   */
  const solana = {
    getAddress(publicKey) {
      const pubPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_sol_get_address(pubPtr, publicKey.length, outPtr, 64);
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(pubPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    validateAddress(address) {
      const addrPtr = allocString(wasm, address);
      try {
        return wasm._hd_sol_validate_address(addrPtr) === 0;
      } finally {
        wasm._hd_dealloc(addrPtr);
      }
    },

    signMessage(message, privateKey) {
      const msgPtr = allocAndCopy(wasm, message);
      const keyPtr = allocAndCopy(wasm, privateKey);
      const sigPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_sol_sign_message(msgPtr, message.length, keyPtr, sigPtr, 64);
        checkResult(result);
        return readBytes(wasm, sigPtr, 64);
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(sigPtr);
      }
    },

    verifyMessage(message, signature, publicKey) {
      const msgPtr = allocAndCopy(wasm, message);
      const sigPtr = allocAndCopy(wasm, signature);
      const pubPtr = allocAndCopy(wasm, publicKey);
      try {
        return wasm._hd_sol_verify_message(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length) === 1;
      } finally {
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(sigPtr);
        wasm._hd_dealloc(pubPtr);
      }
    }
  };

  // ==========================================================================
  // Polkadot API
  // ==========================================================================

  /**
   * Polkadot/Substrate API
   * @type {Object}
   */
  const polkadot = {
    getAddress(publicKey, ss58Prefix = 0) {
      const pubPtr = allocAndCopy(wasm, publicKey);
      const outPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_dot_get_address(pubPtr, publicKey.length, ss58Prefix, outPtr, 64);
        checkResult(result);
        return readString(wasm, outPtr);
      } finally {
        wasm._hd_dealloc(pubPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    validateAddress(address) {
      const addrPtr = allocString(wasm, address);
      try {
        return wasm._hd_dot_validate_address(addrPtr) === 0;
      } finally {
        wasm._hd_dealloc(addrPtr);
      }
    },

    signMessage(message, privateKey) {
      const msgPtr = allocAndCopy(wasm, message);
      const keyPtr = allocAndCopy(wasm, privateKey);
      const sigPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_dot_sign_message(msgPtr, message.length, keyPtr, sigPtr, 64);
        checkResult(result);
        return readBytes(wasm, sigPtr, 64);
      } finally {
        wasm._hd_secure_wipe(keyPtr, 32);
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(keyPtr);
        wasm._hd_dealloc(sigPtr);
      }
    },

    verifyMessage(message, signature, publicKey) {
      const msgPtr = allocAndCopy(wasm, message);
      const sigPtr = allocAndCopy(wasm, signature);
      const pubPtr = allocAndCopy(wasm, publicKey);
      try {
        return wasm._hd_dot_verify_message(msgPtr, message.length, sigPtr, signature.length, pubPtr, publicKey.length) === 1;
      } finally {
        wasm._hd_dealloc(msgPtr);
        wasm._hd_dealloc(sigPtr);
        wasm._hd_dealloc(pubPtr);
      }
    }
  };

  // ==========================================================================
  // Hardware Wallet API
  // ==========================================================================

  /**
   * Hardware Wallet API (requires WASI bridge)
   * @type {Object}
   */
  const hardware = {
    /**
     * Check if hardware wallet support is available
     * @returns {boolean}
     */
    isAvailable() {
      return wasm._hd_wasi_has_feature(WasiFeature.USB_HID) !== 0;
    },

    /**
     * Enumerate connected hardware wallets
     * @returns {Promise<Object[]>} Array of device descriptors
     */
    async enumerate() {
      const ptr = wasm._hd_hw_enumerate();
      const json = readString(wasm, ptr);
      return JSON.parse(json);
    },

    /**
     * Connect to a hardware wallet
     * @param {string} devicePath - Device path from enumeration
     * @returns {Promise<Object>} Hardware wallet interface
     */
    async connect(devicePath) {
      const pathPtr = allocString(wasm, devicePath);
      try {
        const handle = wasm._hd_hw_connect(pathPtr);
        if (!handle) {
          throw new HDWalletError(ErrorCode.DEVICE_NOT_CONNECTED);
        }

        return {
          _handle: handle,

          get vendor() {
            const ptr = wasm._hd_hw_get_vendor(this._handle);
            return readString(wasm, ptr);
          },

          get model() {
            const ptr = wasm._hd_hw_get_model(this._handle);
            return readString(wasm, ptr);
          },

          get firmwareVersion() {
            const ptr = wasm._hd_hw_get_firmware_version(this._handle);
            return readString(wasm, ptr);
          },

          get isConnected() {
            return wasm._hd_hw_is_connected(this._handle) !== 0;
          },

          async getPublicKey(path, curve = Curve.SECP256K1) {
            const pathPtr = allocString(wasm, path);
            const outPtr = wasm._hd_alloc(65);
            try {
              const result = wasm._hd_hw_get_public_key(this._handle, pathPtr, curve, outPtr, 65);
              checkResult(result);
              return readBytes(wasm, outPtr, 33);
            } finally {
              wasm._hd_dealloc(pathPtr);
              wasm._hd_dealloc(outPtr);
            }
          },

          async signTransaction(path, transaction) {
            const pathPtr = allocString(wasm, path);
            const txPtr = allocAndCopy(wasm, transaction);
            const sigPtr = wasm._hd_alloc(128);
            try {
              const result = wasm._hd_hw_sign_transaction(this._handle, pathPtr, txPtr, transaction.length, sigPtr, 128);
              checkResult(result);
              return readBytes(wasm, sigPtr, 64);
            } finally {
              wasm._hd_dealloc(pathPtr);
              wasm._hd_dealloc(txPtr);
              wasm._hd_dealloc(sigPtr);
            }
          },

          async signMessage(path, message) {
            const pathPtr = allocString(wasm, path);
            const msgPtr = allocString(wasm, message);
            const sigPtr = wasm._hd_alloc(128);
            try {
              const result = wasm._hd_hw_sign_message(this._handle, pathPtr, msgPtr, sigPtr, 128);
              checkResult(result);
              return readBytes(wasm, sigPtr, 64);
            } finally {
              wasm._hd_dealloc(pathPtr);
              wasm._hd_dealloc(msgPtr);
              wasm._hd_dealloc(sigPtr);
            }
          },

          async ping() {
            return wasm._hd_hw_ping(this._handle) === 0;
          },

          disconnect() {
            if (this._handle) {
              wasm._hd_hw_disconnect(this._handle);
              this._handle = null;
            }
          }
        };
      } finally {
        wasm._hd_dealloc(pathPtr);
      }
    }
  };

  // ==========================================================================
  // Keyring API
  // ==========================================================================

  /**
   * Keyring API
   * @type {Object}
   */
  const keyring = {
    /**
     * Create a new keyring
     * @returns {Object} Keyring instance
     */
    create() {
      const handle = wasm._hd_keyring_create();

      return {
        _handle: handle,

        addWallet(seed, name) {
          const seedPtr = allocAndCopy(wasm, seed);
          const namePtr = name ? allocString(wasm, name) : 0;
          try {
            const ptr = wasm._hd_keyring_add_wallet(this._handle, seedPtr, seed.length, namePtr);
            return readString(wasm, ptr);
          } finally {
            wasm._hd_secure_wipe(seedPtr, seed.length);
            wasm._hd_dealloc(seedPtr);
            if (namePtr) wasm._hd_dealloc(namePtr);
          }
        },

        removeWallet(id) {
          const idPtr = allocString(wasm, id);
          try {
            const result = wasm._hd_keyring_remove_wallet(this._handle, idPtr);
            checkResult(result);
          } finally {
            wasm._hd_dealloc(idPtr);
          }
        },

        getWalletCount() {
          return wasm._hd_keyring_get_wallet_count(this._handle);
        },

        getAccounts(walletId, coinType, count = 10) {
          const idPtr = allocString(wasm, walletId);
          try {
            const ptr = wasm._hd_keyring_get_accounts(this._handle, idPtr, coinType, count);
            return JSON.parse(readString(wasm, ptr));
          } finally {
            wasm._hd_dealloc(idPtr);
          }
        },

        signTransaction(walletId, path, transaction) {
          const idPtr = allocString(wasm, walletId);
          const pathPtr = allocString(wasm, path);
          const txPtr = allocAndCopy(wasm, transaction);
          const sigPtr = wasm._hd_alloc(128);
          try {
            const result = wasm._hd_keyring_sign_transaction(this._handle, idPtr, pathPtr, txPtr, transaction.length, sigPtr, 128);
            checkResult(result);
            return readBytes(wasm, sigPtr, 64);
          } finally {
            wasm._hd_dealloc(idPtr);
            wasm._hd_dealloc(pathPtr);
            wasm._hd_dealloc(txPtr);
            wasm._hd_dealloc(sigPtr);
          }
        },

        signMessage(walletId, path, message) {
          const idPtr = allocString(wasm, walletId);
          const pathPtr = allocString(wasm, path);
          const msgPtr = allocAndCopy(wasm, message);
          const sigPtr = wasm._hd_alloc(128);
          try {
            const result = wasm._hd_keyring_sign_message(this._handle, idPtr, pathPtr, msgPtr, message.length, sigPtr, 128);
            checkResult(result);
            return readBytes(wasm, sigPtr, 64);
          } finally {
            wasm._hd_dealloc(idPtr);
            wasm._hd_dealloc(pathPtr);
            wasm._hd_dealloc(msgPtr);
            wasm._hd_dealloc(sigPtr);
          }
        },

        destroy() {
          if (this._handle) {
            wasm._hd_keyring_destroy(this._handle);
            this._handle = null;
          }
        }
      };
    }
  };

  // ==========================================================================
  // Utils API
  // ==========================================================================

  /**
   * Utility functions
   * @type {Object}
   */
  const utils = {
    // Hashing
    sha256(data) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(32);
      try {
        const result = wasm._hd_hash_sha256(dataPtr, data.length, hashPtr, 32);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, 32);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    sha512(data) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_hash_sha512(dataPtr, data.length, hashPtr, 64);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, 64);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    keccak256(data) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(32);
      try {
        const result = wasm._hd_hash_keccak256(dataPtr, data.length, hashPtr, 32);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, 32);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    ripemd160(data) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(20);
      try {
        const result = wasm._hd_hash_ripemd160(dataPtr, data.length, hashPtr, 20);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, 20);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    hash160(data) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(20);
      try {
        const result = wasm._hd_hash_hash160(dataPtr, data.length, hashPtr, 20);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, 20);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    blake2b(data, outputLength = 32) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(64);
      try {
        const result = wasm._hd_hash_blake2b(dataPtr, data.length, hashPtr, 64, outputLength);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, outputLength);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    blake2s(data, outputLength = 32) {
      const dataPtr = allocAndCopy(wasm, data);
      const hashPtr = wasm._hd_alloc(32);
      try {
        const result = wasm._hd_hash_blake2s(dataPtr, data.length, hashPtr, 32, outputLength);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, hashPtr, outputLength);
      } finally {
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(hashPtr);
      }
    },

    // Key derivation
    hkdf(ikm, salt, info, length) {
      const ikmPtr = allocAndCopy(wasm, ikm);
      const saltPtr = allocAndCopy(wasm, salt);
      const infoPtr = allocAndCopy(wasm, info);
      const outPtr = wasm._hd_alloc(length);
      try {
        const result = wasm._hd_kdf_hkdf(ikmPtr, ikm.length, saltPtr, salt.length, infoPtr, info.length, outPtr, length);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, outPtr, length);
      } finally {
        wasm._hd_secure_wipe(ikmPtr, ikm.length);
        wasm._hd_dealloc(ikmPtr);
        wasm._hd_dealloc(saltPtr);
        wasm._hd_dealloc(infoPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    pbkdf2(password, salt, iterations, length) {
      const pwdPtr = allocAndCopy(wasm, password);
      const saltPtr = allocAndCopy(wasm, salt);
      const outPtr = wasm._hd_alloc(length);
      try {
        const result = wasm._hd_kdf_pbkdf2(pwdPtr, password.length, saltPtr, salt.length, iterations, outPtr, length);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, outPtr, length);
      } finally {
        wasm._hd_secure_wipe(pwdPtr, password.length);
        wasm._hd_dealloc(pwdPtr);
        wasm._hd_dealloc(saltPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    scrypt(password, salt, n, r, p, length) {
      const pwdPtr = allocAndCopy(wasm, password);
      const saltPtr = allocAndCopy(wasm, salt);
      const outPtr = wasm._hd_alloc(length);
      try {
        const result = wasm._hd_kdf_scrypt(pwdPtr, password.length, saltPtr, salt.length, BigInt(n), r, p, outPtr, length);
        if (result < 0) throw new HDWalletError(result);
        return readBytes(wasm, outPtr, length);
      } finally {
        wasm._hd_secure_wipe(pwdPtr, password.length);
        wasm._hd_dealloc(pwdPtr);
        wasm._hd_dealloc(saltPtr);
        wasm._hd_dealloc(outPtr);
      }
    },

    // Encoding
    encodeBase58(data) {
      const dataPtr = allocAndCopy(wasm, data);
      try {
        const ptr = wasm._hd_encode_base58(dataPtr, data.length);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(dataPtr);
      }
    },

    decodeBase58(str) {
      const strPtr = allocString(wasm, str);
      const outPtr = wasm._hd_alloc(256);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, 256, 'i32');
        const result = wasm._hd_decode_base58(strPtr, outPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return readBytes(wasm, outPtr, size);
      } finally {
        wasm._hd_dealloc(strPtr);
        wasm._hd_dealloc(outPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    encodeBase58Check(data) {
      const dataPtr = allocAndCopy(wasm, data);
      try {
        const ptr = wasm._hd_encode_base58check(dataPtr, data.length);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(dataPtr);
      }
    },

    decodeBase58Check(str) {
      const strPtr = allocString(wasm, str);
      const outPtr = wasm._hd_alloc(256);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, 256, 'i32');
        const result = wasm._hd_decode_base58check(strPtr, outPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return readBytes(wasm, outPtr, size);
      } finally {
        wasm._hd_dealloc(strPtr);
        wasm._hd_dealloc(outPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    encodeBech32(hrp, data) {
      const hrpPtr = allocString(wasm, hrp);
      const dataPtr = allocAndCopy(wasm, data);
      try {
        const ptr = wasm._hd_encode_bech32(hrpPtr, dataPtr, data.length);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(hrpPtr);
        wasm._hd_dealloc(dataPtr);
      }
    },

    decodeBech32(str) {
      const strPtr = allocString(wasm, str);
      const hrpPtr = wasm._hd_alloc(128);
      const dataPtr = wasm._hd_alloc(256);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, 256, 'i32');
        const result = wasm._hd_decode_bech32(strPtr, hrpPtr, 128, dataPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return {
          hrp: readString(wasm, hrpPtr),
          data: readBytes(wasm, dataPtr, size)
        };
      } finally {
        wasm._hd_dealloc(strPtr);
        wasm._hd_dealloc(hrpPtr);
        wasm._hd_dealloc(dataPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    encodeHex(data) {
      const dataPtr = allocAndCopy(wasm, data);
      try {
        const ptr = wasm._hd_encode_hex(dataPtr, data.length);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(dataPtr);
      }
    },

    decodeHex(str) {
      const strPtr = allocString(wasm, str);
      const outPtr = wasm._hd_alloc(str.length / 2);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, str.length / 2, 'i32');
        const result = wasm._hd_decode_hex(strPtr, outPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return readBytes(wasm, outPtr, size);
      } finally {
        wasm._hd_dealloc(strPtr);
        wasm._hd_dealloc(outPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    encodeBase64(data) {
      const dataPtr = allocAndCopy(wasm, data);
      try {
        const ptr = wasm._hd_encode_base64(dataPtr, data.length);
        return readString(wasm, ptr);
      } finally {
        wasm._hd_dealloc(dataPtr);
      }
    },

    decodeBase64(str) {
      const strPtr = allocString(wasm, str);
      const outPtr = wasm._hd_alloc(str.length);
      const sizePtr = wasm._hd_alloc(4);
      try {
        wasm.setValue(sizePtr, str.length, 'i32');
        const result = wasm._hd_decode_base64(strPtr, outPtr, sizePtr);
        checkResult(result);
        const size = wasm.getValue(sizePtr, 'i32');
        return readBytes(wasm, outPtr, size);
      } finally {
        wasm._hd_dealloc(strPtr);
        wasm._hd_dealloc(outPtr);
        wasm._hd_dealloc(sizePtr);
      }
    },

    // Memory
    secureWipe(data) {
      if (data instanceof Uint8Array) {
        // Wipe in-place
        for (let i = 0; i < data.length; i++) {
          data[i] = 0;
        }
      }
    }
  };

  // ==========================================================================
  // Return the module API
  // ==========================================================================

  return {
    // Module info
    getVersion() {
      const ptr = wasm._hd_get_version_string();
      return readString(wasm, ptr);
    },

    hasCryptopp() {
      return wasm._hd_has_cryptopp() !== 0;
    },

    isFipsMode() {
      return wasm._hd_is_fips_mode() !== 0;
    },

    getSupportedCoins() {
      const ptr = wasm._hd_get_supported_coins();
      return JSON.parse(readString(wasm, ptr));
    },

    getSupportedCurves() {
      const ptr = wasm._hd_get_supported_curves();
      return JSON.parse(readString(wasm, ptr));
    },

    // WASI bridge
    wasiHasFeature(feature) {
      return wasm._hd_wasi_has_feature(feature) !== 0;
    },

    wasiGetWarning(feature) {
      return wasm._hd_wasi_get_warning(feature);
    },

    wasiGetWarningMessage(feature) {
      const ptr = wasm._hd_wasi_get_warning_message(feature);
      return readString(wasm, ptr);
    },

    // Entropy
    injectEntropy(entropy) {
      const entropyPtr = allocAndCopy(wasm, entropy);
      try {
        wasm._hd_inject_entropy(entropyPtr, entropy.length);
      } finally {
        wasm._hd_secure_wipe(entropyPtr, entropy.length);
        wasm._hd_dealloc(entropyPtr);
      }
    },

    getEntropyStatus() {
      return wasm._hd_get_entropy_status();
    },

    // APIs
    mnemonic,
    hdkey,
    curves,
    bitcoin,
    ethereum,
    cosmos,
    solana,
    polkadot,
    hardware,
    keyring,
    utils,

    // Aligned binary API for efficient batch operations
    get aligned() {
      if (!this._aligned) {
        // Create a wrapper that exposes wasmMemory for the aligned API
        const wasmWithMemory = Object.create(wasm);
        Object.defineProperty(wasmWithMemory, 'wasmMemory', {
          get: () => ({ buffer: wasm.HEAPU8.buffer })
        });
        this._aligned = new AlignedAPI(wasmWithMemory);
      }
      return this._aligned;
    }
  };
}

// =============================================================================
// Module Export
// =============================================================================

/**
 * Initialize the HD Wallet WASM module
 * @param {string} [wasmPath] - Optional path to WASM file
 * @returns {Promise<Object>} Initialized HDWalletModule
 */
export default async function init(wasmPath) {
  const wasm = await loadWasmModule(wasmPath);
  return createModule(wasm);
}

/**
 * Create HD Wallet instance (alternative syntax)
 * @param {string} [wasmPath] - Optional path to WASM file
 * @returns {Promise<Object>} Initialized HDWalletModule
 */
export async function createHDWallet(wasmPath) {
  return init(wasmPath);
}

// Export types and enums
export {
  HDKey,
  HDWalletError,
  ErrorCode
};
