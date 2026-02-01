/**
 * HD Wallet UI - Main Application
 *
 * Standalone wallet interface with HD key derivation, multi-chain address
 * generation, balance fetching, vCard export, and PIN/passkey storage.
 */

// =============================================================================
// External Imports
// =============================================================================

import initHDWallet, { Curve } from 'hd-wallet-wasm';
import { x25519, ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';
import { sha256 as sha256Noble } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import QRCode from 'qrcode';
import { Buffer } from 'buffer';
import { createV3 } from 'vcard-cryptoperson';

// Make Buffer available globally for various crypto libraries
window.Buffer = Buffer;

// =============================================================================
// Local Module Imports
// =============================================================================

import WalletStorage, { StorageMethod } from './wallet-storage.js';

import {
  cryptoConfig,
  coinTypeToConfig,
  buildSigningPath,
  buildEncryptionPath,
} from './constants.js';

import {
  toHexCompact,
  toHex,
  hexToBytes,
  ensureUint8Array,
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  deriveEthAddress,
  // deriveSuiAddress, // Commented out — BTC/ETH/SOL only
  // deriveMonadAddress,
  // deriveCardanoAddress,
  generateAddresses,
  generateAddressForCoin,
  truncateAddress,
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
  // fetchSuiBalance, // Commented out — BTC/ETH/SOL only
  // fetchMonadBalance,
  // fetchAdaBalance,
  // generateXrpAddress,
  // fetchXrpBalance,
  apiUrl,
} from './address-derivation.js';

// =============================================================================
// DOM Helper
// =============================================================================

let _root = document;
const $ = (id) => {
  const el = _root.getElementById ? _root.getElementById(id) : _root.querySelector(`#${id}`);
  if (el) return el;
  // Fallback to document for elements in the light DOM (e.g. widget mode)
  if (_root !== document) return document.getElementById(id);
  return null;
};
const $q = (sel) => _root.querySelector(sel) || (_root !== document ? document.querySelector(sel) : null);
const $qa = (sel) => {
  const list = _root.querySelectorAll(sel);
  if (list.length > 0 || _root === document) return list;
  return document.querySelectorAll(sel);
};

// =============================================================================
// Wallet Info Box (dismissible notice)
// =============================================================================

function dismissWalletInfo() {
  localStorage.setItem('walletInfoDismissed', '1');
  $('wallet-info-expanded').style.display = 'none';
  $('wallet-info-collapsed').style.display = 'flex';
}

function showWalletInfo() {
  localStorage.removeItem('walletInfoDismissed');
  $('wallet-info-expanded').style.display = 'flex';
  $('wallet-info-collapsed').style.display = 'none';
}

function initWalletInfoBox() {
  if (localStorage.getItem('walletInfoDismissed') === '1') {
    $('wallet-info-expanded').style.display = 'none';
    $('wallet-info-collapsed').style.display = 'flex';
  }
}

function toggleXpubInfo() {
  const box = $('xpub-info-box');
  if (box) box.style.display = box.style.display === 'none' ? 'flex' : 'none';
}

function toggleMemoryInfo() {
  const box = $('memory-info-box');
  if (box) box.style.display = box.style.display === 'none' ? 'flex' : 'none';
}

function bindInfoHandlers() {
  $('wallet-info-dismiss')?.addEventListener('click', dismissWalletInfo);
  $('wallet-info-collapsed')?.addEventListener('click', showWalletInfo);
  $('xpub-info-toggle')?.addEventListener('click', toggleXpubInfo);
  $('xpub-info-close')?.addEventListener('click', toggleXpubInfo);
  $('memory-info-toggle')?.addEventListener('click', toggleMemoryInfo);
  $('memory-info-close')?.addEventListener('click', toggleMemoryInfo);
}

// =============================================================================
// Utilities
// =============================================================================

function setTruncatedValue(el, value) {
  if (!el) return;
  el.dataset.fullValue = value;
  el.textContent = middleTruncate(value, 17, 17);
}

function middleTruncate(str, startChars, endChars) {
  if (!str || str.length <= startChars + endChars + 3) return str;
  return str.slice(0, startChars) + '…' + str.slice(-endChars);
}

function toBase64(arr) {
  return btoa(String.fromCharCode(...arr));
}

// =============================================================================
// SHA-256 and HKDF (WebCrypto-based)
// =============================================================================

async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

async function hkdf(ikm, salt, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    length * 8
  );
  return new Uint8Array(derived);
}

// =============================================================================
// Key Generation
// =============================================================================

function generateKeyPair(curveType) {
  if (curveType === Curve.SECP256K1) {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    return { privateKey, publicKey };
  }
  if (curveType === Curve.X25519) {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }
  throw new Error(`Unsupported curve type: ${curveType}`);
}

async function p256GenerateKeyPairAsync() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const rawPublic = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const pkcs8Private = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  return { publicKey: new Uint8Array(rawPublic), privateKey: new Uint8Array(pkcs8Private) };
}

async function p384GenerateKeyPairAsync() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']
  );
  const rawPublic = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const pkcs8Private = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  return { publicKey: new Uint8Array(rawPublic), privateKey: new Uint8Array(pkcs8Private) };
}

// =============================================================================
// State
// =============================================================================

const state = {
  initialized: false,
  loggedIn: false,
  selectedCrypto: 'btc',
  addresses: {
    btc: null,
    eth: null,
    sol: null,
  },
  wallet: {
    x25519: null,
    ed25519: null,
    secp256k1: null,
    p256: null,
  },
  // HD wallet state
  hdWalletModule: null,
  masterSeed: null,
  hdRoot: null,
  mnemonic: null,
  // Encryption keys (derived from password/seed)
  encryptionKey: null,
  encryptionIV: null,
  // vCard photo (base64 data URI)
  vcardPhoto: null,
  // PKI Demo state
  pki: {
    alice: null,
    bob: null,
    algorithm: 'x25519',
  },
};

// =============================================================================
// Entropy Calculation & Password Strength
// =============================================================================

function calculateEntropy(password) {
  if (!password) return 0;

  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) charsetSize += 32;
  if (/\s/.test(password)) charsetSize += 1;
  if (/[^\x00-\x7F]/.test(password)) charsetSize += 100;

  if (charsetSize === 0) return 0;
  return Math.round(password.length * Math.log2(charsetSize));
}

function updatePasswordStrength(password) {
  const entropy = calculateEntropy(password);
  const fill = $('strength-fill');
  const bits = $('entropy-bits');
  const btn = $('derive-from-password');

  if (bits) bits.textContent = `${entropy}`;

  const MIN_SAFE_ENTROPY = 112;

  let strength, percentage;

  if (entropy < 40) {
    strength = 'weak';
    percentage = Math.min(25, (entropy / 40) * 25);
  } else if (entropy < 80) {
    strength = 'fair';
    percentage = 25 + ((entropy - 40) / 40) * 25;
  } else if (entropy < MIN_SAFE_ENTROPY) {
    strength = 'good';
    percentage = 50 + ((entropy - 80) / (MIN_SAFE_ENTROPY - 80)) * 25;
  } else {
    strength = 'strong';
    percentage = 75 + Math.min(25, ((entropy - MIN_SAFE_ENTROPY) / 50) * 25);
  }

  if (fill) {
    fill.style.width = `${percentage}%`;
    // Gradient: deep red (0) → orange (50%) → green (100%)
    const ratio = percentage / 100;
    let r, g;
    if (ratio < 0.5) {
      r = 180 + Math.round(75 * (ratio / 0.5));  // 180→255
      g = Math.round(140 * (ratio / 0.5));        // 0→140
    } else {
      r = 255 - Math.round(200 * ((ratio - 0.5) / 0.5)); // 255→55
      g = 140 + Math.round(115 * ((ratio - 0.5) / 0.5)); // 140→255
    }
    fill.style.background = `rgb(${r}, ${g}, 30)`;
  }

  const username = $('wallet-username')?.value;
  if (btn) btn.disabled = !username || password.length < 24;
}

// =============================================================================
// Key Derivation
// =============================================================================

async function deriveKeysFromPassword(username, password) {
  const encoder = new TextEncoder();
  const usernameSalt = encoder.encode(username);
  const passwordBytes = encoder.encode(password);

  const initialHash = await sha256(new Uint8Array([...usernameSalt, ...passwordBytes]));
  const masterKey = await hkdf(initialHash, usernameSalt, encoder.encode('master-key'), 32);

  state.encryptionKey = await hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
  state.encryptionIV = await hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);

  // Create 64-byte seed for HD wallet (password-based, not BIP39)
  const hdSeed = await hkdf(masterKey, new Uint8Array(0), encoder.encode('hd-wallet-seed'), 64);
  state.masterSeed = hdSeed;
  state.hdRoot = state.hdWalletModule.hdkey.fromSeed(hdSeed);
  state.mnemonic = null; // Not available for password-derived wallets
  console.log('HD wallet initialized from password, hdRoot:', !!state.hdRoot);

  const keys = deriveKeysFromHDRoot(state.hdRoot);
  // Also derive auxiliary keys for encryption / key agreement
  keys.x25519 = generateKeyPair(Curve.X25519);
  keys.p256 = await p256GenerateKeyPairAsync();
  keys.p384 = await p384GenerateKeyPairAsync();

  return keys;
}

async function deriveKeysFromSeed(seedPhrase) {
  const seed = state.hdWalletModule.mnemonic.toSeed(seedPhrase);
  const encoder = new TextEncoder();

  const masterKey = await hkdf(
    new Uint8Array(seed.slice(0, 32)),
    new Uint8Array(0),
    encoder.encode('wallet-master'),
    32
  );

  state.encryptionKey = await hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
  state.encryptionIV = await hkdf(masterKey, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);

  state.masterSeed = new Uint8Array(seed);
  state.hdRoot = state.hdWalletModule.hdkey.fromSeed(new Uint8Array(seed));
  state.mnemonic = seedPhrase;
  console.log('HD wallet initialized from seed phrase, hdRoot:', !!state.hdRoot);

  const keys = deriveKeysFromHDRoot(state.hdRoot);
  keys.x25519 = generateKeyPair(Curve.X25519);
  keys.p256 = await p256GenerateKeyPairAsync();
  keys.p384 = await p384GenerateKeyPairAsync();

  return keys;
}

/**
 * Derive secp256k1 and ed25519 signing keys from the HD root using BIP44 signing paths.
 * This ensures addresses match what the HD derivation grid produces.
 */
function deriveKeysFromHDRoot(hdRoot) {
  // BTC signing path m/44'/0'/0'/0/0 — secp256k1
  const btcKey = hdRoot.derivePath(buildSigningPath(0, 0, 0));
  const secp256k1PrivKey = btcKey.privateKey();
  const secp256k1PubKey = btcKey.publicKey();

  // SOL signing path m/44'/501'/0'/0/0 — ed25519
  const solKey = hdRoot.derivePath(buildSigningPath(501, 0, 0));
  const ed25519PrivKey = solKey.privateKey();
  const ed25519PubKey = ed25519.getPublicKey(ed25519PrivKey);

  return {
    secp256k1: { privateKey: secp256k1PrivKey, publicKey: secp256k1PubKey },
    ed25519: { privateKey: ed25519PrivKey, publicKey: ed25519PubKey },
  };
}

/**
 * Derive all blockchain addresses from the HD root using signing paths.
 * Each coin uses its own BIP44 signing path: m/44'/{coinType}'/0'/0/0
 */
function deriveAllAddressesFromHD() {
  if (!state.hdRoot) return {};

  const deriveAddress = (coinType) => {
    try {
      const path = buildSigningPath(coinType, 0, 0);
      const derived = state.hdRoot.derivePath(path);
      const pubKey = derived.publicKey();
      return generateAddressForCoin(pubKey, coinType);
    } catch (e) {
      console.error(`Failed to derive address for coinType ${coinType}:`, e);
      return null;
    }
  };

  // For SOL, derive ed25519 key and use it directly
  let solAddress = null;
  try {
    const solPath = buildSigningPath(501, 0, 0);
    const solDerived = state.hdRoot.derivePath(solPath);
    const solPrivKey = solDerived.privateKey();
    solAddress = generateSolAddress(ed25519.getPublicKey(solPrivKey));
  } catch (e) {
    console.error('Failed to derive SOL address:', e);
  }

  return {
    btc: deriveAddress(0),
    eth: deriveAddress(60),
    sol: solAddress,
    // xrp: deriveAddress(144), // Commented out — BTC/ETH/SOL only
  };
}

function generateSeedPhrase() {
  return state.hdWalletModule.mnemonic.generate(24);
}

function validateSeedPhrase(phrase) {
  return state.hdWalletModule.mnemonic.validate(phrase.trim().toLowerCase());
}

// =============================================================================
// HD Wallet Derivation
// =============================================================================

function deriveHDKey(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  try {
    return state.hdRoot.derivePath(path);
  } catch (e) {
    console.error('HD derivation error:', e, 'path:', path);
    throw e;
  }
}

function updatePathDisplay() {
  const coin = $('hd-coin')?.value;
  const account = $('hd-account')?.value || '0';
  const index = $('hd-index')?.value || '0';

  const signingPath = buildSigningPath(coin, account, index);
  const encryptionPath = buildEncryptionPath(coin, account, index);

  const signingPathEl = $('signing-path');
  const encryptionPathEl = $('encryption-path');

  if (signingPathEl) signingPathEl.textContent = signingPath;
  if (encryptionPathEl) encryptionPathEl.textContent = encryptionPath;
}

async function deriveAndDisplayAddress() {
  console.log('deriveAndDisplayAddress called, hdRoot:', !!state.hdRoot);

  const hdNotInitialized = $('hd-not-initialized');
  const derivedResult = $('derived-result');

  if (!state.hdRoot) {
    console.log('HD not initialized, showing warning.');
    if (hdNotInitialized) hdNotInitialized.style.display = 'block';
    if (derivedResult) derivedResult.style.display = 'none';
    return;
  }

  if (hdNotInitialized) hdNotInitialized.style.display = 'none';

  const coin = $('hd-coin')?.value;
  const account = $('hd-account')?.value || '0';
  const index = $('hd-index')?.value || '0';
  const coinType = parseInt(coin);
  const coinOption = $('hd-coin')?.selectedOptions[0];
  const cryptoName = coinOption?.dataset.name || 'Unknown';
  const cryptoSymbol = coinOption?.dataset.symbol || '???';

  const signingPath = buildSigningPath(coin, account, index);
  const encryptionPath = buildEncryptionPath(coin, account, index);

  console.log('Deriving signing path:', signingPath);
  console.log('Deriving encryption path:', encryptionPath);

  try {
    const signingKey = deriveHDKey(signingPath);
    const signingPubKey = signingKey.publicKey();

    const encryptionKey = deriveHDKey(encryptionPath);
    const encryptionPubKey = encryptionKey.publicKey();

    const address = generateAddressForCoin(signingPubKey, coinType);
    console.log('Generated address:', address);

    const config = coinTypeToConfig[coinType];
    const explorerUrl = config ? config.explorer + address : null;

    if (derivedResult) derivedResult.style.display = 'block';

    const signingPathEl = $('signing-path');
    const encryptionPathEl = $('encryption-path');
    if (signingPathEl) signingPathEl.textContent = signingPath;
    if (encryptionPathEl) encryptionPathEl.textContent = encryptionPath;

    const signingPubkeyEl = $('signing-pubkey');
    const encryptionPubkeyEl = $('encryption-pubkey');
    if (signingPubkeyEl) signingPubkeyEl.textContent = toHexCompact(signingPubKey);
    if (encryptionPubkeyEl) encryptionPubkeyEl.textContent = toHexCompact(encryptionPubKey);

    const derivedCryptoName = $('derived-crypto-name');
    const derivedIcon = $('derived-icon');
    const derivedAddress = $('derived-address');
    if (derivedCryptoName) derivedCryptoName.textContent = cryptoName;
    if (derivedIcon) derivedIcon.textContent = cryptoSymbol.substring(0, 2);
    if (derivedAddress) derivedAddress.textContent = address;

    const explorerLink = $('derived-explorer-link');
    if (explorerLink) {
      if (explorerUrl) {
        explorerLink.href = explorerUrl;
        explorerLink.style.display = 'inline-flex';
      } else {
        explorerLink.style.display = 'none';
      }
    }

    // Generate QR code
    try {
      const qrCanvas = $('address-qr');
      if (qrCanvas) {
        await QRCode.toCanvas(qrCanvas, address, {
          width: 64,
          margin: 1,
          color: { dark: '#1e293b', light: '#ffffff' },
        });
      }
    } catch (qrErr) {
      console.warn('QR generation failed:', qrErr);
    }

  } catch (err) {
    console.error('Derivation failed:', err);
  }
}

// =============================================================================
// PKI Key Derivation from HD Wallet
// =============================================================================

function deriveKeyFromPath(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  const derived = state.hdRoot.derivePath(path);
  return derived.privateKey();
}

function deriveX25519FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = x25519.getPublicKey(privateKey);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function deriveSecp256k1FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function deriveP256FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = p256.getPublicKey(privateKey, true);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function derivePKIKeysFromHD() {
  if (!state.hdRoot) {
    console.warn('HD wallet not initialized, cannot derive PKI keys');
    return false;
  }

  const algorithm = $('pki-algorithm')?.value || 'x25519';
  state.pki.algorithm = algorithm;

  try {
    const alicePath = "m/44'/0'/0'/0/0";
    const bobPath = "m/44'/0'/0'/0/1";

    const aliceSeed = deriveKeyFromPath(alicePath);
    const bobSeed = deriveKeyFromPath(bobPath);

    switch (algorithm) {
      case 'x25519':
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
        break;
      case 'secp256k1':
        state.pki.alice = deriveSecp256k1FromSeed(aliceSeed);
        state.pki.bob = deriveSecp256k1FromSeed(bobSeed);
        break;
      case 'p256':
        state.pki.alice = deriveP256FromSeed(aliceSeed);
        state.pki.bob = deriveP256FromSeed(bobSeed);
        break;
      default:
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
    }

    return true;
  } catch (e) {
    console.error('Failed to derive PKI keys from HD:', e);
    return false;
  }
}

function savePKIKeys() {
  if (!state.pki.alice || !state.pki.bob) {
    console.warn('Cannot save PKI keys: alice or bob is null');
    return;
  }

  const data = {
    algorithm: state.pki.algorithm,
    alice: {
      publicKey: toHexCompact(state.pki.alice.publicKey),
      privateKey: toHexCompact(state.pki.alice.privateKey),
    },
    bob: {
      publicKey: toHexCompact(state.pki.bob.publicKey),
      privateKey: toHexCompact(state.pki.bob.privateKey),
    },
    savedAt: new Date().toISOString(),
  };

  if (state.encryptionKey && state.encryptionIV) {
    data.encryptionKey = toHexCompact(state.encryptionKey);
    data.encryptionIV = toHexCompact(state.encryptionIV);
  }

  try {
    localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.warn('Failed to save PKI keys to localStorage:', e);
  }
}

function loadPKIKeys() {
  try {
    const stored = localStorage.getItem(PKI_STORAGE_KEY);
    if (!stored) return false;

    const data = JSON.parse(stored);
    if (!data.alice || !data.bob || !data.algorithm) {
      console.warn('Invalid PKI data in localStorage');
      return false;
    }

    state.pki.algorithm = data.algorithm;
    state.pki.alice = {
      publicKey: hexToBytes(data.alice.publicKey),
      privateKey: hexToBytes(data.alice.privateKey),
    };
    state.pki.bob = {
      publicKey: hexToBytes(data.bob.publicKey),
      privateKey: hexToBytes(data.bob.privateKey),
    };

    if (data.encryptionKey && data.encryptionIV) {
      state.encryptionKey = hexToBytes(data.encryptionKey);
      state.encryptionIV = hexToBytes(data.encryptionIV);
    }

    // Update UI
    const alicePublicKey = $('alice-public-key');
    const alicePrivateKey = $('alice-private-key');
    const bobPublicKey = $('bob-public-key');
    const bobPrivateKey = $('bob-private-key');
    const pkiParties = $('pki-parties');
    const pkiDemo = $('pki-demo');
    const pkiSecurity = $('pki-security');
    const pkiClearKeys = $('pki-clear-keys');

    const pkiAlgorithm = $('pki-algorithm');
    if (pkiAlgorithm) pkiAlgorithm.value = data.algorithm;
    if (alicePublicKey) alicePublicKey.textContent = data.alice.publicKey;
    if (alicePrivateKey) alicePrivateKey.textContent = data.alice.privateKey;
    if (bobPublicKey) bobPublicKey.textContent = data.bob.publicKey;
    if (bobPrivateKey) bobPrivateKey.textContent = data.bob.privateKey;
    if (pkiParties) pkiParties.style.display = 'grid';
    if (pkiDemo) pkiDemo.style.display = 'block';
    if (pkiSecurity) pkiSecurity.style.display = 'block';
    if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';

    return true;
  } catch (e) {
    console.warn('Failed to load PKI keys from localStorage:', e);
    return false;
  }
}

function clearPKIKeys() {
  try {
    localStorage.removeItem(PKI_STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear PKI keys:', e);
  }

  state.pki.alice = null;
  state.pki.bob = null;
  state.pki.algorithm = 'x25519';

  const els = ['alice-public-key', 'alice-private-key', 'bob-public-key', 'bob-private-key'];
  els.forEach(id => {
    const el = $(id);
    if (el) el.textContent = '--';
  });

  const loginPrompt = $('pki-login-prompt');
  if (loginPrompt) loginPrompt.style.display = 'block';
  const pkiControls = $('pki-controls');
  if (pkiControls) pkiControls.style.display = 'none';
  const pkiParties = $('pki-parties');
  if (pkiParties) pkiParties.style.display = 'none';
  const pkiDemo = $('pki-demo');
  if (pkiDemo) pkiDemo.style.display = 'none';
  const pkiSecurity = $('pki-security');
  if (pkiSecurity) pkiSecurity.style.display = 'none';
  const pkiClearKeys = $('pki-clear-keys');
  if (pkiClearKeys) pkiClearKeys.style.display = 'none';
}

async function generatePKIKeyPairs() {
  // First try to derive from HD wallet
  if (state.hdRoot && derivePKIKeysFromHD()) {
    // PKI keys derived from HD wallet
  } else {
    // Fallback to random generation
    const algorithm = $('pki-algorithm')?.value || 'x25519';
    state.pki.algorithm = algorithm;

    try {
      if (algorithm === 'p256') {
        state.pki.alice = await p256GenerateKeyPairAsync();
        state.pki.bob = await p256GenerateKeyPairAsync();
      } else if (algorithm === 'p384') {
        state.pki.alice = await p384GenerateKeyPairAsync();
        state.pki.bob = await p384GenerateKeyPairAsync();
      } else {
        const curveType = algorithm === 'secp256k1' ? Curve.SECP256K1 : Curve.X25519;
        state.pki.alice = generateKeyPair(curveType);
        state.pki.bob = generateKeyPair(curveType);
      }
    } catch (e) {
      console.error('Failed to generate PKI keys:', e);
      alert('Failed to generate keys: ' + e.message);
      return;
    }
  }

  savePKIKeys();

  // Display keys
  const alicePub = $('alice-public-key');
  const alicePriv = $('alice-private-key');
  const bobPub = $('bob-public-key');
  const bobPriv = $('bob-private-key');
  if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
  if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
  if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
  if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

  const algorithmNames = {
    x25519: 'X25519 (Curve25519)',
    secp256k1: 'secp256k1 (Bitcoin/Ethereum)',
    p256: 'P-256 / secp256r1 (NIST)',
    p384: 'P-384 / secp384r1 (NIST)',
  };
  const algDisplay = $('pki-algorithm-display');
  if (algDisplay) algDisplay.textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;

  const selector = $('pki-algorithm');
  if (selector) selector.value = state.pki.algorithm;

  // Show UI sections
  const loginPrompt = $('pki-login-prompt');
  if (loginPrompt) loginPrompt.style.display = 'none';
  const pkiControls = $('pki-controls');
  if (pkiControls) pkiControls.style.display = 'flex';
  const pkiParties = $('pki-parties');
  if (pkiParties) pkiParties.style.display = 'grid';
  const pkiDemo = $('pki-demo');
  if (pkiDemo) pkiDemo.style.display = 'block';
  const pkiSecurity = $('pki-security');
  if (pkiSecurity) pkiSecurity.style.display = 'block';
  const pkiClearKeys = $('pki-clear-keys');
  if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';
}

// =============================================================================
// Login / Logout
// =============================================================================

function login(keys) {
  state.loggedIn = true;
  state.wallet = keys;
  state.addresses = deriveAllAddressesFromHD();
  state.selectedCrypto = 'btc';

  // Close login modal if open
  $('login-modal')?.classList.remove('active');

  // Update hero stats display
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (heroWalletType) heroWalletType.textContent = cryptoConfig[state.selectedCrypto].name;
  if (heroAddress) heroAddress.textContent = truncateAddress(state.addresses[state.selectedCrypto]);
  if (heroStats) heroStats.classList.remove('hidden');

  // Show nav action buttons, hide login button
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = 'none';
  if (navKeys) navKeys.style.display = 'flex';
  if (navLogout) navLogout.style.display = 'flex';

  // Update mobile menu buttons
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = 'none';
  if (mobileLogout) mobileLogout.style.display = 'block';

  // Update HD wallet root keys display
  if (state.hdRoot) {
    const xpubEl = $('wallet-xpub');
    const xprvEl = $('wallet-xprv');
    const seedEl = $('wallet-seed-phrase');

    if (xpubEl) {
      setTruncatedValue(xpubEl, state.hdRoot.toXpub() || 'N/A');
    }
    const keysXpubEl = $('keys-xpub');
    if (keysXpubEl) {
      setTruncatedValue(keysXpubEl, state.hdRoot.toXpub() || 'N/A');
    }
    populateAccountAddressDropdown();
    if (xprvEl) {
      setTruncatedValue(xprvEl, state.hdRoot.toXprv() || 'N/A');
      xprvEl.dataset.revealed = 'false';
    }
    if (seedEl && state.mnemonic) {
      seedEl.textContent = state.mnemonic;
      seedEl.dataset.revealed = 'false';
    } else if (seedEl) {
      seedEl.textContent = 'Not available (derived from password)';
    }
  }

  // Derive PKI keys from HD wallet if available
  if (state.hdRoot) {
    generatePKIKeyPairs();
  } else if (state.pki.alice && state.pki.bob) {
    const alicePub = $('alice-public-key');
    const alicePriv = $('alice-private-key');
    const bobPub = $('bob-public-key');
    const bobPriv = $('bob-private-key');
    if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
    if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
    if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
    if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

    const algorithmNames = {
      x25519: 'X25519 (Curve25519)',
      secp256k1: 'secp256k1 (Bitcoin)',
      p256: 'P-256 (NIST)',
      p384: 'P-384 (NIST)',
    };
    const algDisplay = $('pki-algorithm-display');
    if (algDisplay) algDisplay.textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;
    const loginPrompt = $('pki-login-prompt');
    if (loginPrompt) loginPrompt.style.display = 'none';
    const pkiControls = $('pki-controls');
    if (pkiControls) pkiControls.style.display = 'flex';
    const pkiParties = $('pki-parties');
    if (pkiParties) pkiParties.style.display = 'grid';
    const pkiDemo = $('pki-demo');
    if (pkiDemo) pkiDemo.style.display = 'block';
    const pkiSecurity = $('pki-security');
    if (pkiSecurity) pkiSecurity.style.display = 'block';
    const pkiClearKeys = $('pki-clear-keys');
    if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';
  } else if (!loadPKIKeys()) {
    generatePKIKeyPairs();
  }

  // Update wallet addresses and balances
  updateAdversarialSecurity();

  // Populate vCard keys display
  populateVCardKeysDisplay();

  // Open Account modal so user can see the wallet they just loaded
  $('keys-modal')?.classList.add('active');
  deriveAndDisplayAddress();

  // Resolve names and update title
  clearNameCache();
  resolveNames().then(names => updateAccountTitle(names));

  // Start trust auto-scanning
  if (state._startTrustScanning) state._startTrustScanning();
}

function logout() {
  // Stop trust auto-scanning
  if (state._stopTrustScanning) state._stopTrustScanning();

  clearNameCache();
  const titleEl = $('account-title');
  if (titleEl) titleEl.textContent = 'Account';
  state.loggedIn = false;
  state.wallet = { x25519: null, ed25519: null, secp256k1: null, p256: null };
  state.encryptionKey = null;
  state.encryptionIV = null;
  state.masterSeed = null;
  state.hdRoot = null;
  state.mnemonic = null;

  localStorage.removeItem(PKI_STORAGE_KEY);

  // Update hero stats
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (heroWalletType) heroWalletType.textContent = '--';
  if (heroAddress) heroAddress.textContent = '--';
  if (heroStats) heroStats.classList.add('hidden');

  // Show login button, hide other nav action buttons
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = 'flex';
  if (navKeys) navKeys.style.display = 'none';
  if (navLogout) navLogout.style.display = 'none';

  // Update mobile menu buttons
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = 'block';
  if (mobileLogout) mobileLogout.style.display = 'none';

  // Clear form inputs
  const usernameEl = $('wallet-username');
  const passwordEl = $('wallet-password');
  const seedEl = $('seed-phrase');
  if (usernameEl) usernameEl.value = '';
  if (passwordEl) passwordEl.value = '';
  if (seedEl) seedEl.value = '';
  updatePasswordStrength('');

  // Clear HD wallet UI
  const derivedResult = $('derived-result');
  if (derivedResult) derivedResult.style.display = 'none';
}

// =============================================================================
// Export Wallet
// =============================================================================

async function exportWallet(format) {
  if (!state.loggedIn) {
    alert('Please log in first to export wallet data.');
    return;
  }

  let data, filename, mimeType;

  switch (format) {
    case 'mnemonic':
      if (!state.mnemonic) {
        alert('Seed phrase not available. This wallet was derived from a password.');
        return;
      }
      data = state.mnemonic;
      filename = 'wallet-seed-phrase.txt';
      mimeType = 'text/plain';
      break;

    case 'xpub':
      if (!state.hdRoot?.publicExtendedKey) {
        alert('Extended public key not available.');
        return;
      }
      data = state.hdRoot.toXpub();
      filename = 'wallet-xpub.txt';
      mimeType = 'text/plain';
      break;

    case 'xprv':
      if (!state.hdRoot?.privateExtendedKey) {
        alert('Extended private key not available.');
        return;
      }
      if (!confirm('Warning: You are about to export your master private key. Anyone with this key can access all your funds. Continue?')) {
        return;
      }
      data = state.hdRoot.toXprv();
      filename = 'wallet-xprv.txt';
      mimeType = 'text/plain';
      break;

    case 'hex':
      if (!state.masterSeed) {
        alert('Master seed not available.');
        return;
      }
      if (!confirm('Warning: You are about to export your raw master seed in hex format. This is extremely sensitive data. Continue?')) {
        return;
      }
      data = toHexCompact(state.masterSeed);
      filename = 'wallet-seed-hex.txt';
      mimeType = 'text/plain';
      break;

    default:
      alert('Unknown export format: ' + format);
      return;
  }

  // Download the file
  downloadData(data, filename, mimeType);
}

function downloadData(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// Wallet Address Population & Balance Fetching
// =============================================================================

// Account address dropdown — populated once after login, updated when balances arrive
let _accountAddressData = {}; // { xpub: { addr, value }, btc: { addr, value }, ... }

function populateAccountAddressDropdown() {
  const sel = $('account-address-select');
  if (!sel) return;

  const xpubStr = state.hdRoot ? state.hdRoot.toXpub() : '';
  const addrs = state.addresses || {};

  const networks = [
    { key: 'xpub', label: 'xpub', addr: xpubStr },
    { key: 'btc',  label: 'Bitcoin',  addr: addrs.btc || '' },
    { key: 'eth',  label: 'Ethereum', addr: addrs.eth || '' },
    { key: 'sol',  label: 'Solana',   addr: addrs.sol || '' },
    // { key: 'xrp',  label: 'Ripple',   addr: addrs.xrp || '' },
  ];

  // // Add SUI/Monad/ADA if we can derive them
  // if (state.hdRoot) {
  //   try {
  //     const suiPath = buildSigningPath(784, 0, 0);
  //     const suiDerived = state.hdRoot.derivePath(suiPath);
  //     const suiPubKey = ed25519.getPublicKey(suiDerived.privateKey());
  //     networks.push({ key: 'sui', label: 'SUI', addr: deriveSuiAddress(suiPubKey, 'ed25519') });
  //   } catch (_) {}
  //   networks.push({ key: 'monad', label: 'Monad', addr: addrs.eth || '' });
  //   try {
  //     const adaPath = buildSigningPath(1815, 0, 0);
  //     const adaDerived = state.hdRoot.derivePath(adaPath);
  //     const adaPubKey = ed25519.getPublicKey(adaDerived.privateKey());
  //     networks.push({ key: 'ada', label: 'Cardano', addr: deriveCardanoAddress(adaPubKey) });
  //   } catch (_) {}
  // }

  _accountAddressData = {};
  sel.innerHTML = '';
  for (const n of networks) {
    if (!n.addr) continue;
    _accountAddressData[n.key] = { addr: n.addr, value: '' };
    const opt = document.createElement('option');
    opt.value = n.key;
    opt.textContent = n.label;
    sel.appendChild(opt);
  }

  sel.removeEventListener('change', updateAccountAddressDisplay);
  sel.addEventListener('change', updateAccountAddressDisplay);

  const copyBtn = $('account-address-copy');
  if (copyBtn) {
    copyBtn.onclick = () => {
      const key = sel.value;
      const data = _accountAddressData[key];
      if (data?.addr) {
        navigator.clipboard.writeText(data.addr).then(() => {
          copyBtn.title = 'Copied!';
          setTimeout(() => { copyBtn.title = 'Copy address'; }, 1500);
        });
      }
    };
  }

  updateAccountAddressDisplay();
}

function updateAccountAddressDisplay() {
  const sel = $('account-address-select');
  const addrEl = $('account-address-display');
  const valEl = $('account-address-value');
  if (!sel || !addrEl) return;

  const key = sel.value;
  const data = _accountAddressData[key];
  if (!data) return;

  const addr = data.addr;
  addrEl.textContent = addr;
  addrEl.title = addr;
  if (valEl) valEl.textContent = data.value || (key !== 'xpub' ? '$0.00' : '');
}

function updateAccountAddressValues(bondBalances, prices, currency) {
  const symbol = CURRENCY_SYMBOLS[currency] || currency;
  const keyToSymbol = { btc: 'BTC', eth: 'ETH', sol: 'SOL' };

  for (const [key, data] of Object.entries(_accountAddressData)) {
    if (key === 'xpub') {
      data.value = '';
      continue;
    }
    const sym = keyToSymbol[key];
    const bal = parseFloat(bondBalances[key]) || 0;
    const price = (prices && sym) ? (prices[sym] || 0) : 0;
    const converted = bal * price;
    data.value = converted > 0 ? symbol + converted.toFixed(2) : bal > 0 ? bal.toFixed(6) + ' ' + (sym || '') : '';
  }
  updateAccountAddressDisplay();
}

function populateWalletAddresses() {
  if (!state.wallet) return;

  const btcAddress = state.addresses?.btc || '--';
  const ethAddress = state.addresses?.eth || '--';
  const solAddress = state.addresses?.sol || '--';

  // let suiAddress = '--';
  // let monadAddress = ethAddress; // Monad uses same address as ETH (same coin type 60)
  // let adaAddress = '--';

  // // Derive SUI and ADA from HD root using their signing paths
  // if (state.hdRoot) {
  //   try {
  //     // SUI: coin type 784, uses ed25519
  //     const suiPath = buildSigningPath(784, 0, 0);
  //     const suiDerived = state.hdRoot.derivePath(suiPath);
  //     const suiPrivKey = suiDerived.privateKey();
  //     const suiPubKey = ed25519.getPublicKey(suiPrivKey);
  //     suiAddress = deriveSuiAddress(suiPubKey, 'ed25519');
  //   } catch (e) {
  //     console.error('Failed to derive SUI address:', e);
  //   }

  //   try {
  //     // ADA: coin type 1815, uses ed25519
  //     const adaPath = buildSigningPath(1815, 0, 0);
  //     const adaDerived = state.hdRoot.derivePath(adaPath);
  //     const adaPrivKey = adaDerived.privateKey();
  //     const adaPubKey = ed25519.getPublicKey(adaPrivKey);
  //     adaAddress = deriveCardanoAddress(adaPubKey);
  //   } catch (e) {
  //     console.error('Failed to derive ADA address:', e);
  //   }
  // }

  const updateAddressCard = (network, address, explorerBase) => {
    const addrEl = $(`wallet-${network}-address`);
    const linkEl = $(`wallet-${network}-explorer`);

    if (addrEl && address !== '--') {
      addrEl.textContent = address.length > 20
        ? address.slice(0, 10) + '...' + address.slice(-8)
        : address;
      addrEl.title = address;
    }

    if (linkEl && address !== '--') {
      linkEl.href = explorerBase + address;
    }
  };

  updateAddressCard('btc', btcAddress, 'https://blockstream.info/address/');
  updateAddressCard('eth', ethAddress, 'https://etherscan.io/address/');
  updateAddressCard('sol', solAddress, 'https://solscan.io/account/');
  // updateAddressCard('sui', suiAddress, 'https://suiscan.xyz/mainnet/account/');
  // updateAddressCard('monad', monadAddress, 'https://monadscan.com/address/');
  // updateAddressCard('ada', adaAddress, 'https://cardanoscan.io/address/');

  // const xrpAddress = state.addresses?.xrp || '--';

  // Also populate bond tab addresses
  const bondAddresses = {
    btc: { addr: btcAddress, explorer: 'https://blockstream.info/address/' },
    eth: { addr: ethAddress, explorer: 'https://etherscan.io/address/' },
    sol: { addr: solAddress, explorer: 'https://solscan.io/account/' },
    // sui: { addr: suiAddress, explorer: 'https://suiscan.xyz/mainnet/account/' },
    // monad: { addr: monadAddress, explorer: 'https://monadscan.com/address/' },
    // ada: { addr: adaAddress, explorer: 'https://cardanoscan.io/address/' },
    // xrp: { addr: xrpAddress, explorer: 'https://xrpscan.com/account/' },
  };

  Object.entries(bondAddresses).forEach(([net, { addr, explorer }]) => {
    const addrEl = $(`bond-${net}-address`);
    const linkEl = $(`bond-${net}-explorer`);
    if (addrEl && addr !== '--') {
      addrEl.textContent = addr.length > 20
        ? addr.slice(0, 10) + '...' + addr.slice(-8)
        : addr;
      addrEl.title = addr;
    }
    if (linkEl && addr !== '--') {
      linkEl.href = explorer + addr;
    }
  });
}

// =============================================================================
// Currency Conversion (Coinbase API)
// =============================================================================

const CURRENCY_SYMBOLS = {
  USD: '$', EUR: '€', GBP: '£', JPY: '¥', CAD: 'C$', AUD: 'A$',
  CHF: 'CHF', CNY: '¥', BTC: '₿',
};

const CURRENCY_OPTIONS = Object.keys(CURRENCY_SYMBOLS);

let priceCache = { data: null, currency: null, timestamp: 0 };

function getSelectedCurrency() {
  return localStorage.getItem('bond-currency') || 'USD';
}

function setSelectedCurrency(currency) {
  localStorage.setItem('bond-currency', currency);
}

async function fetchCryptoPrices(currency) {
  const now = Date.now();
  if (priceCache.data && priceCache.currency === currency && now - priceCache.timestamp < 60000) {
    return priceCache.data;
  }

  const cryptos = ['BTC', 'ETH', 'SOL'];
  const prices = {};

  if (currency === 'BTC') {
    // For BTC denomination, fetch each crypto's price in BTC
    prices.BTC = 1;
    const others = ['ETH', 'SOL'];
    const results = await Promise.allSettled(
      others.map(async (crypto) => {
        const url = apiUrl(`https://api.coinbase.com/v2/exchange-rates?currency=${crypto}`);
        const res = await fetch(url);
        const json = await res.json();
        return { crypto, rate: parseFloat(json.data?.rates?.BTC) || 0 };
      })
    );
    results.forEach(r => {
      if (r.status === 'fulfilled') prices[r.value.crypto] = r.value.rate;
    });
    // prices.MONAD = 0; // Testnet token, no market price
  } else {
    // Fetch exchange rates with USD as base, then convert
    const results = await Promise.allSettled(
      cryptos.map(async (crypto) => {
        const url = apiUrl(`https://api.coinbase.com/v2/prices/${crypto}-${currency}/spot`);
        const res = await fetch(url);
        const json = await res.json();
        return { crypto, price: parseFloat(json.data?.amount) || 0 };
      })
    );
    results.forEach(r => {
      if (r.status === 'fulfilled') prices[r.value.crypto] = r.value.price;
    });
    // prices.MONAD = 0;
  }

  priceCache = { data: prices, currency, timestamp: now };
  return prices;
}

function formatCurrencyValue(value, currency) {
  const symbol = CURRENCY_SYMBOLS[currency] || currency;
  if (currency === 'BTC') {
    return `${symbol}${value.toFixed(8)}`;
  }
  if (currency === 'JPY' || currency === 'CNY') {
    return `${symbol}${Math.round(value).toLocaleString()}`;
  }
  return `${symbol}${value.toFixed(2)}`;
}

// =============================================================================
// Name Resolution (ENS, BNS, Solana Names)
// =============================================================================

let nameCache = null;

async function resolveENSName(ethAddress) {
  if (!ethAddress) return null;
  try {
    // ENS reverse resolution: call addr.reverse resolver
    const addr = ethAddress.toLowerCase().slice(2);
    // namehash of <addr>.addr.reverse
    const node = await ensReverseNode(addr);
    // Call the ENS universal resolver
    const data = '0x691f3431' + node.slice(2); // name(bytes32)
    const response = await fetch(apiUrl('https://cloudflare-eth.com'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1,
        method: 'eth_call',
        params: [{ to: '0xa58E81fe9b61B5c3fE2AFD33CF304c454AbFc7Cb', data }, 'latest'],
      }),
    });
    const json = await response.json();
    if (json.result && json.result !== '0x' && json.result.length > 130) {
      const name = decodeENSName(json.result);
      if (name && name.endsWith('.eth')) return name;
    }
  } catch (e) { console.warn('ENS resolution failed:', e); }
  return null;
}

async function ensReverseNode(addrHex) {
  // namehash for <addr>.addr.reverse
  // Start with namehash('') = 0x0...0
  let node = new Uint8Array(32);
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode('reverse'))]));
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode('addr'))]));
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode(addrHex))]));
  return '0x' + Array.from(node).map(b => b.toString(16).padStart(2, '0')).join('');
}

function decodeENSName(hexResult) {
  try {
    // ABI-decode the string result
    const bytes = hexResult.slice(2);
    const offset = parseInt(bytes.slice(0, 64), 16) * 2;
    const length = parseInt(bytes.slice(offset, offset + 64), 16);
    const nameHex = bytes.slice(offset + 64, offset + 64 + length * 2);
    let name = '';
    for (let i = 0; i < nameHex.length; i += 2) {
      name += String.fromCharCode(parseInt(nameHex.slice(i, i + 2), 16));
    }
    return name;
  } catch { return null; }
}

async function resolveBNSName(btcAddress) {
  if (!btcAddress) return null;
  try {
    const response = await fetch(apiUrl(`https://api.hiro.so/v1/addresses/stacks/${btcAddress}`));
    if (!response.ok) return null;
    const json = await response.json();
    const names = json.names || [];
    if (names.length > 0) return names[0]; // Returns e.g. "alice.btc"
  } catch (e) { console.warn('BNS resolution failed:', e); }
  return null;
}

async function resolveSolanaName(solAddress) {
  if (!solAddress) return null;
  try {
    // Use Solana Name Service reverse lookup via public API
    const response = await fetch(`https://sns-sdk-proxy.bonfida.workers.dev/v2/domain/${solAddress}`);
    if (!response.ok) return null;
    const json = await response.json();
    if (json.result && json.result.length > 0) {
      return json.result[0] + '.sol';
    }
  } catch (e) { console.warn('Solana name resolution failed:', e); }
  return null;
}

async function resolveNames() {
  if (nameCache) return nameCache;

  const btcAddress = state.addresses?.btc;
  const ethAddress = state.addresses?.eth;
  const solAddress = state.addresses?.sol;

  const [bns, ens, sol] = await Promise.allSettled([
    resolveBNSName(btcAddress),
    resolveENSName(ethAddress),
    resolveSolanaName(solAddress),
  ]);

  nameCache = {
    bns: bns.status === 'fulfilled' ? bns.value : null,
    ens: ens.status === 'fulfilled' ? ens.value : null,
    sol: sol.status === 'fulfilled' ? sol.value : null,
  };
  return nameCache;
}

function clearNameCache() {
  nameCache = null;
}

function updateAccountTitle(names) {
  const titleEl = $('account-title');
  if (!titleEl) return;

  const resolved = [];
  if (names.bns) resolved.push({ name: names.bns, service: 'BNS' });
  if (names.ens) resolved.push({ name: names.ens, service: 'ENS' });
  if (names.sol) resolved.push({ name: names.sol, service: 'SOL' });

  if (resolved.length === 0) {
    // Fallback to truncated xpub
    const xpub = state.hdRoot?.toXpub?.() || '';
    titleEl.innerHTML = xpub ? middleTruncate(xpub, 12, 8) : 'Account';
    return;
  }

  titleEl.innerHTML = resolved.map(({ name, service }) =>
    `${name}<sub class="name-service-label">${service}</sub>`
  ).join(' · ');
}

// =============================================================================
// Currency Selector UI
// =============================================================================

function initCurrencySelector() {
  const gearBtn = $('bond-currency-gear');
  const popover = $('bond-currency-popover');
  if (!gearBtn || !popover) return;

  // Populate options
  const current = getSelectedCurrency();
  popover.innerHTML = CURRENCY_OPTIONS.map(c =>
    `<button class="currency-option${c === current ? ' active' : ''}" data-currency="${c}">${CURRENCY_SYMBOLS[c]} ${c}</button>`
  ).join('');

  gearBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    popover.classList.toggle('visible');
  });

  popover.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-currency]');
    if (!btn) return;
    const currency = btn.dataset.currency;
    setSelectedCurrency(currency);
    popover.querySelectorAll('.currency-option').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    popover.classList.remove('visible');
    priceCache = { data: null, currency: null, timestamp: 0 }; // invalidate
    await updateAdversarialSecurity();
  });

  // Close popover on outside click
  document.addEventListener('click', () => popover.classList.remove('visible'));
}

// =============================================================================
// Adversarial Security / Bond Balances
// =============================================================================

async function updateAdversarialSecurity() {
  const loginRequired = $('adversarial-login-required');
  const balancesSection = $('adversarial-balances');

  const hasWallet = state.wallet && (state.wallet.secp256k1 || state.wallet.ed25519);

  if (!hasWallet) {
    if (loginRequired) loginRequired.style.display = 'block';
    if (balancesSection) balancesSection.style.display = 'none';
    const trustNote = $('trust-note');
    if (trustNote) trustNote.textContent = 'Login to derive addresses and check balances.';
    return;
  }

  if (loginRequired) loginRequired.style.display = 'none';
  if (balancesSection) balancesSection.style.display = 'block';

  populateWalletAddresses();

  const btcAddress = state.addresses?.btc;
  const ethAddress = state.addresses?.eth;
  const solAddress = state.addresses?.sol;

  // let suiAddress = null;
  // let adaAddress = null;
  // if (state.hdRoot) {
  //   try {
  //     const suiPath = buildSigningPath(784, 0, 0);
  //     const suiDerived = state.hdRoot.derivePath(suiPath);
  //     const suiPubKey = ed25519.getPublicKey(suiDerived.privateKey());
  //     suiAddress = deriveSuiAddress(suiPubKey, 'ed25519');
  //   } catch (e) { console.error('SUI derivation error:', e); }

  //   try {
  //     const adaPath = buildSigningPath(1815, 0, 0);
  //     const adaDerived = state.hdRoot.derivePath(adaPath);
  //     const adaPubKey = ed25519.getPublicKey(adaDerived.privateKey());
  //     adaAddress = deriveCardanoAddress(adaPubKey);
  //   } catch (e) { console.error('ADA derivation error:', e); }
  // }

  // const monadAddress = ethAddress;
  // const xrpAddress = state.addresses?.xrp;

  // Set loading state
  const networks = ['btc', 'eth', 'sol'];
  networks.forEach(net => {
    const balEl = $(`wallet-${net}-balance`);
    if (balEl) balEl.textContent = '...';
  });
  const trustNote = $('trust-note');
  if (trustNote) trustNote.textContent = 'Fetching balances from blockchain...';

  const fetchResults = await Promise.allSettled([
    btcAddress ? fetchBtcBalance(btcAddress) : Promise.resolve({ balance: '0' }),
    ethAddress ? fetchEthBalance(ethAddress) : Promise.resolve({ balance: '0' }),
    solAddress ? fetchSolBalance(solAddress) : Promise.resolve({ balance: '0' }),
    // suiAddress ? fetchSuiBalance(suiAddress) : Promise.resolve({ balance: '0' }),
    // monadAddress ? fetchMonadBalance(monadAddress) : Promise.resolve({ balance: '0' }),
    // adaAddress ? fetchAdaBalance(adaAddress) : Promise.resolve({ balance: '0' }),
    // xrpAddress ? fetchXrpBalance(xrpAddress) : Promise.resolve({ balance: '0' }),
  ]);

  const [btcResult, ethResult, solResult] = fetchResults.map(
    r => r.status === 'fulfilled' ? r.value : { balance: '0' }
  );

  const updateBalance = (network, balance, decimals = 4) => {
    const balEl = $(`wallet-${network}-balance`);
    if (balEl) {
      const val = parseFloat(balance) || 0;
      balEl.textContent = val > 0 ? val.toFixed(val < 0.0001 ? 8 : decimals) : '0';
    }

    const card = $(`wallet-${network}-card`);
    if (card) {
      const hasBalance = parseFloat(balance) > 0;
      card.classList.toggle('has-balance', hasBalance);
      card.classList.toggle('secure', hasBalance);
    }
  };

  updateBalance('btc', btcResult.balance, 8);
  updateBalance('eth', ethResult.balance, 6);
  updateBalance('sol', solResult.balance, 6);
  // updateBalance('sui', suiResult.balance, 4);
  // updateBalance('monad', monadResult.balance, 4);
  // updateBalance('ada', adaResult.balance, 6);
  // updateBalance('xrp', xrpResult.balance, 6);

  // Update bond tab per-network balances
  const bondBalances = {
    btc: btcResult.balance, eth: ethResult.balance, sol: solResult.balance,
    // sui: suiResult.balance, monad: monadResult.balance, ada: adaResult.balance,
    // xrp: xrpResult.balance,
  };
  Object.entries(bondBalances).forEach(([net, bal]) => {
    const el = $(`bond-${net}-balance`);
    const card = $(`bond-${net}-card`);
    const val = parseFloat(bal) || 0;
    if (el) el.textContent = val > 0 ? val.toFixed(val < 0.0001 ? 8 : 4) : '0';
    if (card) card.classList.toggle('has-balance', val > 0);
  });

  // Convert to selected currency
  const currency = getSelectedCurrency();
  let totalConverted = 0;
  let cryptoPrices = null;

  try {
    cryptoPrices = await fetchCryptoPrices(currency);
    const prices = cryptoPrices;
    const balances = {
      BTC: parseFloat(btcResult.balance) || 0,
      ETH: parseFloat(ethResult.balance) || 0,
      SOL: parseFloat(solResult.balance) || 0,
      // SUI: parseFloat(suiResult.balance) || 0,
      // MONAD: parseFloat(monadResult.balance) || 0,
      // ADA: parseFloat(adaResult.balance) || 0,
      // XRP: parseFloat(xrpResult.balance) || 0,
    };

    for (const [crypto, bal] of Object.entries(balances)) {
      totalConverted += bal * (prices[crypto] || 0);
    }
  } catch (e) {
    console.warn('Price conversion failed:', e);
  }

  // Update account header total value
  const accountTotalEl = $('account-total-value');
  if (accountTotalEl) {
    accountTotalEl.textContent = 'Security Level: ' + formatCurrencyValue(totalConverted, currency);
  }

  // Update account address dropdown values
  updateAccountAddressValues(bondBalances, cryptoPrices, currency);
}

// =============================================================================
// vCard Generation
// =============================================================================

function generateVCard(info, { skipPhoto = false } = {}) {
  const person = {};

  if (info.firstName || info.lastName) {
    if (info.lastName) person.FAMILY_NAME = info.lastName;
    if (info.firstName) person.GIVEN_NAME = info.firstName;
    if (info.middleName) person.ADDITIONAL_NAME = info.middleName;
    if (info.prefix) person.HONORIFIC_PREFIX = info.prefix;
    if (info.suffix) person.HONORIFIC_SUFFIX = info.suffix;
  }

  if (info.email) {
    person.CONTACT_POINT = [{ EMAIL: info.email }];
  }

  if (info.org) {
    person.AFFILIATION = { LEGAL_NAME: info.org };
  }

  if (info.title) {
    person.HAS_OCCUPATION = { NAME: info.title };
  }

  if (!skipPhoto && state.vcardPhoto) {
    person.IMAGE = state.vcardPhoto;
  }

  if (info.includeKeys && state.wallet.x25519) {
    person.KEY = [
      ...(state.hdRoot?.publicExtendedKey ? [{
        KEY_TYPE: 'xpub',
        PUBLIC_KEY: state.hdRoot.toXpub(),
      }] : []),
      {
        KEY_TYPE: 'X25519',
        PUBLIC_KEY: toBase64(state.wallet.x25519.publicKey),
      },
      {
        KEY_TYPE: 'Ed25519',
        PUBLIC_KEY: toBase64(state.wallet.ed25519.publicKey),
      },
      {
        KEY_TYPE: 'secp256k1',
        PUBLIC_KEY: toBase64(state.wallet.secp256k1.publicKey),
        CRYPTO_ADDRESS: state.addresses.btc || undefined,
      },
    ];
  }

  const note = info.includeKeys
    ? 'Generated by HD Wallet UI'
    : undefined;

  let vcard = createV3(person, note);

  // Convert PHOTO from data URI format to iOS-compatible inline base64 format
  vcard = vcard.replace(
    /PHOTO;VALUE=URI:data:image\/(\w+);base64,([^\n]+)\n/,
    (_, type, b64) => {
      const vcardType = type.toUpperCase();
      let folded = `PHOTO;ENCODING=b;TYPE=${vcardType}:`;
      for (let i = 0; i < b64.length; i += 74) {
        folded += '\n ' + b64.slice(i, i + 74);
      }
      return folded + '\n';
    }
  );

  return vcard;
}

// =============================================================================
// vCard Keys Display
// =============================================================================

function populateVCardKeysDisplay() {
  const keysDisplay = $('vcard-keys-display');
  if (!keysDisplay) return;

  const keys = [];

  // Bitcoin signing key
  if (state.addresses.btc) {
    keys.push({
      label: 'Bitcoin Signing',
      curve: 'secp256k1',
      address: state.addresses.btc,
      pubkey: state.wallet.secp256k1 ? toHex(state.wallet.secp256k1.publicKey) : '—',
      path: buildSigningPath(0, 0, 0), // m/44'/0'/0'/0'/0'
      role: 'signing',
      explorer: `https://blockstream.info/address/${state.addresses.btc}`,
    });
  }

  // Ethereum signing key
  if (state.addresses.eth) {
    keys.push({
      label: 'Ethereum Signing',
      curve: 'secp256k1',
      address: state.addresses.eth,
      pubkey: state.wallet.secp256k1 ? toHex(state.wallet.secp256k1.publicKey) : '—',
      path: buildSigningPath(60, 0, 0), // m/44'/60'/0'/0'/0'
      role: 'signing',
      explorer: `https://etherscan.io/address/${state.addresses.eth}`,
    });
  }

  // Solana signing key
  if (state.addresses.sol) {
    keys.push({
      label: 'Solana Signing',
      curve: 'Ed25519',
      address: state.addresses.sol,
      pubkey: state.wallet.ed25519 ? toHex(state.wallet.ed25519.publicKey) : '—',
      path: buildSigningPath(501, 0, 0), // m/44'/501'/0'/0'
      role: 'signing',
      explorer: `https://explorer.solana.com/address/${state.addresses.sol}`,
    });
  }

  // P-256 encryption key
  if (state.wallet.p256) {
    keys.push({
      label: 'Encryption Key',
      curve: 'P-256 (NIST)',
      address: '—',
      pubkey: toHex(state.wallet.p256.publicKey),
      path: buildEncryptionPath(0, 0, 0), // m/44'/0'/0'/1'/0'
      role: 'encryption',
      explorer: null,
    });
  }

  // Clear and populate
  keysDisplay.innerHTML = '';

  keys.forEach(key => {
    const keyCard = document.createElement('div');
    keyCard.className = 'key-display-card';
    keyCard.innerHTML = `
      <div class="key-display-header">
        <span class="key-display-label">${key.label}</span>
        <span class="key-display-badge ${key.role}">${key.role}</span>
      </div>
      <div class="key-display-row">
        <span class="key-display-field">Curve</span>
        <code class="key-display-value">${key.curve}</code>
      </div>
      <div class="key-display-row">
        <span class="key-display-field">Public Key</span>
        <code class="key-display-value truncate" title="${key.pubkey}">${truncateAddress(key.pubkey, 16)}</code>
        <button class="copy-btn-small" data-copy-text="${key.pubkey}" title="Copy">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
          </svg>
        </button>
      </div>
      ${key.address !== '—' ? `
      <div class="key-display-row">
        <span class="key-display-field">Address</span>
        <code class="key-display-value truncate" title="${key.address}">${truncateAddress(key.address, 16)}</code>
        ${key.explorer ? `<a href="${key.explorer}" target="_blank" rel="noopener" class="explorer-link-small" title="View on Explorer">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
            <polyline points="15 3 21 3 21 9"/>
            <line x1="10" y1="14" x2="21" y2="3"/>
          </svg>
        </a>` : ''}
      </div>
      ` : ''}
      <div class="key-display-row">
        <span class="key-display-field">Derivation Path</span>
        <code class="key-display-value">${key.path}</code>
      </div>
    `;
    keysDisplay.appendChild(keyCard);
  });

  // Add copy button event listeners
  keysDisplay.querySelectorAll('.copy-btn-small').forEach(btn => {
    btn.addEventListener('click', async () => {
      const text = btn.getAttribute('data-copy-text');
      try {
        await navigator.clipboard.writeText(text);
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '✓';
        setTimeout(() => { btn.innerHTML = originalHTML; }, 1000);
      } catch (err) {
        console.error('Copy failed:', err);
      }
    });
  });
}

function parseAndDisplayVCF(vcfText) {
  const lines = vcfText.replace(/\r?\n /g, '').split(/\r?\n/);
  const fields = {};
  const keys = [];
  let photo = null;

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const prop = line.substring(0, colonIdx).toUpperCase();
    const value = line.substring(colonIdx + 1);

    if (prop === 'FN') {
      fields.name = value;
    } else if (prop.startsWith('N')) {
      if (!fields.name) {
        const parts = value.split(';');
        fields.name = [parts[3], parts[1], parts[2], parts[0], parts[4]].filter(Boolean).join(' ');
      }
    } else if (prop.startsWith('EMAIL')) {
      fields.email = value;
    } else if (prop.startsWith('ORG')) {
      fields.org = value.replace(/;/g, ', ');
    } else if (prop.startsWith('TITLE')) {
      fields.title = value;
    } else if (prop.startsWith('TEL')) {
      fields.tel = value;
    } else if (prop.startsWith('PHOTO')) {
      if (prop.includes('VALUE=URI') || value.startsWith('data:') || value.startsWith('http')) {
        photo = value;
      } else if (prop.includes('ENCODING=B') || prop.includes('ENCODING=b')) {
        const typeMatch = prop.match(/TYPE=(\w+)/i);
        const imgType = typeMatch ? typeMatch[1].toLowerCase() : 'jpeg';
        photo = `data:image/${imgType};base64,${value}`;
      }
    } else if (prop.startsWith('KEY')) {
      const typeMatch = prop.match(/TYPE=(\w+)/i);
      keys.push({ type: typeMatch ? typeMatch[1] : 'Unknown', value });
    } else if (prop.startsWith('X-CRYPTO-KEY') || prop.startsWith('X-KEY')) {
      keys.push({ type: prop.split(';')[0], value });
    }
  }

  const resultEl = $('vcf-import-result');
  const photoEl = $('vcf-import-photo');
  const fieldsEl = $('vcf-import-fields');
  if (!resultEl || !fieldsEl) return;

  if (photoEl) {
    photoEl.innerHTML = photo
      ? `<img src="${photo}" alt="Contact photo">`
      : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:32px;height:32px;opacity:0.3">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
        </svg>`;
  }

  let html = '';
  const fieldMap = [
    ['Name', fields.name],
    ['Email', fields.email],
    ['Org', fields.org],
    ['Title', fields.title],
    ['Phone', fields.tel],
  ];
  for (const [label, val] of fieldMap) {
    if (val) {
      html += `<div class="vcf-import-field">
        <span class="vcf-import-field-label">${label}</span>
        <span class="vcf-import-field-value">${val}</span>
      </div>`;
    }
  }

  if (keys.length > 0) {
    html += '<div class="vcf-import-keys">';
    for (const k of keys) {
      html += `<div class="vcf-import-key"><strong>${k.type}:</strong> <code>${k.value}</code></div>`;
    }
    html += '</div>';
  }

  fieldsEl.innerHTML = html;
  resultEl.style.display = 'block';
}

// =============================================================================
// Grid Canvas Animation
// =============================================================================

function initGridAnimation() {
  const canvas = $('grid-canvas') || document.getElementById('grid-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const gridSize = 40;
  const dotRadius = 1.5;

  const travelers = [];
  const maxTravelers = 30;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  function createTraveler() {
    const horizontal = Math.random() > 0.5;
    const value = Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();

    if (horizontal) {
      const row = Math.floor(Math.random() * (canvas.height / gridSize)) * gridSize;
      return {
        x: Math.random() > 0.5 ? -20 : canvas.width + 20,
        y: row,
        dx: (Math.random() > 0.5 ? 1 : -1) * (0.3 + Math.random() * 0.4),
        dy: 0,
        value,
        opacity: 0.3 + Math.random() * 0.4
      };
    } else {
      const col = Math.floor(Math.random() * (canvas.width / gridSize)) * gridSize;
      return {
        x: col,
        y: Math.random() > 0.5 ? -20 : canvas.height + 20,
        dx: 0,
        dy: (Math.random() > 0.5 ? 1 : -1) * (0.3 + Math.random() * 0.4),
        value,
        opacity: 0.3 + Math.random() * 0.4
      };
    }
  }

  for (let i = 0; i < maxTravelers; i++) {
    travelers.push(createTraveler());
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
    for (let x = 0; x <= canvas.width; x += gridSize) {
      for (let y = 0; y <= canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.arc(x, y, dotRadius, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    ctx.font = '10px monospace';
    for (let i = 0; i < travelers.length; i++) {
      const t = travelers[i];

      t.x += t.dx;
      t.y += t.dy;

      if (t.x < -30 || t.x > canvas.width + 30 || t.y < -30 || t.y > canvas.height + 30) {
        travelers[i] = createTraveler();
        continue;
      }

      ctx.fillStyle = `rgba(100, 200, 255, ${t.opacity})`;
      ctx.fillText(t.value, t.x - 6, t.y + 3);
    }

    requestAnimationFrame(draw);
  }

  draw();
}

// =============================================================================
// WebAuthn / Passkey Helpers
// =============================================================================

function isPasskeySupported() {
  return window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
}

// =============================================================================
// Login Handler Setup
// =============================================================================

// Track selected remember method (pin or passkey) for each login type
const rememberMethod = {
  password: 'passkey',
  seed: 'passkey'
};

function setupLoginHandlers() {
  // Migrate from old storage format if needed
  WalletStorage.migrateStorage();

  // Check for stored wallet using module
  const storageMetadata = WalletStorage.getStorageMetadata();
  const storageMethod = storageMetadata?.method || StorageMethod.NONE;

  if (storageMethod !== StorageMethod.NONE) {
    const storedTab = $('stored-tab');
    if (storedTab) storedTab.style.display = '';

    const dateEl = $('stored-wallet-date');
    if (dateEl && storageMetadata?.date) {
      dateEl.textContent = `Saved on ${storageMetadata.date}`;
    }

    const pinSection = $('stored-pin-section');
    const passkeySection = $('stored-passkey-section');
    const divider = $('stored-divider');

    if (divider) divider.style.display = 'none';

    if (storageMethod === StorageMethod.PIN) {
      if (pinSection) pinSection.style.display = 'block';
      if (passkeySection) passkeySection.style.display = 'none';
    } else if (storageMethod === StorageMethod.PASSKEY) {
      if (pinSection) pinSection.style.display = 'none';
      if (passkeySection) passkeySection.style.display = 'block';
    }

    // Auto-switch to stored tab and open modal
    $qa('.method-tab').forEach(t => t.classList.remove('active'));
    $qa('.method-content').forEach(c => c.classList.remove('active'));
    if (storedTab) storedTab.classList.add('active');
    const storedMethod = $('stored-method');
    if (storedMethod) storedMethod.classList.add('active');

    const loginModal = $('login-modal');
    if (loginModal) loginModal.classList.add('active');
  }

  // Hide passkey buttons if not supported
  if (!isPasskeySupported()) {
    const ppBtn = $('passkey-btn-password');
    if (ppBtn) ppBtn.style.display = 'none';
    const psBtn = $('passkey-btn-seed');
    if (psBtn) psBtn.style.display = 'none';
  }

  // Method tab switching
  $qa('.method-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $qa('.method-tab').forEach(t => t.classList.remove('active'));
      $qa('.method-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const methodEl = $(`${tab.dataset.method}-method`);
      if (methodEl) methodEl.classList.add('active');
    });
  });

  // Remember method selector (PIN vs Passkey)
  $qa('.remember-method-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.target;
      const method = btn.dataset.method;
      rememberMethod[target] = method;

      $qa(`.remember-method-btn[data-target="${target}"]`).forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const pinGroup = $(`pin-group-${target}`);
      const passkeyInfo = $(`passkey-info-${target}`);
      if (pinGroup) pinGroup.style.display = method === 'pin' ? 'block' : 'none';
      if (passkeyInfo) passkeyInfo.style.display = method === 'passkey' ? 'flex' : 'none';
    });
  });

  // Remember wallet checkbox handlers
  $('remember-wallet-password')?.addEventListener('change', (e) => {
    const opts = $('remember-options-password');
    if (opts) opts.style.display = e.target.checked ? 'block' : 'none';
    if (e.target.checked && rememberMethod.password === 'pin') {
      $('pin-input-password')?.focus();
    }
  });

  $('remember-wallet-seed')?.addEventListener('change', (e) => {
    const opts = $('remember-options-seed');
    if (opts) opts.style.display = e.target.checked ? 'block' : 'none';
    if (e.target.checked && rememberMethod.seed === 'pin') {
      $('pin-input-seed')?.focus();
    }
  });

  // PIN input validation
  ['pin-input-password', 'pin-input-seed', 'pin-input-unlock'].forEach(id => {
    $(id)?.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
      if (id === 'pin-input-unlock') {
        const unlockBtn = $('unlock-stored-wallet');
        if (unlockBtn) unlockBtn.disabled = e.target.value.length !== 6;
      }
    });
  });

  // Password input handler
  $('wallet-password')?.addEventListener('input', (e) => {
    updatePasswordStrength(e.target.value);
  });

  $('wallet-username')?.addEventListener('input', () => {
    const pw = $('wallet-password');
    if (pw) updatePasswordStrength(pw.value);
  });

  // Derive from password button
  $('derive-from-password')?.addEventListener('click', async () => {
    const username = $('wallet-username')?.value;
    const password = $('wallet-password')?.value;
    const rememberWallet = $('remember-wallet-password')?.checked;
    const usePasskey = rememberMethod.password === 'passkey';
    const pin = $('pin-input-password')?.value;

    console.log('Login clicked, username:', username, 'password length:', password?.length);
    if (!username || !password || password.length < 24) {
      console.log('Login validation failed');
      return;
    }

    if (rememberWallet && !usePasskey && (!pin || pin.length !== 6)) {
      alert('Please enter a 6-digit PIN to store your wallet');
      return;
    }

    const btn = $('derive-from-password');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      console.log('Calling deriveKeysFromPassword...');
      const keys = await deriveKeysFromPassword(username, password);
      console.log('Keys derived, hdRoot after derivation:', !!state.hdRoot);

      if (rememberWallet) {
        const walletData = {
          type: 'password',
          username,
          password,
          masterSeed: Array.from(state.masterSeed)
        };

        if (usePasskey) {
          await WalletStorage.storeWithPasskey(walletData, {
            rpName: 'HD Wallet',
            userName: username,
            userDisplayName: username
          });
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'none';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'block';
        } else {
          await WalletStorage.storeWithPIN(pin, walletData);
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'block';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'none';
        }
        const storedTab = $('stored-tab');
        if (storedTab) storedTab.style.display = '';
        const divider = $('stored-divider');
        if (divider) divider.style.display = 'none';
        const dateEl = $('stored-wallet-date');
        if (dateEl) dateEl.textContent = `Saved on ${new Date().toLocaleDateString()}`;
      }

      login(keys);
      console.log('Login complete, hdRoot:', !!state.hdRoot);
    } catch (err) {
      console.error('Login error:', err);
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login';
    }
  });

  // Generate seed phrase button
  $('generate-seed')?.addEventListener('click', () => {
    const seedEl = $('seed-phrase');
    if (seedEl) seedEl.value = generateSeedPhrase();
    const deriveBtn = $('derive-from-seed');
    if (deriveBtn) deriveBtn.disabled = false;
  });

  // Validate seed phrase button
  $('validate-seed')?.addEventListener('click', () => {
    const seedEl = $('seed-phrase');
    const valid = validateSeedPhrase(seedEl?.value || '');
    if (valid) {
      alert('Valid BIP39 seed phrase!');
      const deriveBtn = $('derive-from-seed');
      if (deriveBtn) deriveBtn.disabled = false;
    } else {
      alert('Invalid seed phrase');
      const deriveBtn = $('derive-from-seed');
      if (deriveBtn) deriveBtn.disabled = true;
    }
  });

  // Seed phrase input validation
  $('seed-phrase')?.addEventListener('input', () => {
    const phrase = $('seed-phrase')?.value.trim();
    const deriveBtn = $('derive-from-seed');
    if (phrase && phrase.split(/\s+/).length >= 12) {
      if (deriveBtn) deriveBtn.disabled = !validateSeedPhrase(phrase);
    } else {
      if (deriveBtn) deriveBtn.disabled = true;
    }
  });

  // Derive from seed button
  $('derive-from-seed')?.addEventListener('click', async () => {
    const phrase = $('seed-phrase')?.value;
    if (!phrase || !validateSeedPhrase(phrase)) return;

    const rememberWallet = $('remember-wallet-seed')?.checked;
    const usePasskey = rememberMethod.seed === 'passkey';
    const pin = $('pin-input-seed')?.value;

    if (rememberWallet && !usePasskey && (!pin || pin.length !== 6)) {
      alert('Please enter a 6-digit PIN to store your wallet');
      return;
    }

    const btn = $('derive-from-seed');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      const keys = await deriveKeysFromSeed(phrase);

      if (rememberWallet) {
        const walletData = {
          type: 'seed',
          seedPhrase: phrase,
          masterSeed: Array.from(state.masterSeed)
        };

        if (usePasskey) {
          await WalletStorage.storeWithPasskey(walletData, {
            rpName: 'HD Wallet',
            userName: 'seed-wallet',
            userDisplayName: 'Seed Phrase Wallet'
          });
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'none';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'block';
        } else {
          await WalletStorage.storeWithPIN(pin, walletData);
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'block';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'none';
        }
        const storedTab = $('stored-tab');
        if (storedTab) storedTab.style.display = '';
        const divider = $('stored-divider');
        if (divider) divider.style.display = 'none';
        const dateEl = $('stored-wallet-date');
        if (dateEl) dateEl.textContent = `Saved on ${new Date().toLocaleDateString()}`;
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login';
    }
  });

  // Unlock stored wallet with PIN
  $('unlock-stored-wallet')?.addEventListener('click', async () => {
    const pin = $('pin-input-unlock')?.value;
    if (!pin || pin.length !== 6) {
      alert('Please enter a 6-digit PIN');
      return;
    }

    const btn = $('unlock-stored-wallet');
    btn.disabled = true;
    btn.textContent = 'Unlocking...';

    try {
      const walletData = await WalletStorage.retrieveWithPIN(pin);

      let keys;
      if (walletData.type === 'password') {
        keys = await deriveKeysFromPassword(walletData.username, walletData.password);
      } else if (walletData.type === 'seed') {
        keys = await deriveKeysFromSeed(walletData.seedPhrase);
      } else {
        throw new Error('Unknown wallet type');
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
      const pinInput = $('pin-input-unlock');
      if (pinInput) pinInput.value = '';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock with PIN';
    }
  });

  // Unlock stored wallet with Passkey
  $('unlock-with-passkey')?.addEventListener('click', async () => {
    const btn = $('unlock-with-passkey');
    btn.disabled = true;
    btn.innerHTML = 'Authenticating...';

    try {
      const walletData = await WalletStorage.retrieveWithPasskey();

      let keys;
      if (walletData.type === 'password') {
        keys = await deriveKeysFromPassword(walletData.username, walletData.password);
      } else if (walletData.type === 'seed') {
        keys = await deriveKeysFromSeed(walletData.seedPhrase);
      } else {
        throw new Error('Unknown wallet type');
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Unlock with Passkey';
    }
  });

  // Forget stored wallet
  $('forget-stored-wallet')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to forget your stored wallet? You will need to enter your password or seed phrase again.')) {
      WalletStorage.clearStorage();
      const storedTab = $('stored-tab');
      if (storedTab) storedTab.style.display = 'none';
      const pinSect = $('stored-pin-section');
      if (pinSect) pinSect.style.display = 'block';
      const psSect = $('stored-passkey-section');
      if (psSect) psSect.style.display = 'none';
      const divider = $('stored-divider');
      if (divider) divider.style.display = 'none';
      // Switch to password tab
      $qa('.method-tab').forEach(t => t.classList.remove('active'));
      $qa('.method-content').forEach(c => c.classList.remove('active'));
      const pwMethod = $('password-method');
      if (pwMethod) pwMethod.classList.add('active');
      const pwTab = $q('.method-tab[data-method="password"]');
      if (pwTab) pwTab.classList.add('active');
    }
  });
}

// =============================================================================
// Main App UI Handlers
// =============================================================================

function setupMainAppHandlers() {
  // Nav actions
  $('nav-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('hero-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('nav-logout')?.addEventListener('click', logout);
  $('nav-keys')?.addEventListener('click', async () => {
    $('keys-modal')?.classList.add('active');
    deriveAndDisplayAddress();
    if (state.loggedIn) {
      const names = await resolveNames();
      updateAccountTitle(names);
    }
  });

  // Modal close handlers
  $qa('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal || e.target.classList.contains('modal-close')) {
        modal.classList.remove('active');
      }
    });
  });

  // Account modal tab switching
  $qa('.modal-tab[data-modal-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      $qa('.modal-tab[data-modal-tab]').forEach(t => t.classList.remove('active'));
      $qa('.modal-tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const target = $(tab.dataset.modalTab);
      if (target) target.classList.add('active');
    });
  });

  // vCard identity auto-save
  const VCARD_STORAGE_KEY = 'hd-wallet-vcard-identity';
  const vcardFieldIds = [
    'vcard-prefix', 'vcard-firstname', 'vcard-middlename', 'vcard-lastname',
    'vcard-suffix', 'vcard-email', 'vcard-phone', 'vcard-org', 'vcard-title',
    'vcard-street', 'vcard-city', 'vcard-region', 'vcard-postal', 'vcard-country'
  ];

  function saveVcardIdentity() {
    const data = {};
    for (const id of vcardFieldIds) {
      const el = $(id);
      if (el) data[id] = el.value;
    }
    if (state.vcardPhoto) data._photo = state.vcardPhoto;
    try { localStorage.setItem(VCARD_STORAGE_KEY, JSON.stringify(data)); } catch (e) { /* ignore */ }
  }

  function restoreVcardIdentity() {
    try {
      const raw = localStorage.getItem(VCARD_STORAGE_KEY);
      if (!raw) return;
      const data = JSON.parse(raw);
      for (const id of vcardFieldIds) {
        const el = $(id);
        if (el && data[id]) el.value = data[id];
      }
      if (data._photo) {
        state.vcardPhoto = data._photo;
        showPhotoPreview(data._photo);
      }
    } catch (e) { /* ignore */ }
  }

  restoreVcardIdentity();

  let vcardSaveTimer = null;
  function debouncedVcardSave() {
    clearTimeout(vcardSaveTimer);
    vcardSaveTimer = setTimeout(saveVcardIdentity, 500);
  }

  for (const id of vcardFieldIds) {
    $(id)?.addEventListener('input', debouncedVcardSave);
  }

  // Photo upload handler
  $('vcard-photo-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const size = 128;
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        const min = Math.min(img.width, img.height);
        const sx = (img.width - min) / 2;
        const sy = (img.height - min) / 2;
        ctx.drawImage(img, sx, sy, min, min, 0, 0, size, size);
        const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
        state.vcardPhoto = dataUrl;
        stopCamera();
        showPhotoPreview(dataUrl);
        saveVcardIdentity();
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  });

  // Photo remove handler with confirmation modal
  $('vcard-photo-remove')?.addEventListener('click', () => {
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.add('active');
  });

  $('photo-remove-yes')?.addEventListener('click', () => {
    state.vcardPhoto = null;
    resetPhotoPreview();
    saveVcardIdentity();
    const removeBtn = $('vcard-photo-remove');
    if (removeBtn) removeBtn.style.display = 'none';
    const input = $('vcard-photo-input');
    if (input) input.value = '';
    // Show upload/camera buttons again
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    if (uploadLabel) uploadLabel.style.display = '';
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const cameraBtn = $('vcard-camera-btn');
      if (cameraBtn) cameraBtn.style.display = '';
    }
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.remove('active');
  });

  $('photo-remove-no')?.addEventListener('click', () => {
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.remove('active');
  });

  function resetPhotoPreview() {
    const preview = $('vcard-photo-preview');
    if (!preview) return;
    preview.querySelectorAll('img').forEach(el => el.remove());
    const placeholder = preview.querySelector('.photo-placeholder-icon');
    if (placeholder) placeholder.style.display = '';
    const video = $('vcard-camera-video');
    if (video) video.style.display = 'none';
  }

  function showPhotoPreview(dataUrl) {
    const preview = $('vcard-photo-preview');
    if (!preview) return;
    const placeholder = preview.querySelector('.photo-placeholder-icon');
    if (placeholder) placeholder.style.display = 'none';
    const video = $('vcard-camera-video');
    if (video) video.style.display = 'none';
    preview.querySelectorAll('img').forEach(el => el.remove());
    const img = document.createElement('img');
    img.src = dataUrl;
    img.alt = 'Photo';
    preview.appendChild(img);
    const removeBtn = $('vcard-photo-remove');
    if (removeBtn) removeBtn.style.display = '';
    // Hide upload/camera buttons when photo is present
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    if (uploadLabel) uploadLabel.style.display = 'none';
    const cameraBtn = $('vcard-camera-btn');
    if (cameraBtn) cameraBtn.style.display = 'none';
  }

  // Camera support
  let cameraStream = null;
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const cameraBtn = $('vcard-camera-btn');
    if (cameraBtn && !state.vcardPhoto) cameraBtn.style.display = '';

    cameraBtn?.addEventListener('click', async () => {
      try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'user', width: { ideal: 512 }, height: { ideal: 512 } }
        });
        const video = $('vcard-camera-video');
        if (video) {
          video.srcObject = cameraStream;
          video.style.display = '';
        }
        const preview = $('vcard-photo-preview');
        if (preview) {
          const placeholder = preview.querySelector('.photo-placeholder-icon');
          if (placeholder) placeholder.style.display = 'none';
          preview.querySelectorAll('img').forEach(el => el.style.display = 'none');
        }
        cameraBtn.style.display = 'none';
        const captureBtn = $('vcard-camera-capture');
        const cancelBtn = $('vcard-camera-cancel');
        if (captureBtn) captureBtn.style.display = '';
        if (cancelBtn) cancelBtn.style.display = '';
      } catch (err) {
        console.error('Camera access denied:', err);
        alert('Could not access camera. Please check your browser permissions.');
      }
    });

    $('vcard-camera-capture')?.addEventListener('click', () => {
      const video = $('vcard-camera-video');
      if (!video) return;
      const canvas = document.createElement('canvas');
      const size = 128;
      canvas.width = size;
      canvas.height = size;
      const ctx = canvas.getContext('2d');
      const vw = video.videoWidth;
      const vh = video.videoHeight;
      const min = Math.min(vw, vh);
      const sx = (vw - min) / 2;
      const sy = (vh - min) / 2;
      ctx.drawImage(video, sx, sy, min, min, 0, 0, size, size);
      const dataUrl = canvas.toDataURL('image/jpeg', 0.7);
      state.vcardPhoto = dataUrl;
      stopCamera();
      showPhotoPreview(dataUrl);
      saveVcardIdentity();
    });

    $('vcard-camera-cancel')?.addEventListener('click', () => {
      stopCamera();
      if (state.vcardPhoto) {
        showPhotoPreview(state.vcardPhoto);
      } else {
        resetPhotoPreview();
      }
    });
  }

  function stopCamera() {
    if (cameraStream) {
      cameraStream.getTracks().forEach(t => t.stop());
      cameraStream = null;
    }
    const video = $('vcard-camera-video');
    if (video) {
      video.srcObject = null;
      video.style.display = 'none';
    }
    const cameraBtn = $('vcard-camera-btn');
    const captureBtn = $('vcard-camera-capture');
    const cancelBtn = $('vcard-camera-cancel');
    if (cameraBtn) cameraBtn.style.display = state.vcardPhoto ? 'none' : '';
    if (captureBtn) captureBtn.style.display = 'none';
    if (cancelBtn) cancelBtn.style.display = 'none';
  }

  // VCF import handler
  $('vcf-import-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const vcfText = ev.target.result;
      parseAndDisplayVCF(vcfText);
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  // Reveal sensitive key buttons
  $qa('.reveal-key-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const targetEl = $(targetId);
      if (targetEl) {
        const isRevealed = targetEl.dataset.revealed === 'true';
        targetEl.dataset.revealed = isRevealed ? 'false' : 'true';
        btn.innerHTML = isRevealed
          ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'
          : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
      }
    });
  });

  // Copy key buttons
  $qa('.copy-key-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.dataset.copy;
      const targetEl = $(targetId);
      if (targetEl) {
        try {
          await navigator.clipboard.writeText(targetEl.dataset.fullValue || targetEl.textContent);
          btn.classList.add('copied');
          setTimeout(() => btn.classList.remove('copied'), 1500);
        } catch (err) {
          console.error('Copy failed:', err);
        }
      }
    });
  });

  // Export wallet dropdown
  const exportBtn = $('export-wallet-btn');
  const exportMenu = $('export-menu');
  if (exportBtn && exportMenu) {
    exportBtn.addEventListener('click', () => {
      exportMenu.classList.toggle('active');
    });

    _root.addEventListener('click', (e) => {
      if (!exportBtn.contains(e.target) && !exportMenu.contains(e.target)) {
        exportMenu.classList.remove('active');
      }
    });

    $qa('.export-option').forEach(option => {
      option.addEventListener('click', async () => {
        const format = option.dataset.format;
        await exportWallet(format);
        exportMenu.classList.remove('active');
      });
    });
  }

  // Mobile menu toggle
  const mobileMenuBtn = $('nav-menu-btn');
  const mobileMenu = $('nav-mobile-menu');

  if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
      const isOpen = mobileMenu.classList.contains('open');
      mobileMenuBtn.innerHTML = isOpen
        ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    });

    const mobileLogin = $('mobile-login');
    const mobileLogout = $('mobile-logout');

    if (mobileLogin) {
      mobileLogin.addEventListener('click', () => {
        $('login-modal')?.classList.add('active');
        mobileMenu.classList.remove('open');
        mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
      });
    }

    if (mobileLogout) {
      mobileLogout.addEventListener('click', () => {
        logout();
        mobileMenu.classList.remove('open');
        mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
      });
    }
  }

  // Navigation links - scroll to sections
  $qa('.nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      $qa('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const tabEl = $(`${link.dataset.tab}-tab`);
      if (tabEl) {
        tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      if (mobileMenu) {
        mobileMenu.classList.remove('open');
        if (mobileMenuBtn) {
          mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
        }
      }
    });
  });

  // HD wallet controls
  $('hd-coin')?.addEventListener('change', () => {
    updatePathDisplay();
    deriveAndDisplayAddress();
  });
  $('hd-account')?.addEventListener('input', () => {
    updatePathDisplay();
    deriveAndDisplayAddress();
  });
  $('hd-index')?.addEventListener('input', () => {
    updatePathDisplay();
    deriveAndDisplayAddress();
  });

  // PKI clear keys
  $('pki-clear-keys')?.addEventListener('click', clearPKIKeys);

  // PKI algorithm change
  $('pki-algorithm')?.addEventListener('change', async () => {
    const newAlgorithm = $('pki-algorithm').value;
    state.pki.algorithm = newAlgorithm;

    if (state.hdRoot) {
      derivePKIKeysFromHD();
      savePKIKeys();
    } else {
      try {
        if (newAlgorithm === 'p256') {
          state.pki.alice = await p256GenerateKeyPairAsync();
          state.pki.bob = await p256GenerateKeyPairAsync();
        } else if (newAlgorithm === 'p384') {
          state.pki.alice = await p384GenerateKeyPairAsync();
          state.pki.bob = await p384GenerateKeyPairAsync();
        } else {
          const curveType = newAlgorithm === 'secp256k1' ? Curve.SECP256K1 : Curve.X25519;
          state.pki.alice = generateKeyPair(curveType);
          state.pki.bob = generateKeyPair(curveType);
        }
        savePKIKeys();
      } catch (err) {
        console.error('Failed to generate keys for', newAlgorithm, err);
        return;
      }
    }

    // Update display
    const alicePub = $('alice-public-key');
    const alicePriv = $('alice-private-key');
    const bobPub = $('bob-public-key');
    const bobPriv = $('bob-private-key');
    if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
    if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
    if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
    if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

    const algorithmNames = {
      x25519: 'X25519 (Curve25519)',
      secp256k1: 'secp256k1 (Bitcoin/Ethereum)',
      p256: 'P-256 / secp256r1 (NIST)',
      p384: 'P-384 / secp384r1 (NIST)',
    };
    const algDisplay = $('pki-algorithm-display');
    if (algDisplay) algDisplay.textContent = algorithmNames[newAlgorithm] || newAlgorithm;
  });

  // vCard generation
  $('generate-vcard')?.addEventListener('click', async () => {
    const info = {
      prefix: $('vcard-prefix')?.value || '',
      firstName: $('vcard-firstname')?.value || '',
      middleName: $('vcard-middlename')?.value || '',
      lastName: $('vcard-lastname')?.value || '',
      suffix: $('vcard-suffix')?.value || '',
      email: $('vcard-email')?.value || '',
      org: $('vcard-org')?.value || '',
      title: $('vcard-title')?.value || '',
      includeKeys: true,
    };

    if (!info.firstName && !info.lastName) {
      alert('Please enter at least a first or last name');
      return;
    }

    const vcard = generateVCard(info);
    const vcardForQR = generateVCard(info, { skipPhoto: true });
    const vcardPreview = $('vcard-preview');
    if (vcardPreview) vcardPreview.textContent = vcard;

    try {
      const qrCanvas = $('qr-code');
      if (qrCanvas) {
        await QRCode.toCanvas(qrCanvas, vcardForQR, {
          width: 256,
          margin: 2,
          color: { dark: '#1e293b', light: '#ffffff' },
        });
      }
      const formView = $('vcard-form-view');
      const resultView = $('vcard-result-view');
      if (formView) formView.style.display = 'none';
      if (resultView) resultView.style.display = '';
    } catch (err) {
      alert('Error generating QR code: ' + err.message);
    }
  });

  // Back to editor from result view
  $('vcard-back-btn')?.addEventListener('click', () => {
    const resultView = $('vcard-result-view');
    const formView = $('vcard-form-view');
    if (resultView) resultView.style.display = 'none';
    if (formView) formView.style.display = '';
  });

  // Download vCard
  $('download-vcard')?.addEventListener('click', () => {
    const vcard = $('vcard-preview')?.textContent || '';
    const blob = new Blob([vcard], { type: 'text/vcard' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'contact.vcf';
    a.click();
    URL.revokeObjectURL(url);
  });

  // Copy vCard
  $('copy-vcard')?.addEventListener('click', async () => {
    const vcard = $('vcard-preview')?.textContent || '';
    try {
      await navigator.clipboard.writeText(vcard);
      const btn = $('copy-vcard');
      if (btn) {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy vCard'; }, 2000);
      }
    } catch (err) {
      alert('Failed to copy: ' + err.message);
    }
  });

  // Refresh balances button
  $('refresh-balances')?.addEventListener('click', () => {
    updateAdversarialSecurity();
  });

  // Escape key closes modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $qa('.modal.active').forEach(m => m.classList.remove('active'));
    }
  });

  // Trust system handlers
  setupTrustHandlers();
}

// =============================================================================
// Trust System Handlers
// =============================================================================

function setupTrustHandlers() {
  let trustScanInterval = null;
  const TRUST_SCAN_INTERVAL_MS = 60000; // 60 seconds
  const TRUST_RULES_KEY = 'trust-rules';
  const TRUST_IMPORTED_KEY = 'trust-imported-txs';

  // Auto-scan trust transactions
  async function runTrustScan() {
    if (!state.loggedIn || !state.addresses) return;

    const statusEl = $('trust-scan-status');
    const labelEl = $('trust-scan-label');
    const countEl = $('trust-scan-count');
    if (statusEl) statusEl.classList.add('active');
    if (labelEl) labelEl.textContent = 'Scanning...';

    try {
      const { scanAllTrustTransactions, renderTrustList } = await import('./trust-ui.js');
      const { buildTrustGraph, analyzeTrustRelationships } = await import('./blockchain-trust.js');

      // Scan on-chain transactions
      const onChainTxs = await scanAllTrustTransactions(state.addresses);

      // Merge with imported transactions
      let importedTxs = [];
      try {
        const raw = localStorage.getItem(TRUST_IMPORTED_KEY);
        if (raw) importedTxs = JSON.parse(raw);
      } catch (e) { /* ignore */ }

      const allTxs = [...onChainTxs, ...importedTxs];

      // Deduplicate by txHash
      const seen = new Set();
      const dedupedTxs = allTxs.filter(tx => {
        if (seen.has(tx.txHash)) return false;
        seen.add(tx.txHash);
        return true;
      });

      // Build graph and analyze relationships
      const graph = buildTrustGraph(dedupedTxs);
      const relationships = analyzeTrustRelationships(state.addresses, dedupedTxs);

      // Apply trust rules
      const rules = loadTrustRules();
      if (rules.length > 0) {
        applyTrustRules(relationships, rules);
      }

      // Store in state
      state.trustGraph = graph;
      state.trustTransactions = dedupedTxs;
      state.trustRelationships = relationships;

      // Update UI
      const listEl = $('trust-list');
      if (listEl) {
        renderTrustList(listEl, relationships, state.addresses);
      }

      if (labelEl) labelEl.textContent = 'Last scan: just now';
      if (countEl) countEl.textContent = `${relationships.length} relationships`;

      console.log(`Trust scan: ${dedupedTxs.length} txs, ${relationships.length} relationships`);
    } catch (err) {
      console.error('Trust scan failed:', err);
      if (labelEl) labelEl.textContent = 'Scan failed';
    }
  }

  // Start auto-scanning
  function startTrustScanning() {
    runTrustScan();
    trustScanInterval = setInterval(runTrustScan, TRUST_SCAN_INTERVAL_MS);
  }

  // Stop auto-scanning
  function stopTrustScanning() {
    if (trustScanInterval) {
      clearInterval(trustScanInterval);
      trustScanInterval = null;
    }
    const statusEl = $('trust-scan-status');
    if (statusEl) statusEl.classList.remove('active');
  }

  // Load trust rules from localStorage
  function loadTrustRules() {
    try {
      const raw = localStorage.getItem(TRUST_RULES_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }

  // Apply trust rules to relationships
  function applyTrustRules(relationships, rules) {
    for (const rel of relationships) {
      for (const rule of rules) {
        switch (rule.type) {
          case 'mutual_tx_count':
            if (rel.direction === 'mutual' && rel.txCount >= rule.params.threshold) {
              rel.ruleLevel = Math.max(rel.ruleLevel || 0, rule.resultLevel);
            }
            break;
          case 'last_interaction_days': {
            const daysSince = (Date.now() - rel.lastSeen) / (1000 * 60 * 60 * 24);
            if (daysSince <= rule.params.threshold) {
              rel.ruleLevel = Math.max(rel.ruleLevel || 0, rule.resultLevel);
            }
            break;
          }
          case 'bidirectional_trust':
            if (rel.direction === 'mutual') {
              rel.ruleLevel = Math.min((rel.level || 2) + 1, 5);
            }
            break;
          case 'address_blocklist':
            // Handled by NEVER trust level on-chain
            break;
        }
      }
    }
  }

  // Establish trust button
  $('establish-trust-btn')?.addEventListener('click', async () => {
    if (!state.loggedIn) { alert('Please login first'); return; }
    const { showEstablishTrustModal } = await import('./trust-ui.js');
    showEstablishTrustModal(({ level, network, recipientAddress }) => {
      console.log('Establish trust:', { level, network, recipientAddress });
      // TODO: Build, sign, and broadcast trust transaction
      alert(`Trust transaction would be published on ${network.toUpperCase()} for level ${level}.\nTransaction signing/broadcasting is not yet implemented.`);
    });
  });

  // Rules button
  $('trust-rules-btn')?.addEventListener('click', async () => {
    const { showRulesModal } = await import('./trust-ui.js');
    const currentRules = loadTrustRules();
    showRulesModal(currentRules, (updatedRules) => {
      localStorage.setItem(TRUST_RULES_KEY, JSON.stringify(updatedRules));
      // Re-apply rules
      if (state.trustRelationships) {
        applyTrustRules(state.trustRelationships, updatedRules);
        runTrustScan();
      }
    });
  });

  // Export trust data
  $('trust-export-btn')?.addEventListener('click', async () => {
    if (!state.trustTransactions || state.trustTransactions.length === 0) {
      alert('No trust data to export. Wait for a scan to complete.');
      return;
    }
    const { exportTrustData } = await import('./trust-ui.js');
    const xpub = state.hdRoot ? state.hdRoot.publicExtendedKey() : '';
    exportTrustData(state.trustTransactions, xpub);
  });

  // Import trust data
  $('trust-import-input')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const { importTrustData } = await import('./trust-ui.js');
      const importedTxs = await importTrustData(file);

      // Merge with existing imported txs
      let existing = [];
      try {
        const raw = localStorage.getItem(TRUST_IMPORTED_KEY);
        if (raw) existing = JSON.parse(raw);
      } catch (err) { /* ignore */ }

      const merged = [...existing, ...importedTxs];
      const seen = new Set();
      const deduped = merged.filter(tx => {
        if (seen.has(tx.txHash)) return false;
        seen.add(tx.txHash);
        return true;
      });

      localStorage.setItem(TRUST_IMPORTED_KEY, JSON.stringify(deduped));
      alert(`Imported ${importedTxs.length} trust transactions.`);

      // Re-scan to incorporate
      runTrustScan();
    } catch (err) {
      console.error('Trust import failed:', err);
      alert('Failed to import trust data: ' + err.message);
    }
    e.target.value = '';
  });

  // Expose start/stop for login/logout
  state._startTrustScanning = startTrustScanning;
  state._stopTrustScanning = stopTrustScanning;
}

// =============================================================================
// Homepage Handlers
// =============================================================================

function setupHomepageHandlers() {
  // Version tag
  const versionTag = $('version-tag');
  if (versionTag) {
    try {
      const pkg = __APP_VERSION__;
      versionTag.textContent = pkg ? `v${pkg}` : '';
    } catch { /* ignore */ }
  }

  // Code copy buttons
  document.querySelectorAll('.code-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.closest('.code-block')?.querySelector('code');
      if (code) {
        navigator.clipboard.writeText(code.textContent).then(() => {
          btn.title = 'Copied!';
          setTimeout(() => { btn.title = 'Copy code'; }, 2000);
        });
      }
    });
  });
}

// =============================================================================
// Initialization
// =============================================================================

export async function init(rootElement) {
  if (rootElement && rootElement instanceof Node) _root = rootElement;
  const status = $('status');
  const loadingOverlay = $('loading-overlay');

  // Initialize grid animation
  initGridAnimation();

  // Initialize wallet info box state
  initWalletInfoBox();
  bindInfoHandlers();

  try {
    // Load HD wallet WASM
    if (status) status.textContent = 'Loading HD wallet module...';
    state.hdWalletModule = await initHDWallet();

    // Load saved PKI keys if available
    const hasSavedKeys = loadPKIKeys();

    state.initialized = true;

    // Update nav status
    const navStatus = $('nav-status');
    if (navStatus) {
      navStatus.className = 'nav-status ready';
    }

    // Hide loading overlay with fade
    if (loadingOverlay) {
      loadingOverlay.classList.add('hidden');
      setTimeout(() => {
        loadingOverlay.style.display = 'none';
      }, 500);
    }

    setupLoginHandlers();
    setupMainAppHandlers();
    initCurrencySelector();
    setupHomepageHandlers();

    // Handle initial hash navigation
    const initialHash = window.location.hash.slice(1);
    if (initialHash) {
      const tabEl = $(`${initialHash}-tab`);
      if (tabEl) {
        setTimeout(() => {
          tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          $qa('.nav-link[data-tab]').forEach(link => {
            link.classList.remove('active');
            if (link.dataset.tab === initialHash) {
              link.classList.add('active');
            }
          });
        }, 100);
      }
    }

    // Check if there's a stored wallet
    const storageMetadata = WalletStorage.getStorageMetadata();
    const hasStoredWallet = storageMetadata?.method && storageMetadata.method !== StorageMethod.NONE;

    // Auto-open login modal if stored wallet found
    if (hasStoredWallet) {
      const loginModal = $('login-modal');
      if (loginModal) {
        loginModal.classList.add('active');
        // Switch to stored wallet tab
        const storedTab = loginModal.querySelector('[data-tab="stored"]');
        if (storedTab) storedTab.click();
      }
    }

    // Auto-login with saved PKI keys if no stored wallet
    if (hasSavedKeys && !hasStoredWallet) {
      const tempEd25519Seed = new Uint8Array(32);
      crypto.getRandomValues(tempEd25519Seed);
      const tempKeys = {
        x25519: generateKeyPair(Curve.X25519),
        ed25519: {
          privateKey: tempEd25519Seed,
          publicKey: ed25519.getPublicKey(tempEd25519Seed),
        },
        secp256k1: generateKeyPair(Curve.SECP256K1),
        p256: await p256GenerateKeyPairAsync(),
        p384: await p384GenerateKeyPairAsync(),
      };

      login(tempKeys);
    }

  } catch (err) {
    console.error('Initialization failed:', err);
    if (status) status.textContent = `Error: ${err.message}`;
  }
}

