/**
 * SpaceDataStandards Bridge Module
 *
 * Converts between wallet-ui data models and SpaceDataStandards FlatBuffers
 * formats (EPM, EME) for interoperable key/identity import/export.
 */

import * as flatbuffers from 'flatbuffers';
import { EPM, EPMT } from '@sds/lib/js/EPM/EPM.js';
import { CryptoKeyT } from '@sds/lib/js/EPM/CryptoKey.js';
import { AddressT } from '@sds/lib/js/EPM/Address.js';
import { KeyType } from '@sds/lib/js/EPM/KeyType.js';
import { EME, EMET } from '@sds/lib/js/EME/EME.js';

// =============================================================================
// DN Parsing / Formatting
// =============================================================================

/**
 * Build X.500 DN string from structured fields.
 * e.g. "CN=Alice, OU=Engineering, O=Acme Corp, C=US"
 */
export function buildDNString(dn) {
  const parts = [];
  if (dn.CN) parts.push(`CN=${dn.CN}`);
  if (dn.OU) parts.push(`OU=${dn.OU}`);
  if (dn.O) parts.push(`O=${dn.O}`);
  if (dn.L) parts.push(`L=${dn.L}`);
  if (dn.ST) parts.push(`ST=${dn.ST}`);
  if (dn.C) parts.push(`C=${dn.C}`);
  return parts.join(', ');
}

/**
 * Parse X.500 DN string into structured fields.
 */
export function parseDNString(dnStr) {
  const dn = { CN: '', O: '', OU: '', C: '', ST: '', L: '' };
  if (!dnStr) return dn;
  const parts = dnStr.split(/,\s*/);
  for (const part of parts) {
    const [key, ...rest] = part.split('=');
    const value = rest.join('=');
    if (key && value && key.toUpperCase() in dn) {
      dn[key.toUpperCase()] = value;
    }
  }
  return dn;
}

// =============================================================================
// Curve / Address Type Mapping
// =============================================================================

const CURVE_TO_ADDRESS_TYPE = {
  secp256k1: '0',       // BTC coin type
  ed25519: '501',        // SOL coin type
  'P-256': 'NIST-P256',
  'P-384': 'NIST-P384',
  x25519: 'X25519',
};

const ADDRESS_TYPE_TO_CURVE = {};
for (const [k, v] of Object.entries(CURVE_TO_ADDRESS_TYPE)) {
  ADDRESS_TYPE_TO_CURVE[v] = k;
}

// =============================================================================
// CryptoKey Conversion
// =============================================================================

/**
 * Convert a wallet KeyIdentity to a CryptoKeyT for FlatBuffers packing.
 */
export function buildCryptoKey(key, opts = {}) {
  return new CryptoKeyT(
    key.publicKey || null,
    opts.xpub || null,
    opts.includePrivate ? (key.privateKey || null) : null,
    opts.includePrivate ? (opts.xpriv || null) : null,
    key.address || null,
    CURVE_TO_ADDRESS_TYPE[key.curve] || key.curve || null,
    key.role === 'encryption' ? KeyType.Encryption : KeyType.Signing,
  );
}

/**
 * Convert a parsed CryptoKeyT from FlatBuffers to wallet key format.
 */
export function parseCryptoKey(fbKey) {
  return {
    publicKey: fbKey.PUBLIC_KEY || null,
    xpub: fbKey.XPUB || null,
    privateKey: fbKey.PRIVATE_KEY || null,
    xpriv: fbKey.XPRIV || null,
    address: fbKey.KEY_ADDRESS || null,
    curve: ADDRESS_TYPE_TO_CURVE[fbKey.ADDRESS_TYPE] || fbKey.ADDRESS_TYPE || null,
    role: fbKey.KEY_TYPE === KeyType.Encryption ? 'encryption' : 'signing',
  };
}

// =============================================================================
// EPM Build / Parse
// =============================================================================

/**
 * Build an EPM FlatBuffer from wallet identity + keys.
 *
 * @param {Object} identity — { dn, label, email, jobTitle, keys[], ... }
 * @param {Object} opts — { includePrivate: false, xpub, xpriv }
 * @returns {Uint8Array} FlatBuffer binary
 */
export function buildEPM(identity, opts = {}) {
  const epmT = new EPMT();

  // DN
  if (identity.dn) {
    epmT.DN = typeof identity.dn === 'string' ? identity.dn : buildDNString(identity.dn);
  }

  // Name fields
  epmT.LEGAL_NAME = identity.orgName || identity.label || null;
  epmT.FAMILY_NAME = identity.familyName || null;
  epmT.GIVEN_NAME = identity.givenName || null;
  epmT.ADDITIONAL_NAME = identity.additionalName || null;
  epmT.HONORIFIC_PREFIX = identity.prefix || null;
  epmT.HONORIFIC_SUFFIX = identity.suffix || null;
  epmT.JOB_TITLE = identity.jobTitle || null;
  epmT.OCCUPATION = identity.occupation || null;
  epmT.EMAIL = identity.email || null;
  epmT.TELEPHONE = identity.telephone || null;

  // Address
  if (identity.address) {
    epmT.ADDRESS = new AddressT(
      identity.address.C || identity.address.COUNTRY || null,
      identity.address.ST || identity.address.REGION || null,
      identity.address.L || identity.address.LOCALITY || null,
      identity.address.postalCode || null,
      identity.address.street || null,
      null,
    );
  }

  // Keys
  if (identity.keys && identity.keys.length > 0) {
    epmT.KEYS = identity.keys.map(k => buildCryptoKey(k, opts));
  }

  // Multiformat addresses
  if (identity.multiformatAddresses) {
    epmT.MULTIFORMAT_ADDRESS = identity.multiformatAddresses;
  }

  const builder = new flatbuffers.Builder(1024);
  const offset = epmT.pack(builder);
  EPM.finishEPMBuffer(builder, offset);
  return builder.asUint8Array();
}

/**
 * Parse an EPM FlatBuffer binary into wallet identity format.
 *
 * @param {Uint8Array} buffer — FlatBuffer binary
 * @returns {Object} Parsed identity
 */
export function parseEPM(buffer) {
  const buf = new flatbuffers.ByteBuffer(buffer);
  const epm = EPM.getRootAsEPM(buf);
  const epmT = epm.unpack();

  const dn = parseDNString(epmT.DN);

  const keys = (epmT.KEYS || []).map(parseCryptoKey);

  return {
    dn,
    dnString: epmT.DN,
    orgName: epmT.LEGAL_NAME,
    familyName: epmT.FAMILY_NAME,
    givenName: epmT.GIVEN_NAME,
    additionalName: epmT.ADDITIONAL_NAME,
    prefix: epmT.HONORIFIC_PREFIX,
    suffix: epmT.HONORIFIC_SUFFIX,
    jobTitle: epmT.JOB_TITLE,
    occupation: epmT.OCCUPATION,
    email: epmT.EMAIL,
    telephone: epmT.TELEPHONE,
    address: epmT.ADDRESS ? {
      C: epmT.ADDRESS.COUNTRY,
      ST: epmT.ADDRESS.REGION,
      L: epmT.ADDRESS.LOCALITY,
      postalCode: epmT.ADDRESS.POSTAL_CODE,
      street: epmT.ADDRESS.STREET,
    } : null,
    keys,
    multiformatAddresses: epmT.MULTIFORMAT_ADDRESS || [],
  };
}

// =============================================================================
// EME Build / Parse (Encrypted Message Envelope)
// =============================================================================

/**
 * Build an EME FlatBuffer from encrypted data.
 *
 * @param {Uint8Array} ciphertext — Encrypted data
 * @param {Object} params — { iv, tag, nonce, cipherSuite, kdfParams, ... }
 * @returns {Uint8Array} FlatBuffer binary
 */
export function buildEME(ciphertext, params = {}) {
  const emeT = new EMET();
  emeT.ENCRYPTED_BLOB = Array.from(ciphertext);
  emeT.IV = params.iv || null;
  emeT.TAG = params.tag || null;
  emeT.NONCE = params.nonce || null;
  emeT.CIPHER_SUITE = params.cipherSuite || 'AES-256-GCM';
  emeT.KDF_PARAMETERS = params.kdfParams || null;
  emeT.ENCRYPTION_ALGORITHM_PARAMETERS = params.algParams || null;
  emeT.PUBLIC_KEY_IDENTIFIER = params.publicKeyId || null;
  emeT.EPHEMERAL_PUBLIC_KEY = params.ephemeralPublicKey || null;
  emeT.MAC = params.mac || null;

  const builder = new flatbuffers.Builder(ciphertext.length + 512);
  const offset = emeT.pack(builder);
  EME.finishEMEBuffer(builder, offset);
  return builder.asUint8Array();
}

/**
 * Parse an EME FlatBuffer binary into encrypted data + params.
 *
 * @param {Uint8Array} buffer — FlatBuffer binary
 * @returns {Object} { ciphertext: Uint8Array, iv, tag, nonce, cipherSuite, ... }
 */
export function parseEME(buffer) {
  const buf = new flatbuffers.ByteBuffer(buffer);
  const eme = EME.getRootAsEME(buf);

  return {
    ciphertext: eme.encryptedBlobArray() ? new Uint8Array(eme.encryptedBlobArray()) : new Uint8Array(0),
    iv: eme.IV(),
    tag: eme.TAG(),
    nonce: eme.NONCE(),
    cipherSuite: eme.CIPHER_SUITE(),
    kdfParams: eme.KDF_PARAMETERS(),
    algParams: eme.ENCRYPTION_ALGORITHM_PARAMETERS(),
    publicKeyId: eme.PUBLIC_KEY_IDENTIFIER(),
    ephemeralPublicKey: eme.EPHEMERAL_PUBLIC_KEY(),
    mac: eme.MAC(),
  };
}

// =============================================================================
// Utility: base64 encode/decode for vCard embedding
// =============================================================================

export function bufferToBase64(uint8arr) {
  let binary = '';
  for (let i = 0; i < uint8arr.length; i++) {
    binary += String.fromCharCode(uint8arr[i]);
  }
  return btoa(binary);
}

export function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
