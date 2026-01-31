/**
 * PKI X.509 Certificate Module
 *
 * Certificate generation, chain building, and import/export using
 * @peculiar/x509 with NIST curves (P-256, P-384) only.
 * Supports embedding xpub + secp256k1 signature as custom X.509 extensions.
 */

import * as x509 from '@peculiar/x509';
import { addCertificate, getKeyIdentity, getCertificate } from './pki-org.js';
import { buildDNString } from './sds-bridge.js';

// =============================================================================
// Crypto Provider Initialization
// =============================================================================

const cryptoProvider = new x509.CryptoProvider();
x509.cryptoProvider.set(crypto);

// Custom OIDs for wallet extensions
const OID_XPUB = '1.3.6.1.4.1.99999.1.1';        // xpub value
const OID_XPUB_SIGNATURE = '1.3.6.1.4.1.99999.1.2'; // secp256k1 signature over xpub

// Allowed curves for certificate generation
const ALLOWED_CURVES = { 'P-256': 'ECDSA', 'P-384': 'ECDSA' };

// =============================================================================
// Key Pair Generation (NIST curves only)
// =============================================================================

/**
 * Generate an ECDSA key pair for certificate use.
 * @param {'P-256'|'P-384'} namedCurve
 * @returns {Promise<CryptoKeyPair>}
 */
export async function generateKeyPair(namedCurve = 'P-256') {
  if (!ALLOWED_CURVES[namedCurve]) {
    throw new Error(`Only NIST curves (P-256, P-384) allowed for certificates. Got: ${namedCurve}`);
  }
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve },
    true,
    ['sign', 'verify']
  );
}

/**
 * Export a CryptoKey to hex string.
 */
export async function exportKeyHex(key) {
  const format = key.type === 'private' ? 'pkcs8' : 'spki';
  const buf = await crypto.subtle.exportKey(format, key);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// =============================================================================
// Certificate Generation
// =============================================================================

/**
 * Generate a self-signed root CA certificate.
 *
 * @param {Object} opts
 * @param {Object} opts.dn — { CN, O, OU, C, ST, L }
 * @param {CryptoKeyPair} opts.keys — ECDSA key pair
 * @param {number} opts.validityYears — years of validity (default 10)
 * @param {string} opts.xpub — optional xpub to embed
 * @param {Uint8Array} opts.xpubSignature — optional secp256k1 sig over xpub
 * @param {string} opts.orgId — org ID for storage
 * @param {string} opts.keyIdentityId — key identity ID for storage
 * @returns {Promise<x509.X509Certificate>}
 */
export async function generateRootCA(opts) {
  const { dn, keys, validityYears = 10, xpub, xpubSignature, orgId, keyIdentityId } = opts;
  const dnStr = typeof dn === 'string' ? dn : buildDNString(dn);
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + validityYears);

  const extensions = [
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
      true
    ),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ];

  // Embed xpub as custom extension
  if (xpub) {
    extensions.push(new x509.Extension(OID_XPUB, false, new TextEncoder().encode(xpub)));
  }
  if (xpubSignature) {
    extensions.push(new x509.Extension(OID_XPUB_SIGNATURE, false, xpubSignature));
  }

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: generateSerialNumber(),
    name: dnStr,
    notBefore: now,
    notAfter,
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions,
  });

  // Store certificate reference
  if (orgId || keyIdentityId) {
    storeCert(cert, { orgId, keyIdentityId, isCA: true });
  }

  return cert;
}

/**
 * Generate an intermediate CA certificate signed by a parent CA.
 */
export async function generateIntermediateCA(opts) {
  const { dn, keys, signerKey, signerCert, validityYears = 5, orgId, keyIdentityId } = opts;
  const dnStr = typeof dn === 'string' ? dn : buildDNString(dn);
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + validityYears);

  const extensions = [
    new x509.BasicConstraintsExtension(true, 0, true),
    new x509.KeyUsagesExtension(
      x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
      true
    ),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(signerCert),
  ];

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: generateSerialNumber(),
    subject: dnStr,
    issuer: signerCert.subject,
    notBefore: now,
    notAfter,
    signingKey: signerKey,
    publicKey: keys.publicKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions,
  });

  if (orgId || keyIdentityId) {
    storeCert(cert, { orgId, keyIdentityId, isCA: true, issuerCertId: opts.issuerCertId });
  }

  return cert;
}

/**
 * Generate an end-entity certificate signed by a CA.
 */
export async function generateEndEntity(opts) {
  const {
    dn, publicKey, signerKey, signerCert, validityYears = 2,
    xpub, xpubSignature, orgId, keyIdentityId, issuerCertId,
  } = opts;
  const dnStr = typeof dn === 'string' ? dn : buildDNString(dn);
  const now = new Date();
  const notAfter = new Date(now);
  notAfter.setFullYear(notAfter.getFullYear() + validityYears);

  const extensions = [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    await x509.SubjectKeyIdentifierExtension.create(publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(signerCert),
  ];

  if (xpub) {
    extensions.push(new x509.Extension(OID_XPUB, false, new TextEncoder().encode(xpub)));
  }
  if (xpubSignature) {
    extensions.push(new x509.Extension(OID_XPUB_SIGNATURE, false, xpubSignature));
  }

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: generateSerialNumber(),
    subject: dnStr,
    issuer: signerCert.subject,
    notBefore: now,
    notAfter,
    signingKey: signerKey,
    publicKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions,
  });

  if (orgId || keyIdentityId) {
    storeCert(cert, { orgId, keyIdentityId, isCA: false, issuerCertId });
  }

  return cert;
}

// =============================================================================
// Certificate Import / Export
// =============================================================================

/**
 * Import a PEM-encoded certificate.
 * @param {string} pem
 * @param {Object} linkOpts — { orgId, keyIdentityId }
 * @returns {x509.X509Certificate}
 */
export function importPEM(pem, linkOpts = {}) {
  const cert = new x509.X509Certificate(pem);
  storeCert(cert, linkOpts);
  return cert;
}

/**
 * Import DER binary certificate.
 */
export function importDER(derBuffer, linkOpts = {}) {
  const cert = new x509.X509Certificate(derBuffer);
  storeCert(cert, linkOpts);
  return cert;
}

/**
 * Export certificate as PEM string.
 */
export function exportPEM(cert) {
  return cert.toString('pem');
}

/**
 * Export certificate chain as concatenated PEM.
 */
export function exportChainPEM(certIds) {
  return certIds
    .map(id => getCertificate(id))
    .filter(Boolean)
    .map(c => c.pem)
    .join('\n');
}

// =============================================================================
// Certificate Verification
// =============================================================================

/**
 * Verify a certificate against an issuer certificate.
 */
export async function verifyCertificate(cert, issuerCert) {
  try {
    const result = await cert.verify({ publicKey: issuerCert.publicKey });
    return result;
  } catch {
    return false;
  }
}

/**
 * Build certificate chain from end entity to root.
 * @param {string} certId — starting cert ID
 * @returns {Object[]} Array of cert records from leaf to root
 */
export function buildChain(certId) {
  const chain = [];
  let current = getCertificate(certId);
  const visited = new Set();
  while (current && !visited.has(current.id)) {
    visited.add(current.id);
    chain.push(current);
    if (current.issuerCertId) {
      current = getCertificate(current.issuerCertId);
    } else {
      break;
    }
  }
  return chain;
}

// =============================================================================
// X.509 Extension Extraction
// =============================================================================

/**
 * Extract xpub from a certificate's custom extension.
 */
export function extractXpub(cert) {
  try {
    const ext = cert.getExtension(OID_XPUB);
    if (!ext) return null;
    return new TextDecoder().decode(ext.value);
  } catch {
    return null;
  }
}

/**
 * Extract xpub signature from a certificate's custom extension.
 */
export function extractXpubSignature(cert) {
  try {
    const ext = cert.getExtension(OID_XPUB_SIGNATURE);
    if (!ext) return null;
    return new Uint8Array(ext.value);
  } catch {
    return null;
  }
}

// =============================================================================
// Internal Helpers
// =============================================================================

function generateSerialNumber() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function storeCert(cert, opts = {}) {
  const pem = cert.toString('pem');
  const fingerprint = Array.from(new Uint8Array(cert.rawData.slice(0, 32)))
    .map(b => b.toString(16).padStart(2, '0')).join(':');

  addCertificate({
    keyIdentityId: opts.keyIdentityId || null,
    orgId: opts.orgId || null,
    subjectDN: cert.subject,
    issuerDN: cert.issuer,
    issuerCertId: opts.issuerCertId || null,
    serialNumber: cert.serialNumber,
    validFrom: cert.notBefore.getTime(),
    validTo: cert.notAfter.getTime(),
    curve: detectCurve(cert),
    fingerprint,
    pem,
    isCA: opts.isCA || false,
  });
}

function detectCurve(cert) {
  try {
    const algo = cert.publicKey.algorithm;
    return algo.namedCurve || 'unknown';
  } catch {
    return 'unknown';
  }
}
