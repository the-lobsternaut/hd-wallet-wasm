/**
 * PKI Organization Module
 *
 * CRUD for Organizations and KeyIdentities in the PKI org tree.
 * Manages DN paths, parent-child relationships, and role assignments.
 */

import { getState } from './pki-storage.js';
import { buildDNString, parseDNString } from './sds-bridge.js';

// =============================================================================
// ID Generation
// =============================================================================

let _seq = 0;
function genId(prefix = 'org') {
  return `${prefix}-${Date.now()}-${++_seq}-${Math.random().toString(36).slice(2, 6)}`;
}

// =============================================================================
// Organization CRUD
// =============================================================================

/**
 * Create a new organization.
 * @param {Object} dn — { CN, O, OU, C, ST, L }
 * @param {string|null} parentId — parent org ID or null for root
 * @returns {Object} The new organization
 */
export function createOrganization(dn, parentId = null) {
  const state = getState();
  const org = {
    id: genId('org'),
    dn: typeof dn === 'string' ? parseDNString(dn) : { CN: '', O: '', OU: '', C: '', ST: '', L: '', ...dn },
    parentId,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  state.organizations.push(org);
  state.updatedAt = Date.now();
  return org;
}

export function getOrganization(id) {
  return getState().organizations.find(o => o.id === id) || null;
}

export function updateOrganization(id, updates) {
  const org = getOrganization(id);
  if (!org) return null;
  if (updates.dn) {
    org.dn = typeof updates.dn === 'string' ? parseDNString(updates.dn) : { ...org.dn, ...updates.dn };
  }
  org.updatedAt = Date.now();
  getState().updatedAt = Date.now();
  return org;
}

export function deleteOrganization(id) {
  const state = getState();
  // Remove child orgs recursively
  const children = state.organizations.filter(o => o.parentId === id);
  for (const child of children) deleteOrganization(child.id);
  // Remove identities under this org
  state.identities = state.identities.filter(k => k.orgId !== id);
  // Remove the org
  state.organizations = state.organizations.filter(o => o.id !== id);
  state.updatedAt = Date.now();
}

/**
 * Get child organizations of a parent.
 */
export function getChildOrgs(parentId) {
  return getState().organizations.filter(o => o.parentId === parentId);
}

/**
 * Get root organizations (no parent).
 */
export function getRootOrgs() {
  return getState().organizations.filter(o => !o.parentId);
}

/**
 * Get full DN path from root to this org.
 */
export function getOrgPath(orgId) {
  const path = [];
  let current = getOrganization(orgId);
  while (current) {
    path.unshift(current);
    current = current.parentId ? getOrganization(current.parentId) : null;
  }
  return path;
}

/**
 * Build a full DN string for an org by walking the path.
 */
export function getFullDN(orgId) {
  const path = getOrgPath(orgId);
  // Merge DN fields from root to leaf, leaf takes precedence for CN/OU
  const merged = { CN: '', O: '', OU: '', C: '', ST: '', L: '' };
  for (const org of path) {
    if (org.dn.C) merged.C = org.dn.C;
    if (org.dn.ST) merged.ST = org.dn.ST;
    if (org.dn.L) merged.L = org.dn.L;
    if (org.dn.O) merged.O = org.dn.O;
  }
  // Leaf-specific
  const leaf = path[path.length - 1];
  if (leaf) {
    merged.CN = leaf.dn.CN;
    merged.OU = leaf.dn.OU;
  }
  return buildDNString(merged);
}

// =============================================================================
// Key Identity CRUD
// =============================================================================

/**
 * Create a key identity under an organization.
 * @param {string} orgId — parent organization ID
 * @param {Object} keyData — { label, curve, publicKey, address, role, derivationPath, ... }
 * @returns {Object} The new key identity
 */
export function createKeyIdentity(orgId, keyData) {
  const state = getState();
  const identity = {
    id: genId('key'),
    orgId,
    label: keyData.label || '',
    curve: keyData.curve || 'secp256k1',
    publicKey: keyData.publicKey || null,
    address: keyData.address || null,
    role: keyData.role || 'signing', // 'signing' | 'encryption' | 'root' | 'personnel'
    derivationPath: keyData.derivationPath || null,
    xpub: keyData.xpub || null,
    certId: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  state.identities.push(identity);
  state.updatedAt = Date.now();
  return identity;
}

export function getKeyIdentity(id) {
  return getState().identities.find(k => k.id === id) || null;
}

export function updateKeyIdentity(id, updates) {
  const key = getKeyIdentity(id);
  if (!key) return null;
  Object.assign(key, updates, { updatedAt: Date.now() });
  getState().updatedAt = Date.now();
  return key;
}

export function deleteKeyIdentity(id) {
  const state = getState();
  state.identities = state.identities.filter(k => k.id !== id);
  // Also remove associated certificates
  state.certificates = state.certificates.filter(c => c.keyIdentityId !== id);
  state.updatedAt = Date.now();
}

/**
 * Get all key identities for an organization.
 */
export function getOrgIdentities(orgId) {
  return getState().identities.filter(k => k.orgId === orgId);
}

/**
 * Get all identities (flat list).
 */
export function getAllIdentities() {
  return getState().identities;
}

// =============================================================================
// Certificate References
// =============================================================================

/**
 * Store a certificate reference linked to a key identity.
 */
export function addCertificate(certData) {
  const state = getState();
  const cert = {
    id: genId('cert'),
    keyIdentityId: certData.keyIdentityId || null,
    orgId: certData.orgId || null,
    subjectDN: certData.subjectDN || '',
    issuerDN: certData.issuerDN || '',
    issuerCertId: certData.issuerCertId || null,
    serialNumber: certData.serialNumber || '',
    validFrom: certData.validFrom || Date.now(),
    validTo: certData.validTo || Date.now() + 365 * 24 * 60 * 60 * 1000,
    curve: certData.curve || 'P-256',
    fingerprint: certData.fingerprint || '',
    pem: certData.pem || '',
    isCA: certData.isCA || false,
    createdAt: Date.now(),
  };
  state.certificates.push(cert);
  // Link to key identity
  if (cert.keyIdentityId) {
    const key = getKeyIdentity(cert.keyIdentityId);
    if (key) key.certId = cert.id;
  }
  state.updatedAt = Date.now();
  return cert;
}

export function getCertificate(id) {
  return getState().certificates.find(c => c.id === id) || null;
}

export function getCertificatesForOrg(orgId) {
  return getState().certificates.filter(c => c.orgId === orgId);
}

export function deleteCertificate(id) {
  const state = getState();
  const cert = getCertificate(id);
  if (cert && cert.keyIdentityId) {
    const key = getKeyIdentity(cert.keyIdentityId);
    if (key && key.certId === id) key.certId = null;
  }
  state.certificates = state.certificates.filter(c => c.id !== id);
  state.updatedAt = Date.now();
}

// =============================================================================
// Tree Structure Helpers (for UI)
// =============================================================================

/**
 * Build a tree structure for rendering.
 * Returns array of root nodes, each with { org, children[], identities[], certificates[] }
 */
export function buildOrgTree() {
  const state = getState();

  function buildNode(org) {
    const children = getChildOrgs(org.id).map(buildNode);
    const identities = getOrgIdentities(org.id);
    const certificates = getCertificatesForOrg(org.id);
    return { org, children, identities, certificates };
  }

  return getRootOrgs().map(buildNode);
}

/**
 * Reparent an organization under a new parent.
 */
export function reparentOrg(orgId, newParentId) {
  const org = getOrganization(orgId);
  if (!org) return;
  // Prevent circular reference
  const path = getOrgPath(newParentId);
  if (path.some(p => p.id === orgId)) return;
  org.parentId = newParentId;
  org.updatedAt = Date.now();
  getState().updatedAt = Date.now();
}
