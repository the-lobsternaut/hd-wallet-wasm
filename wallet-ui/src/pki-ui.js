/**
 * PKI UI Controller
 *
 * Wires PKI tab interactions: org tree rendering, detail panels,
 * CRUD operations, trust policy management, import/export.
 */

import {
  createOrganization, getOrganization, updateOrganization, deleteOrganization,
  getChildOrgs, getRootOrgs, getOrgPath, getFullDN,
  createKeyIdentity, getKeyIdentity, deleteKeyIdentity, getOrgIdentities,
  addCertificate, getCertificate, getCertificatesForOrg, deleteCertificate,
  buildOrgTree,
} from './pki-org.js';
import { getState, saveState, exportAsPasswordEME, importFromPasswordEME } from './pki-storage.js';
import { buildDNString, buildEPM, parseEPM, bufferToBase64, base64ToBuffer } from './sds-bridge.js';
import { createPolicy, addRule, removeRule, RULE_METADATA } from './trust-rules.js';
import { evaluatePolicy, buildContext } from './trust-engine.js';

// Current selection state
let _selectedType = null; // 'org' | 'key' | 'cert'
let _selectedId = null;
let _root = null; // shadow root or document

// =============================================================================
// Initialization
// =============================================================================

export function initPKI(root = document) {
  _root = root;

  // Tree add root org button
  const addBtn = _root.getElementById('pki-add-root-org');
  if (addBtn) addBtn.addEventListener('click', () => handleAddOrg(null));

  // Org detail save button
  const saveBtn = _root.getElementById('pki-save-org');
  if (saveBtn) saveBtn.addEventListener('click', handleSaveOrg);

  // Add key button
  const addKeyBtn = _root.getElementById('pki-add-key');
  if (addKeyBtn) addKeyBtn.addEventListener('click', handleAddKey);

  // Gen cert button
  const genCertBtn = _root.getElementById('pki-gen-cert');
  if (genCertBtn) genCertBtn.addEventListener('click', handleGenCert);

  // Import / export
  const importBtn = _root.getElementById('pki-import-btn');
  const importFile = _root.getElementById('pki-import-file');
  if (importBtn && importFile) {
    importBtn.addEventListener('click', () => importFile.click());
    importFile.addEventListener('change', handleImport);
  }

  const exportBtn = _root.getElementById('pki-export-btn');
  if (exportBtn) exportBtn.addEventListener('click', handleExport);

  // Add policy button
  const addPolicyBtn = _root.getElementById('pki-add-policy');
  if (addPolicyBtn) addPolicyBtn.addEventListener('click', handleAddPolicy);

  // Address analysis
  const analyzeBtn = _root.getElementById('pki-analyze-btn');
  if (analyzeBtn) analyzeBtn.addEventListener('click', handleAnalyzeAddresses);

  renderTree();
  renderPolicies();
}

// =============================================================================
// Tree Rendering
// =============================================================================

export function renderTree() {
  const container = _root.getElementById('pki-tree');
  if (!container) return;

  const tree = buildOrgTree();

  if (tree.length === 0) {
    container.innerHTML = '<div class="pki-tree-empty">No organizations. Click + to create one.</div>';
    return;
  }

  container.innerHTML = '';
  for (const node of tree) {
    container.appendChild(renderTreeNode(node, 0));
  }
}

function renderTreeNode(node, depth) {
  const { org, children, identities, certificates } = node;
  const frag = document.createDocumentFragment();

  // Org node
  const hasChildren = children.length > 0 || identities.length > 0;
  const orgEl = document.createElement('div');
  orgEl.className = `pki-tree-node${_selectedType === 'org' && _selectedId === org.id ? ' selected' : ''}`;
  orgEl.style.paddingLeft = `${depth * 16 + 4}px`;
  orgEl.innerHTML = `
    <span class="pki-tree-chevron${hasChildren ? ' expanded' : ' leaf'}">&#9654;</span>
    <span class="pki-tree-icon">&#128193;</span>
    <span class="pki-tree-label">${org.dn.CN || org.dn.O || 'Unnamed'}</span>
  `;
  orgEl.addEventListener('click', (e) => {
    e.stopPropagation();
    selectOrg(org.id);
  });
  // Context menu for add child / delete
  orgEl.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    const action = confirm(`Delete "${org.dn.CN || org.dn.O || 'Unnamed'}"? (Cancel to add child instead)`);
    if (action) {
      deleteOrganization(org.id);
      if (_selectedId === org.id) clearDetail();
      renderTree();
    } else {
      handleAddOrg(org.id);
    }
  });
  frag.appendChild(orgEl);

  // Children container
  if (hasChildren) {
    const childrenEl = document.createElement('div');
    childrenEl.className = 'pki-tree-children';

    // Key identity nodes
    for (const key of identities) {
      const keyEl = document.createElement('div');
      keyEl.className = `pki-tree-node${_selectedType === 'key' && _selectedId === key.id ? ' selected' : ''}`;
      keyEl.style.paddingLeft = `${(depth + 1) * 16 + 4}px`;
      const certStatus = key.certId ? 'valid' : 'none';
      keyEl.innerHTML = `
        <span class="pki-tree-chevron leaf">&#9654;</span>
        <span class="pki-tree-icon">&#128273;</span>
        <span class="pki-tree-label">${key.label || key.curve}</span>
        <span class="pki-tree-badge ${certStatus}"></span>
      `;
      keyEl.addEventListener('click', (e) => {
        e.stopPropagation();
        selectKey(key.id);
      });
      childrenEl.appendChild(keyEl);
    }

    // Child org nodes (recursive)
    for (const child of children) {
      childrenEl.appendChild(renderTreeNode(child, depth + 1));
    }

    frag.appendChild(childrenEl);
  }

  return frag;
}

// =============================================================================
// Selection & Detail Panels
// =============================================================================

function clearDetail() {
  _selectedType = null;
  _selectedId = null;
  const detail = _root.getElementById('pki-detail-panel');
  if (!detail) return;
  showPanel('pki-detail-empty');
}

function showPanel(panelId) {
  const panels = ['pki-detail-empty', 'pki-org-detail', 'pki-key-detail', 'pki-cert-detail'];
  for (const id of panels) {
    const el = _root.getElementById(id);
    if (el) el.style.display = id === panelId ? '' : 'none';
  }
}

function selectOrg(orgId) {
  _selectedType = 'org';
  _selectedId = orgId;
  const org = getOrganization(orgId);
  if (!org) return;

  showPanel('pki-org-detail');

  // Fill DN form
  _root.getElementById('pki-org-title').textContent = org.dn.CN || org.dn.O || 'Organization';
  _root.getElementById('pki-dn-cn').value = org.dn.CN || '';
  _root.getElementById('pki-dn-o').value = org.dn.O || '';
  _root.getElementById('pki-dn-ou').value = org.dn.OU || '';
  _root.getElementById('pki-dn-c').value = org.dn.C || '';
  _root.getElementById('pki-dn-st').value = org.dn.ST || '';
  _root.getElementById('pki-dn-l').value = org.dn.L || '';

  // Render keys list
  const keyList = _root.getElementById('pki-key-list');
  const identities = getOrgIdentities(orgId);
  if (identities.length === 0) {
    keyList.innerHTML = '<div class="pki-tree-empty">No keys. Click + Key to add.</div>';
  } else {
    keyList.innerHTML = identities.map(k => `
      <div class="pki-key-item" data-key-id="${k.id}">
        <span class="pki-tree-icon">&#128273;</span>
        <span>${k.label || k.curve}</span>
        <span class="pki-badge ${k.role}">${k.role}</span>
      </div>
    `).join('');
    keyList.querySelectorAll('.pki-key-item').forEach(el => {
      el.addEventListener('click', () => selectKey(el.dataset.keyId));
    });
  }

  // Render certs list
  const certList = _root.getElementById('pki-cert-list');
  const certs = getCertificatesForOrg(orgId);
  if (certs.length === 0) {
    certList.innerHTML = '<div class="pki-tree-empty">No certificates.</div>';
  } else {
    certList.innerHTML = certs.map(c => {
      const now = Date.now();
      const valid = now >= c.validFrom && now <= c.validTo;
      return `
        <div class="pki-cert-item" data-cert-id="${c.id}">
          <span class="pki-tree-icon">&#128737;</span>
          <span>${c.subjectDN || 'Certificate'}</span>
          <span class="pki-badge ${valid ? 'valid' : 'expired'}">${valid ? 'Valid' : 'Expired'}</span>
          ${c.isCA ? '<span class="pki-badge ca">CA</span>' : ''}
        </div>
      `;
    }).join('');
    certList.querySelectorAll('.pki-cert-item').forEach(el => {
      el.addEventListener('click', () => selectCert(el.dataset.certId));
    });
  }

  renderTree();
}

function selectKey(keyId) {
  _selectedType = 'key';
  _selectedId = keyId;
  const key = getKeyIdentity(keyId);
  if (!key) return;

  showPanel('pki-key-detail');

  _root.getElementById('pki-key-title').textContent = key.label || key.curve;
  _root.getElementById('pki-key-curve').textContent = key.curve;
  _root.getElementById('pki-key-role').textContent = key.role;
  _root.getElementById('pki-key-pubkey').textContent = key.publicKey || '--';
  _root.getElementById('pki-key-address').textContent = key.address || '--';
  _root.getElementById('pki-key-path').textContent = key.derivationPath || '--';

  const certStatus = _root.getElementById('pki-key-cert-status');
  if (key.certId) {
    const cert = getCertificate(key.certId);
    const valid = cert && Date.now() >= cert.validFrom && Date.now() <= cert.validTo;
    certStatus.innerHTML = `<span class="pki-badge ${valid ? 'valid' : 'expired'}">${valid ? 'Valid' : 'Expired'}</span>`;
  } else {
    certStatus.textContent = 'None';
  }

  renderTree();
}

function selectCert(certId) {
  _selectedType = 'cert';
  _selectedId = certId;
  const cert = getCertificate(certId);
  if (!cert) return;

  showPanel('pki-cert-detail');

  _root.getElementById('pki-cert-title').textContent = 'Certificate';
  _root.getElementById('pki-cert-subject').textContent = cert.subjectDN;
  _root.getElementById('pki-cert-issuer').textContent = cert.issuerDN;
  _root.getElementById('pki-cert-from').textContent = new Date(cert.validFrom).toLocaleDateString();
  _root.getElementById('pki-cert-to').textContent = new Date(cert.validTo).toLocaleDateString();
  _root.getElementById('pki-cert-algo').textContent = cert.curve;
  _root.getElementById('pki-cert-fingerprint').textContent = cert.fingerprint;
  _root.getElementById('pki-cert-pem').textContent = cert.pem || 'N/A';

  renderTree();
}

// =============================================================================
// Handlers
// =============================================================================

function handleAddOrg(parentId) {
  const name = prompt('Organization name (CN):');
  if (!name) return;
  const org = createOrganization({ CN: name }, parentId);
  selectOrg(org.id);
  renderTree();
}

function handleSaveOrg() {
  if (_selectedType !== 'org' || !_selectedId) return;
  updateOrganization(_selectedId, {
    dn: {
      CN: _root.getElementById('pki-dn-cn').value,
      O: _root.getElementById('pki-dn-o').value,
      OU: _root.getElementById('pki-dn-ou').value,
      C: _root.getElementById('pki-dn-c').value,
      ST: _root.getElementById('pki-dn-st').value,
      L: _root.getElementById('pki-dn-l').value,
    },
  });
  selectOrg(_selectedId);
}

function handleAddKey() {
  if (_selectedType !== 'org' || !_selectedId) return;
  const curve = prompt('Curve (secp256k1, ed25519, P-256, P-384):', 'secp256k1');
  if (!curve) return;
  const label = prompt('Key label:', curve + ' key');
  const role = prompt('Role (signing, encryption, root, personnel):', 'signing');
  createKeyIdentity(_selectedId, { label, curve, role });
  selectOrg(_selectedId);
}

async function handleGenCert() {
  if (_selectedType !== 'org' || !_selectedId) return;
  const identities = getOrgIdentities(_selectedId);
  const nistKeys = identities.filter(k => k.curve === 'P-256' || k.curve === 'P-384');
  if (nistKeys.length === 0) {
    alert('Certificate generation requires a NIST curve key (P-256 or P-384). Add one first.');
    return;
  }
  // For now, create a placeholder cert record
  const key = nistKeys[0];
  const dn = getFullDN(_selectedId);
  addCertificate({
    keyIdentityId: key.id,
    orgId: _selectedId,
    subjectDN: dn,
    issuerDN: dn, // self-signed
    curve: key.curve,
    isCA: true,
  });
  selectOrg(_selectedId);
}

async function handleImport(e) {
  const file = e.target.files[0];
  if (!file) return;
  const ext = file.name.split('.').pop().toLowerCase();

  try {
    if (ext === 'json') {
      const text = await file.text();
      const data = JSON.parse(text);
      mergeImportedData(data);
    } else if (ext === 'epm') {
      const buf = new Uint8Array(await file.arrayBuffer());
      const identity = parseEPM(buf);
      // Create an org from the imported identity
      const org = createOrganization(identity.dn || { CN: identity.orgName || 'Imported' });
      if (identity.keys) {
        for (const k of identity.keys) {
          createKeyIdentity(org.id, {
            label: k.curve || 'Imported Key',
            curve: k.curve,
            publicKey: k.publicKey,
            address: k.address,
            role: k.role,
            xpub: k.xpub,
          });
        }
      }
      selectOrg(org.id);
    } else if (ext === 'eme') {
      const buf = new Uint8Array(await file.arrayBuffer());
      const password = prompt('Decryption password:');
      if (!password) return;
      const data = await importFromPasswordEME(buf, password);
      mergeImportedData(data);
    } else if (ext === 'pem' || ext === 'crt' || ext === 'cer') {
      const text = await file.text();
      // Store as cert reference
      addCertificate({
        subjectDN: 'Imported Certificate',
        pem: text,
        orgId: _selectedType === 'org' ? _selectedId : null,
      });
      if (_selectedType === 'org') selectOrg(_selectedId);
    }
    renderTree();
    renderPolicies();
  } catch (err) {
    alert('Import failed: ' + err.message);
  }
  e.target.value = '';
}

function mergeImportedData(data) {
  const state = getState();
  if (data.organizations) state.organizations.push(...data.organizations);
  if (data.identities) state.identities.push(...data.identities);
  if (data.certificates) state.certificates.push(...data.certificates);
  if (data.policies) state.policies.push(...data.policies);
  state.updatedAt = Date.now();
}

async function handleExport() {
  const format = prompt('Export format (json, epm, eme):', 'json');
  if (!format) return;

  if (format === 'json') {
    const state = getState();
    downloadBlob(JSON.stringify(state, null, 2), 'pki-export.json', 'application/json');
  } else if (format === 'epm') {
    // Export selected org as EPM
    if (_selectedType !== 'org' || !_selectedId) {
      alert('Select an organization to export as EPM.');
      return;
    }
    const org = getOrganization(_selectedId);
    const identities = getOrgIdentities(_selectedId);
    const epmData = {
      dn: org.dn,
      orgName: org.dn.O || org.dn.CN,
      keys: identities.map(k => ({
        publicKey: k.publicKey,
        curve: k.curve,
        address: k.address,
        role: k.role,
      })),
    };
    const buf = buildEPM(epmData);
    downloadBlob(buf, `${org.dn.CN || 'org'}.epm`, 'application/octet-stream');
  } else if (format === 'eme') {
    const password = prompt('Encryption password:');
    if (!password) return;
    const state = getState();
    const buf = await exportAsPasswordEME(state, password);
    downloadBlob(buf, 'pki-export.eme', 'application/octet-stream');
  }
}

function downloadBlob(data, filename, mimeType) {
  const blob = data instanceof Blob ? data : new Blob(
    [typeof data === 'string' ? data : data.buffer || data],
    { type: mimeType }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// =============================================================================
// Policy Rendering
// =============================================================================

function handleAddPolicy() {
  const name = prompt('Policy name:');
  if (!name) return;
  const state = getState();
  const policy = createPolicy(name);
  state.policies.push(policy);
  renderPolicies();
}

let _expandedPolicyId = null;

export function renderPolicies() {
  const container = _root.getElementById('pki-policy-list');
  if (!container) return;

  const state = getState();
  const policies = state.policies || [];

  if (policies.length === 0) {
    container.innerHTML = '<div class="pki-tree-empty">No policies defined.</div>';
    return;
  }

  container.innerHTML = policies.map(p => {
    const isExpanded = _expandedPolicyId === p.id;
    const severityClass = (s) => s === 'block' ? 'expired' : s === 'warn' ? 'ca' : 'valid';
    return `
      <div class="pki-policy-card" data-policy-id="${p.id}">
        <div class="pki-policy-item">
          <span class="pki-policy-name">${p.name}</span>
          <span class="pki-policy-score">${p.rules.length} rules</span>
          <button class="pki-policy-toggle ${p.enabled ? 'active' : ''}" data-toggle-id="${p.id}" title="Toggle"></button>
          <button class="glass-btn small pki-policy-delete" data-delete-id="${p.id}" title="Delete">&times;</button>
        </div>
        ${isExpanded ? `
          <div class="pki-policy-rules">
            ${p.rules.map(r => `
              <div class="pki-rule-row">
                <span class="pki-badge ${severityClass(r.severity)}">${r.severity}</span>
                <span class="pki-rule-type">${RULE_METADATA[r.type]?.label || r.type}</span>
                <span class="pki-rule-params">${formatRuleParams(r)}</span>
                <button class="pki-rule-delete" data-rule-id="${r.id}" data-policy-id="${p.id}" title="Remove">&times;</button>
              </div>
            `).join('')}
            <div class="pki-add-rule-row">
              <select class="glass-select compact pki-rule-type-select" data-policy-id="${p.id}">
                <option value="">+ Add rule...</option>
                ${Object.entries(RULE_METADATA).map(([type, meta]) =>
                  `<option value="${type}">${meta.label} (${meta.category})</option>`
                ).join('')}
              </select>
            </div>
          </div>
        ` : ''}
      </div>
    `;
  }).join('');

  // Toggle expand on policy name click
  container.querySelectorAll('.pki-policy-item').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('[data-toggle-id]') || e.target.closest('[data-delete-id]')) return;
      const id = el.closest('.pki-policy-card').dataset.policyId;
      _expandedPolicyId = _expandedPolicyId === id ? null : id;
      renderPolicies();
    });
  });

  // Toggle enabled
  container.querySelectorAll('[data-toggle-id]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const policy = policies.find(p => p.id === btn.dataset.toggleId);
      if (policy) { policy.enabled = !policy.enabled; renderPolicies(); }
    });
  });

  // Delete policy
  container.querySelectorAll('[data-delete-id]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.policies = state.policies.filter(p => p.id !== btn.dataset.deleteId);
      if (_expandedPolicyId === btn.dataset.deleteId) _expandedPolicyId = null;
      renderPolicies();
    });
  });

  // Delete rule
  container.querySelectorAll('.pki-rule-delete').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const policy = policies.find(p => p.id === btn.dataset.policyId);
      if (policy) { removeRule(policy, btn.dataset.ruleId); renderPolicies(); }
    });
  });

  // Add rule via select
  container.querySelectorAll('.pki-rule-type-select').forEach(sel => {
    sel.addEventListener('change', (e) => {
      const type = e.target.value;
      if (!type) return;
      const policy = policies.find(p => p.id === sel.dataset.policyId);
      if (!policy) return;
      const params = buildDefaultParams(type);
      const severity = promptSeverity();
      addRule(policy, type, params, severity);
      renderPolicies();
    });
  });
}

function formatRuleParams(rule) {
  const p = rule.params || {};
  const parts = [];
  for (const [k, v] of Object.entries(p)) {
    if (Array.isArray(v)) parts.push(`${k}: ${v.join(',')}`);
    else parts.push(`${k}: ${v}`);
  }
  return parts.length > 0 ? parts.join('; ') : '';
}

function buildDefaultParams(type) {
  const defaults = {
    minimum_total_value: { minValue: 100, currency: 'USD' },
    per_key_minimum: { keyId: '', minValue: 10, currency: 'USD' },
    max_concentration: { maxPercent: 50 },
    key_diversity: { minNetworks: 3 },
    m_of_n_funded: { m: 2, keyIds: [] },
    all_networks_funded: { keyIds: [] },
    certificate_valid: { keyIdentityId: '' },
    certificate_chain_depth: { minDepth: 2 },
    certificate_algorithm: { allowedCurves: ['P-256', 'P-384'] },
    xpub_signed: {},
    key_age_limit: { maxAgeDays: 365 },
    multi_curve_requirement: { minCurves: 2 },
    nist_curve_required: {},
    org_key_present: { orgId: '' },
    personnel_cert_signed_by_org: { orgId: '' },
    min_personnel_keys: { orgId: '', minKeys: 2 },
  };
  return defaults[type] || {};
}

function promptSeverity() {
  const s = prompt('Severity (info, warn, block):', 'warn');
  return ['info', 'warn', 'block'].includes(s) ? s : 'warn';
}

// =============================================================================
// Address Analysis
// =============================================================================

const ADDRESS_PATTERNS = [
  { network: 'BTC', pattern: /^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/i },
  { network: 'ETH', pattern: /^0x[0-9a-fA-F]{40}$/ },
  { network: 'SOL', pattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/ },
];

function detectNetwork(address) {
  for (const { network, pattern } of ADDRESS_PATTERNS) {
    if (pattern.test(address.trim())) return network;
  }
  return 'Unknown';
}

async function handleAnalyzeAddresses() {
  const input = _root.getElementById('pki-address-input');
  const resultsEl = _root.getElementById('pki-address-results');
  const totalEl = _root.getElementById('pki-address-total');
  const totalValueEl = _root.getElementById('pki-address-total-value');
  if (!input || !resultsEl) return;

  const addresses = input.value.trim().split('\n').map(a => a.trim()).filter(Boolean);
  if (addresses.length === 0) return;

  resultsEl.innerHTML = addresses.map(addr => {
    const network = detectNetwork(addr);
    const truncated = addr.length > 20 ? addr.slice(0, 10) + '...' + addr.slice(-8) : addr;
    return `
      <div class="pki-address-card">
        <span class="pki-badge ${network !== 'Unknown' ? 'valid' : 'expired'}">${network}</span>
        <code class="pki-info-value truncate">${truncated}</code>
        <span class="pki-address-balance" data-addr="${addr}" data-network="${network}">Loading...</span>
        ${_selectedType === 'org' ? `<button class="glass-btn small pki-assign-addr" data-addr="${addr}" data-network="${network}">+ Org</button>` : ''}
      </div>
    `;
  }).join('');

  // Assign to org handlers
  resultsEl.querySelectorAll('.pki-assign-addr').forEach(btn => {
    btn.addEventListener('click', () => {
      if (_selectedType === 'org' && _selectedId) {
        createKeyIdentity(_selectedId, {
          label: `${btn.dataset.network} address`,
          curve: btn.dataset.network === 'BTC' ? 'secp256k1' : btn.dataset.network === 'SOL' ? 'ed25519' : 'secp256k1',
          address: btn.dataset.addr,
          role: 'signing',
        });
        selectOrg(_selectedId);
        renderTree();
      }
    });
  });

  if (totalEl) totalEl.style.display = 'flex';
  if (totalValueEl) totalValueEl.textContent = `${addresses.length} address(es) detected`;
}
