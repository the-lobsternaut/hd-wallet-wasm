/**
 * Trust UI Components
 *
 * UI components for displaying and interacting with blockchain trust graph
 */

import {
  TrustLevel,
  TrustLevelNames,
  scanBitcoinTrustTransactions,
  scanSolanaTrustTransactions,
  scanEthereumTrustTransactions,
  buildTrustGraph,
  calculateTrustScore,
  analyzeTrustRelationships,
} from './blockchain-trust.js';

// =============================================================================
// Helpers
// =============================================================================

export function truncatePubkey(pubkey, prefixLen = 12, suffixLen = 8) {
  if (!pubkey) return '';
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return `${pubkey.slice(0, prefixLen)}...${pubkey.slice(-suffixLen)}`;
}

export function truncateTxHash(txHash, prefixLen = 10, suffixLen = 6) {
  if (!txHash) return '';
  if (txHash.length <= prefixLen + suffixLen + 3) return txHash;
  return `${txHash.slice(0, prefixLen)}...${txHash.slice(-suffixLen)}`;
}

function explorerTxUrl(chain, txHash) {
  switch (chain) {
    case 'btc':
      return `https://blockstream.info/tx/${txHash}`;
    case 'eth':
      return `https://etherscan.io/tx/${txHash}`;
    case 'sol':
      return `https://solscan.io/tx/${txHash}`;
    default:
      return `https://blockstream.info/tx/${txHash}`;
  }
}

function chainBadge(chain) {
  const labels = { btc: 'BTC', eth: 'ETH', sol: 'SOL' };
  const label = labels[chain] || chain?.toUpperCase() || '???';
  return `<span class="chain-badge chain-${chain || 'unknown'}">${label}</span>`;
}

function trustLevelBadge(level) {
  const name = TrustLevelNames[level] || 'Unknown';
  const cls = name.toLowerCase().replace(/\s+/g, '-');
  return `<span class="trust-level-badge trust-level-${cls}">${name}</span>`;
}

function directionIndicator(direction) {
  switch (direction) {
    case 'outbound':
      return '<span class="trust-direction" title="Outbound">&rarr;</span>';
    case 'inbound':
      return '<span class="trust-direction" title="Inbound">&larr;</span>';
    case 'mutual':
      return '<span class="trust-direction" title="Mutual">&harr;</span>';
    default:
      return '<span class="trust-direction">--</span>';
  }
}

function closeModal(modal) {
  modal.classList.remove('active');
  setTimeout(() => modal.remove(), 200);
}

// =============================================================================
// 1. renderTrustList
// =============================================================================

export function renderTrustList(container, relationships, ownAddresses) {
  container.innerHTML = '';

  if (!relationships || relationships.length === 0) {
    container.innerHTML = '<div class="trust-empty">No trust relationships found.</div>';
    return;
  }

  const list = document.createElement('div');
  list.className = 'trust-list';

  for (const rel of relationships) {
    const row = document.createElement('div');
    row.className = 'trust-row';

    const ownSet = new Set(
      Array.isArray(ownAddresses)
        ? ownAddresses
        : Object.values(ownAddresses || {}).flat()
    );

    const isOutbound = ownSet.has(rel.from);
    const isInbound = ownSet.has(rel.to);
    const direction = isOutbound && isInbound ? 'mutual'
      : isOutbound ? 'outbound'
      : isInbound ? 'inbound'
      : 'outbound';

    const displayAddress = direction === 'inbound' ? rel.from : rel.to;
    const chain = rel.chain || rel.network || 'btc';

    // Header
    const header = document.createElement('div');
    header.className = 'trust-row-header';
    header.innerHTML = `
      <span class="trust-row-address" title="${displayAddress}">${truncatePubkey(displayAddress)}</span>
      ${chainBadge(chain)}
      ${trustLevelBadge(rel.level)}
      ${directionIndicator(direction)}
      <span class="trust-row-expand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </span>
    `;

    // Detail
    const detail = document.createElement('div');
    detail.className = 'trust-row-detail';

    const txs = rel.transactions || (rel.txHash ? [rel] : []);
    const txRows = txs.map(tx => {
      const ts = tx.timestamp ? new Date(tx.timestamp).toLocaleString() : '--';
      const hash = tx.txHash || tx.hash || '';
      const txChain = tx.chain || tx.network || chain;
      const url = explorerTxUrl(txChain, hash);
      return `
        <div class="trust-tx-row">
          <span class="trust-tx-time">${ts}</span>
          <a class="trust-tx-link" href="${url}" target="_blank" rel="noopener">${truncateTxHash(hash)}</a>
        </div>
      `;
    }).join('');

    const revokeBtn = direction !== 'inbound'
      ? `<button class="glass-btn glass-btn-sm trust-revoke-btn" data-address="${displayAddress}">Revoke</button>`
      : '';

    detail.innerHTML = `
      <div class="trust-detail-address">
        <label>Full Address</label>
        <code>${displayAddress}</code>
      </div>
      <div class="trust-detail-txs">
        <label>Transactions</label>
        ${txRows || '<span class="trust-no-txs">No transactions recorded</span>'}
      </div>
      ${revokeBtn ? `<div class="trust-detail-actions">${revokeBtn}</div>` : ''}
    `;

    // Toggle expand
    header.addEventListener('click', () => {
      const wasExpanded = row.classList.contains('expanded');
      // Collapse all others
      list.querySelectorAll('.trust-row.expanded').forEach(r => r.classList.remove('expanded'));
      if (!wasExpanded) row.classList.add('expanded');
    });

    row.appendChild(header);
    row.appendChild(detail);
    list.appendChild(row);
  }

  container.appendChild(list);
}

// =============================================================================
// 2. showEstablishTrustModal
// =============================================================================

export function showEstablishTrustModal(onConfirm) {
  const modal = document.createElement('div');
  modal.className = 'modal trust-modal';
  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Establish Trust</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label>Recipient Address</label>
          <input type="text" id="trust-recipient" class="glass-input" placeholder="Enter address..." autocomplete="off" />
        </div>

        <div class="form-group">
          <label>Trust Level</label>
          <div class="trust-level-options">
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.MARGINAL}" checked>
              <span class="trust-level-label">
                <span class="trust-level-name">Marginal</span>
                <span class="trust-level-desc">Some trust -- limited signing authority</span>
              </span>
            </label>
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.FULL}">
              <span class="trust-level-label">
                <span class="trust-level-name">Full</span>
                <span class="trust-level-desc">Fully trusted -- can sign other keys</span>
              </span>
            </label>
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.NEVER}">
              <span class="trust-level-label">
                <span class="trust-level-name">Never</span>
                <span class="trust-level-desc">Blocklist -- explicitly untrusted</span>
              </span>
            </label>
          </div>
        </div>

        <div class="form-group">
          <label>Blockchain Network</label>
          <select id="trust-network" class="glass-select">
            <option value="btc">Bitcoin (OP_RETURN)</option>
            <option value="sol">Solana (Memo)</option>
            <option value="eth">Ethereum (Input Data)</option>
          </select>
        </div>

        <div class="trust-fee-estimate">
          <span class="trust-fee-label">Estimated Fee:</span>
          <span class="trust-fee-value" id="trust-fee-value">~0.0001 BTC</span>
        </div>

        <div class="trust-actions">
          <button class="glass-btn" id="trust-cancel">Cancel</button>
          <button class="glass-btn primary" id="trust-confirm">Publish Trust Transaction</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  requestAnimationFrame(() => modal.classList.add('active'));

  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#trust-cancel');
  const confirmBtn = modal.querySelector('#trust-confirm');
  const networkSelect = modal.querySelector('#trust-network');

  const close = () => closeModal(modal);

  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  networkSelect.addEventListener('change', (e) => {
    const feeValue = modal.querySelector('#trust-fee-value');
    const fees = { btc: '~0.0001 BTC', sol: '~0.000005 SOL', eth: '~0.001 ETH' };
    feeValue.textContent = fees[e.target.value] || '--';
  });

  confirmBtn.addEventListener('click', () => {
    const recipientAddress = modal.querySelector('#trust-recipient').value.trim();
    if (!recipientAddress) {
      modal.querySelector('#trust-recipient').focus();
      return;
    }
    const level = parseInt(modal.querySelector('input[name="trust-level"]:checked').value, 10);
    const network = networkSelect.value;

    onConfirm({ level, network, recipientAddress });
    close();
  });
}

// =============================================================================
// 3. showRevokeTrustModal
// =============================================================================

export function showRevokeTrustModal(originalTxHash, onConfirm) {
  const modal = document.createElement('div');
  modal.className = 'modal trust-modal';
  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Revoke Trust</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div class="trust-warning">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p>This will publish a revocation transaction on-chain. The original trust relationship will be marked as revoked and will no longer contribute to trust scores.</p>
          <p><strong>This action is permanent and cannot be undone.</strong></p>
        </div>

        <div class="trust-tx-hash">
          <label>Original Transaction</label>
          <code>${truncateTxHash(originalTxHash)}</code>
        </div>

        <div class="trust-actions">
          <button class="glass-btn" id="revoke-cancel">Cancel</button>
          <button class="glass-btn danger" id="revoke-confirm">Publish Revocation</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  requestAnimationFrame(() => modal.classList.add('active'));

  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#revoke-cancel');
  const confirmBtn = modal.querySelector('#revoke-confirm');

  const close = () => closeModal(modal);

  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  confirmBtn.addEventListener('click', () => {
    onConfirm({ originalTxHash });
    close();
  });
}

// =============================================================================
// 4. showRulesModal
// =============================================================================

const RULE_CONDITION_TYPES = [
  { value: 'mutual_tx_count', label: 'Mutual Transaction Count' },
  { value: 'last_interaction_days', label: 'Days Since Last Interaction' },
  { value: 'address_blocklist', label: 'Address Blocklist' },
  { value: 'bidirectional_trust', label: 'Bidirectional Trust' },
];

const SEVERITY_OPTIONS = ['info', 'warn', 'block'];

function buildRuleRow(rule, index) {
  const conditionOptions = RULE_CONDITION_TYPES.map(ct =>
    `<option value="${ct.value}" ${rule.type === ct.value ? 'selected' : ''}>${ct.label}</option>`
  ).join('');

  const levelOptions = Object.entries(TrustLevelNames).map(([val, name]) =>
    `<option value="${val}" ${String(rule.resultLevel) === String(val) ? 'selected' : ''}>${name}</option>`
  ).join('');

  const severityOptions = SEVERITY_OPTIONS.map(s =>
    `<option value="${s}" ${rule.severity === s ? 'selected' : ''}>${s}</option>`
  ).join('');

  return `
    <div class="rule-row" data-index="${index}">
      <div class="rule-fields">
        <div class="rule-field">
          <label>Condition</label>
          <select class="glass-select rule-type">${conditionOptions}</select>
        </div>
        <div class="rule-field">
          <label>Threshold</label>
          <input type="number" class="glass-input rule-threshold" value="${rule.params?.threshold ?? 0}" min="0" />
        </div>
        <div class="rule-field">
          <label>Result Level</label>
          <select class="glass-select rule-result-level">${levelOptions}</select>
        </div>
        <div class="rule-field">
          <label>Severity</label>
          <select class="glass-select rule-severity">${severityOptions}</select>
        </div>
        <div class="rule-field rule-field-actions">
          <button class="glass-btn glass-btn-sm rule-delete-btn" data-index="${index}" title="Delete rule">&times;</button>
        </div>
      </div>
    </div>
  `;
}

export function showRulesModal(rules, onSave) {
  let currentRules = (rules || []).map((r, i) => ({
    id: r.id || `rule-${i}`,
    type: r.type || 'mutual_tx_count',
    params: { threshold: r.params?.threshold ?? 0 },
    resultLevel: r.resultLevel ?? TrustLevel.MARGINAL,
    severity: r.severity || 'info',
    description: r.description || '',
  }));

  const modal = document.createElement('div');
  modal.className = 'modal trust-modal rules-modal';

  function renderRules() {
    const rulesHtml = currentRules.map((r, i) => buildRuleRow(r, i)).join('');
    modal.innerHTML = `
      <div class="modal-glass">
        <div class="modal-header">
          <h3>Trust Rules</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          <div class="rules-list">
            ${rulesHtml || '<div class="rules-empty">No rules defined. Add a rule below.</div>'}
          </div>
          <div class="rules-toolbar">
            <button class="glass-btn glass-btn-sm" id="rules-add">+ Add Rule</button>
          </div>
          <div class="trust-actions">
            <button class="glass-btn" id="rules-cancel">Cancel</button>
            <button class="glass-btn primary" id="rules-save">Save Rules</button>
          </div>
        </div>
      </div>
    `;
    bindRulesEvents();
  }

  function readRulesFromDom() {
    const rows = modal.querySelectorAll('.rule-row');
    rows.forEach((row, i) => {
      if (currentRules[i]) {
        currentRules[i].type = row.querySelector('.rule-type').value;
        currentRules[i].params.threshold = parseInt(row.querySelector('.rule-threshold').value, 10) || 0;
        currentRules[i].resultLevel = parseInt(row.querySelector('.rule-result-level').value, 10);
        currentRules[i].severity = row.querySelector('.rule-severity').value;
      }
    });
  }

  function bindRulesEvents() {
    const close = () => closeModal(modal);

    modal.querySelector('.modal-close').addEventListener('click', close);
    modal.querySelector('#rules-cancel').addEventListener('click', close);

    modal.querySelector('#rules-add').addEventListener('click', () => {
      readRulesFromDom();
      currentRules.push({
        id: `rule-${Date.now()}`,
        type: 'mutual_tx_count',
        params: { threshold: 0 },
        resultLevel: TrustLevel.MARGINAL,
        severity: 'info',
        description: '',
      });
      renderRules();
    });

    modal.querySelectorAll('.rule-delete-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        readRulesFromDom();
        const idx = parseInt(btn.getAttribute('data-index'), 10);
        currentRules.splice(idx, 1);
        renderRules();
      });
    });

    modal.querySelector('#rules-save').addEventListener('click', () => {
      readRulesFromDom();
      onSave(currentRules);
      close();
    });
  }

  document.body.appendChild(modal);
  renderRules();
  requestAnimationFrame(() => modal.classList.add('active'));
}

// =============================================================================
// 5. scanAllTrustTransactions
// =============================================================================

export async function scanAllTrustTransactions(addresses) {
  const allTxs = [];

  if (addresses.btc) {
    const btcTxs = await scanBitcoinTrustTransactions(addresses.btc);
    allTxs.push(...btcTxs);
  }

  if (addresses.sol) {
    const solTxs = await scanSolanaTrustTransactions(addresses.sol);
    allTxs.push(...solTxs);
  }

  if (addresses.eth) {
    const ethTxs = await scanEthereumTrustTransactions(addresses.eth);
    allTxs.push(...ethTxs);
  }

  return allTxs;
}

// =============================================================================
// 6. exportTrustData
// =============================================================================

export function exportTrustData(trustTransactions, xpub) {
  const payload = {
    exportDate: new Date().toISOString(),
    xpub: xpub || null,
    chainInfo: {
      btc: 'Bitcoin mainnet',
      sol: 'Solana mainnet-beta',
      eth: 'Ethereum mainnet',
    },
    transactions: trustTransactions || [],
  };

  const json = JSON.stringify(payload, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `trust-export-${Date.now()}.trust.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// 7. importTrustData
// =============================================================================

export function importTrustData(file) {
  return new Promise((resolve, reject) => {
    if (!file) {
      reject(new Error('No file provided'));
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (!data.transactions || !Array.isArray(data.transactions)) {
          reject(new Error('Invalid trust data: missing transactions array'));
          return;
        }
        resolve(data.transactions);
      } catch (err) {
        reject(new Error(`Failed to parse trust data: ${err.message}`));
      }
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}
