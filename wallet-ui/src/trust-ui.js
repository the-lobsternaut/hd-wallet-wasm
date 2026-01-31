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
} from './blockchain-trust.js';

// =============================================================================
// Trust Graph Visualization (Simple Canvas Rendering)
// =============================================================================

export class TrustGraphRenderer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.graph = { nodes: [], edges: [] };
    this.nodeRadius = 20;
    this.colors = {
      never: '#ef4444',
      unknown: '#6b7280',
      marginal: '#f59e0b',
      full: '#10b981',
      ultimate: '#8b5cf6',
      revoked: '#374151',
    };
  }

  setGraph(graph) {
    this.graph = graph;
    this.layoutNodes();
  }

  layoutNodes() {
    // Simple force-directed layout (spring embedder)
    const { nodes } = this.graph;
    const centerX = this.canvas.width / 2;
    const centerY = this.canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 50;

    // Circular layout for simplicity
    nodes.forEach((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI;
      node.x = centerX + radius * Math.cos(angle);
      node.y = centerY + radius * Math.sin(angle);
    });
  }

  render() {
    const { ctx, canvas } = this;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw edges
    for (const edge of this.graph.edges) {
      const fromNode = this.graph.nodes.find(n => n.id === edge.from);
      const toNode = this.graph.nodes.find(n => n.id === edge.to);

      if (!fromNode || !toNode) continue;

      ctx.beginPath();
      ctx.moveTo(fromNode.x, fromNode.y);
      ctx.lineTo(toNode.x, toNode.y);

      // Color and thickness based on trust level
      if (edge.revoked) {
        ctx.strokeStyle = this.colors.revoked;
        ctx.lineWidth = 1;
        ctx.setLineDash([5, 5]);
      } else {
        ctx.strokeStyle = this.getTrustColor(edge.level);
        ctx.lineWidth = edge.level;
        ctx.setLineDash([]);
      }

      ctx.stroke();
    }

    // Draw nodes
    for (const node of this.graph.nodes) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, this.nodeRadius, 0, 2 * Math.PI);

      // Fill color based on node type
      ctx.fillStyle = node.ownKey ? this.colors.ultimate : '#2a2a2d';
      ctx.fill();

      // Border
      ctx.strokeStyle = node.ownKey ? this.colors.ultimate : '#ffffff33';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Label
      ctx.fillStyle = '#ffffff';
      ctx.font = '10px monospace';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + this.nodeRadius + 15);
    }
  }

  getTrustColor(level) {
    switch (level) {
      case TrustLevel.NEVER: return this.colors.never;
      case TrustLevel.UNKNOWN: return this.colors.unknown;
      case TrustLevel.MARGINAL: return this.colors.marginal;
      case TrustLevel.FULL: return this.colors.full;
      case TrustLevel.ULTIMATE: return this.colors.ultimate;
      default: return this.colors.unknown;
    }
  }
}

// =============================================================================
// Trust Controls UI
// =============================================================================

/**
 * Show establish trust modal
 */
export function showEstablishTrustModal(recipientPubkey, onConfirm) {
  const modal = document.createElement('div');
  modal.className = 'modal active trust-modal';
  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Establish Trust</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div class="trust-recipient">
          <label>Recipient Public Key</label>
          <code class="trust-pubkey">${truncatePubkey(recipientPubkey)}</code>
        </div>

        <div class="trust-level-selector">
          <label>Trust Level</label>
          <div class="trust-level-options">
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.MARGINAL}" checked>
              <span class="trust-level-label">
                <span class="trust-level-name">Marginal</span>
                <span class="trust-level-desc">Some trust</span>
              </span>
            </label>
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.FULL}">
              <span class="trust-level-label">
                <span class="trust-level-name">Full</span>
                <span class="trust-level-desc">Can sign other keys</span>
              </span>
            </label>
            <label class="trust-level-option">
              <input type="radio" name="trust-level" value="${TrustLevel.NEVER}">
              <span class="trust-level-label">
                <span class="trust-level-name">Never</span>
                <span class="trust-level-desc">Blocklist</span>
              </span>
            </label>
          </div>
        </div>

        <div class="trust-network-selector">
          <label>Blockchain Network</label>
          <select id="trust-network" class="glass-select">
            <option value="btc">Bitcoin (OP_RETURN)</option>
            <option value="sol">Solana (Memo)</option>
            <option value="eth" disabled>Ethereum (requires API key)</option>
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

  // Event listeners
  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#trust-cancel');
  const confirmBtn = modal.querySelector('#trust-confirm');
  const networkSelect = modal.querySelector('#trust-network');

  const close = () => {
    modal.remove();
  };

  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  networkSelect.addEventListener('change', (e) => {
    const feeValue = modal.querySelector('#trust-fee-value');
    switch (e.target.value) {
      case 'btc':
        feeValue.textContent = '~0.0001 BTC';
        break;
      case 'sol':
        feeValue.textContent = '~0.000005 SOL';
        break;
      case 'eth':
        feeValue.textContent = '~0.001 ETH';
        break;
    }
  });

  confirmBtn.addEventListener('click', () => {
    const level = parseInt(modal.querySelector('input[name="trust-level"]:checked').value, 10);
    const network = networkSelect.value;

    onConfirm({ level, network, recipientPubkey });
    close();
  });
}

/**
 * Show revoke trust modal
 */
export function showRevokeTrustModal(originalTxHash, onConfirm) {
  const modal = document.createElement('div');
  modal.className = 'modal active trust-modal';
  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Revoke Trust</h3>
        <button class="modal-close">&times;</button>
      </div>
      <div class="modal-body">
        <div class="trust-warning">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L2 7l10 5 10-5-10-5z"/>
            <circle cx="12" cy="12" r="3"/>
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
          <button class="glass-btn primary" id="revoke-confirm">Publish Revocation</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#revoke-cancel');
  const confirmBtn = modal.querySelector('#revoke-confirm');

  const close = () => {
    modal.remove();
  };

  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  confirmBtn.addEventListener('click', () => {
    onConfirm({ originalTxHash });
    close();
  });
}

/**
 * Render trust timeline for a contact
 */
export function renderTrustTimeline(container, trustTransactions) {
  container.innerHTML = '';

  if (trustTransactions.length === 0) {
    container.innerHTML = '<div class="trust-timeline-empty">No trust transactions</div>';
    return;
  }

  // Sort by timestamp (newest first)
  const sorted = [...trustTransactions].sort((a, b) => b.timestamp - a.timestamp);

  for (const tx of sorted) {
    const item = document.createElement('div');
    item.className = 'trust-timeline-item';

    const icon = tx.type === 'trust' ? '🤝' : '❌';
    const levelName = tx.type === 'trust' ? TrustLevelNames[tx.level] : 'Revoked';
    const date = new Date(tx.timestamp).toLocaleDateString();
    const time = new Date(tx.timestamp).toLocaleTimeString();

    item.innerHTML = `
      <div class="trust-timeline-icon">${icon}</div>
      <div class="trust-timeline-content">
        <div class="trust-timeline-header">
          <span class="trust-timeline-level">${levelName}</span>
          <span class="trust-timeline-date">${date} ${time}</span>
        </div>
        <div class="trust-timeline-details">
          <a href="#" class="trust-timeline-tx" data-tx="${tx.txHash}" target="_blank" rel="noopener">
            ${truncateTxHash(tx.txHash)}
          </a>
        </div>
      </div>
    `;

    container.appendChild(item);
  }

  // Add block explorer links
  container.querySelectorAll('.trust-timeline-tx').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const txHash = link.getAttribute('data-tx');
      // Open in block explorer (would need to detect network)
      window.open(`https://blockstream.info/tx/${txHash}`, '_blank');
    });
  });
}

// =============================================================================
// Trust Scanner UI
// =============================================================================

/**
 * Scan all addresses and build trust graph
 */
export async function scanAllTrustTransactions(addresses) {
  const allTxs = [];

  // Scan Bitcoin
  if (addresses.btc) {
    const btcTxs = await scanBitcoinTrustTransactions(addresses.btc);
    allTxs.push(...btcTxs);
  }

  // Scan Solana
  if (addresses.sol) {
    const solTxs = await scanSolanaTrustTransactions(addresses.sol);
    allTxs.push(...solTxs);
  }

  // Scan Ethereum
  if (addresses.eth) {
    const ethTxs = await scanEthereumTrustTransactions(addresses.eth);
    allTxs.push(...ethTxs);
  }

  return allTxs;
}

/**
 * Update trust map tab with graph
 */
export function updateTrustMapTab(graph, ownAddresses) {
  const canvas = document.getElementById('trust-graph-canvas');
  if (!canvas) return;

  // Mark own nodes
  for (const node of graph.nodes) {
    if (Object.values(ownAddresses).includes(node.id)) {
      node.ownKey = true;
    }
  }

  const renderer = new TrustGraphRenderer(canvas);
  renderer.setGraph(graph);
  renderer.render();

  // Update stats
  const statsEl = document.getElementById('trust-graph-stats');
  if (statsEl) {
    statsEl.innerHTML = `
      <div class="trust-stat">
        <span class="trust-stat-label">Nodes</span>
        <span class="trust-stat-value">${graph.nodes.length}</span>
      </div>
      <div class="trust-stat">
        <span class="trust-stat-label">Relationships</span>
        <span class="trust-stat-value">${graph.edges.length}</span>
      </div>
      <div class="trust-stat">
        <span class="trust-stat-label">Active</span>
        <span class="trust-stat-value">${graph.edges.filter(e => !e.revoked).length}</span>
      </div>
      <div class="trust-stat">
        <span class="trust-stat-label">Revoked</span>
        <span class="trust-stat-value">${graph.edges.filter(e => e.revoked).length}</span>
      </div>
    `;
  }
}

// =============================================================================
// Helpers
// =============================================================================

function truncatePubkey(pubkey, prefixLen = 12, suffixLen = 8) {
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return `${pubkey.slice(0, prefixLen)}...${pubkey.slice(-suffixLen)}`;
}

function truncateTxHash(txHash, prefixLen = 10, suffixLen = 6) {
  if (txHash.length <= prefixLen + suffixLen + 3) return txHash;
  return `${txHash.slice(0, prefixLen)}...${txHash.slice(-suffixLen)}`;
}
