/**
 * Blockchain Trust Transactions
 *
 * KeySpace-inspired trust model: all trust relationships are published
 * as on-chain transactions using OP_RETURN (Bitcoin), memo fields (Solana),
 * or transaction data (Ethereum).
 */

// =============================================================================
// Trust Levels (PGP-style)
// =============================================================================

export const TrustLevel = {
  NEVER: 1,      // Blocklist / Do not trust
  UNKNOWN: 2,    // Default / No opinion
  MARGINAL: 3,   // Some trust
  FULL: 4,       // Full trust / Can sign other keys
  ULTIMATE: 5,   // Own keys
};

export const TrustLevelNames = {
  1: 'Never',
  2: 'Unknown',
  3: 'Marginal',
  4: 'Full',
  5: 'Ultimate',
};

// =============================================================================
// Trust Transaction Format
// =============================================================================

const TRUST_VERSION = '1';
const TRUST_PREFIX = 'TRUST';
const REVOKE_PREFIX = 'REVOKE';

/**
 * Encode trust metadata for blockchain transaction
 * Format: TRUST:<version>:<level>:<timestamp>:<recipientPubkey>
 */
export function encodeTrustMetadata(level, recipientPubkey, timestamp = Date.now()) {
  if (!TrustLevel[Object.keys(TrustLevel).find(k => TrustLevel[k] === level)]) {
    throw new Error(`Invalid trust level: ${level}`);
  }

  return `${TRUST_PREFIX}:${TRUST_VERSION}:${level}:${timestamp}:${recipientPubkey}`;
}

/**
 * Encode revocation metadata
 * Format: REVOKE:<version>:<originalTxHash>:<timestamp>
 */
export function encodeRevocationMetadata(originalTxHash, timestamp = Date.now()) {
  return `${REVOKE_PREFIX}:${TRUST_VERSION}:${originalTxHash}:${timestamp}`;
}

/**
 * Parse trust metadata from blockchain transaction
 */
export function parseTrustMetadata(metadata) {
  const parts = metadata.split(':');

  if (parts[0] === TRUST_PREFIX && parts.length >= 5) {
    return {
      type: 'trust',
      version: parts[1],
      level: parseInt(parts[2], 10),
      timestamp: parseInt(parts[3], 10),
      recipientPubkey: parts[4],
    };
  }

  if (parts[0] === REVOKE_PREFIX && parts.length >= 4) {
    return {
      type: 'revocation',
      version: parts[1],
      originalTxHash: parts[2],
      timestamp: parseInt(parts[3], 10),
    };
  }

  return null;
}

// =============================================================================
// Bitcoin OP_RETURN Trust Transactions
// =============================================================================

/**
 * Build Bitcoin OP_RETURN output data for trust transaction
 * Note: OP_RETURN is limited to 80 bytes
 */
export function buildBitcoinTrustOpReturn(level, recipientPubkey) {
  const metadata = encodeTrustMetadata(level, recipientPubkey);
  const bytes = new TextEncoder().encode(metadata);

  if (bytes.length > 80) {
    throw new Error('Trust metadata exceeds OP_RETURN size limit (80 bytes)');
  }

  // OP_RETURN format: 0x6a (OP_RETURN) + length + data
  return {
    scriptPubKey: `6a${bytes.length.toString(16).padStart(2, '0')}${Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')}`,
    metadata,
  };
}

/**
 * Parse Bitcoin OP_RETURN data from transaction
 */
export function parseBitcoinOpReturn(scriptPubKey) {
  // Check if it's OP_RETURN (0x6a)
  if (!scriptPubKey.startsWith('6a')) return null;

  // Extract data after OP_RETURN opcode and length byte
  const dataHex = scriptPubKey.slice(4);
  const bytes = [];
  for (let i = 0; i < dataHex.length; i += 2) {
    bytes.push(parseInt(dataHex.slice(i, i + 2), 16));
  }

  const metadata = new TextDecoder().decode(new Uint8Array(bytes));
  return parseTrustMetadata(metadata);
}

// =============================================================================
// Solana Memo Trust Transactions
// =============================================================================

/**
 * Build Solana memo instruction for trust transaction
 */
export function buildSolanaTrustMemo(level, recipientPubkey) {
  return encodeTrustMetadata(level, recipientPubkey);
}

/**
 * Parse Solana memo from transaction
 */
export function parseSolanaMemo(memo) {
  return parseTrustMetadata(memo);
}

// =============================================================================
// Ethereum Data Field Trust Transactions
// =============================================================================

/**
 * Build Ethereum transaction data field for trust transaction
 */
export function buildEthereumTrustData(level, recipientPubkey) {
  const metadata = encodeTrustMetadata(level, recipientPubkey);
  const bytes = new TextEncoder().encode(metadata);
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Parse Ethereum transaction data field
 */
export function parseEthereumData(dataHex) {
  if (!dataHex || dataHex === '0x') return null;

  const hex = dataHex.startsWith('0x') ? dataHex.slice(2) : dataHex;
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }

  const metadata = new TextDecoder().decode(new Uint8Array(bytes));
  return parseTrustMetadata(metadata);
}

// =============================================================================
// Trust Transaction Scanner
// =============================================================================

/**
 * Scan Bitcoin blockchain for trust transactions
 * Uses block explorer API to query OP_RETURN transactions
 */
export async function scanBitcoinTrustTransactions(address) {
  try {
    // Use Blockstream API to get all transactions for address
    const response = await fetch(`https://blockstream.info/api/address/${address}/txs`);
    if (!response.ok) throw new Error('Failed to fetch Bitcoin transactions');

    const txs = await response.json();
    const trustTxs = [];

    for (const tx of txs) {
      // Check each output for OP_RETURN
      for (const output of tx.vout) {
        if (output.scriptpubkey_type === 'op_return') {
          const parsed = parseBitcoinOpReturn(output.scriptpubkey);
          if (parsed) {
            trustTxs.push({
              txHash: tx.txid,
              blockHeight: tx.status.block_height,
              timestamp: tx.status.block_time * 1000,
              from: address, // The address we're scanning
              ...parsed,
            });
          }
        }
      }
    }

    return trustTxs;
  } catch (err) {
    console.error('Bitcoin trust scan failed:', err);
    return [];
  }
}

/**
 * Scan Solana blockchain for trust transactions
 * Uses RPC to get transactions with memo instructions
 */
export async function scanSolanaTrustTransactions(address) {
  try {
    // Use Solana RPC to get signatures for address
    const response = await fetch('https://api.mainnet-beta.solana.com', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getSignaturesForAddress',
        params: [address, { limit: 100 }],
      }),
    });

    if (!response.ok) throw new Error('Failed to fetch Solana signatures');
    const data = await response.json();
    const signatures = data.result || [];

    const trustTxs = [];

    // Fetch each transaction to check for memo
    for (const sig of signatures) {
      const txResponse = await fetch('https://api.mainnet-beta.solana.com', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getTransaction',
          params: [sig.signature, { encoding: 'jsonParsed' }],
        }),
      });

      if (!txResponse.ok) continue;
      const txData = await txResponse.json();
      const tx = txData.result;

      if (!tx || !tx.meta) continue;

      // Look for memo in log messages
      const memos = tx.meta.logMessages?.filter(m => m.startsWith('Program log: Memo')) || [];
      for (const memoLog of memos) {
        const memo = memoLog.replace('Program log: Memo (len ', '').split('): "')[1]?.replace('"', '');
        if (memo) {
          const parsed = parseSolanaMemo(memo);
          if (parsed) {
            trustTxs.push({
              txHash: sig.signature,
              slot: tx.slot,
              timestamp: (tx.blockTime || 0) * 1000,
              from: address,
              ...parsed,
            });
          }
        }
      }
    }

    return trustTxs;
  } catch (err) {
    console.error('Solana trust scan failed:', err);
    return [];
  }
}

/**
 * Scan Ethereum blockchain for trust transactions
 * Uses Etherscan API to query 0-value transactions with data
 */
export async function scanEthereumTrustTransactions(address) {
  try {
    // Note: This would require an Etherscan API key in production
    // For now, return empty array (to be implemented with proper API key)
    console.warn('Ethereum trust scanning requires Etherscan API key');
    return [];

    /* Example implementation with API key:
    const response = await fetch(
      `https://api.etherscan.io/api?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&sort=desc&apikey=${ETHERSCAN_API_KEY}`
    );

    if (!response.ok) throw new Error('Failed to fetch Ethereum transactions');
    const data = await response.json();
    const txs = data.result || [];

    const trustTxs = [];

    for (const tx of txs) {
      if (tx.value === '0' && tx.input && tx.input !== '0x') {
        const parsed = parseEthereumData(tx.input);
        if (parsed) {
          trustTxs.push({
            txHash: tx.hash,
            blockNumber: parseInt(tx.blockNumber, 10),
            timestamp: parseInt(tx.timeStamp, 10) * 1000,
            from: tx.from,
            to: tx.to,
            ...parsed,
          });
        }
      }
    }

    return trustTxs;
    */
  } catch (err) {
    console.error('Ethereum trust scan failed:', err);
    return [];
  }
}

// =============================================================================
// Trust Graph Builder
// =============================================================================

/**
 * Build trust graph from scanned transactions
 * Returns nodes (pubkeys) and edges (trust relationships)
 */
export function buildTrustGraph(trustTxs) {
  const nodes = new Map(); // pubkey -> { id, label, ownKey: boolean }
  const edges = []; // { from, to, level, txHash, timestamp, revoked }
  const revocations = new Map(); // txHash -> revocation timestamp

  // First pass: collect revocations
  for (const tx of trustTxs) {
    if (tx.type === 'revocation') {
      revocations.set(tx.originalTxHash, tx.timestamp);
    }
  }

  // Second pass: build graph
  for (const tx of trustTxs) {
    if (tx.type === 'trust') {
      // Add nodes
      if (!nodes.has(tx.from)) {
        nodes.set(tx.from, {
          id: tx.from,
          label: truncatePubkey(tx.from),
          ownKey: false,
        });
      }

      if (!nodes.has(tx.recipientPubkey)) {
        nodes.set(tx.recipientPubkey, {
          id: tx.recipientPubkey,
          label: truncatePubkey(tx.recipientPubkey),
          ownKey: false,
        });
      }

      // Add edge
      const revoked = revocations.has(tx.txHash);
      edges.push({
        from: tx.from,
        to: tx.recipientPubkey,
        level: tx.level,
        txHash: tx.txHash,
        timestamp: tx.timestamp,
        revoked,
        revokedAt: revoked ? revocations.get(tx.txHash) : null,
      });
    }
  }

  return {
    nodes: Array.from(nodes.values()),
    edges,
  };
}

/**
 * Calculate trust score for a pubkey based on graph
 * Implements weighted transitive trust (web of trust)
 */
export function calculateTrustScore(graph, targetPubkey, ownPubkeys = []) {
  let score = 0;
  const weights = {
    1: 0,   // Direct trust from own key, 1st degree
    2: 0.5, // 2nd degree
    3: 0.25, // 3rd degree
  };

  // Direct trust from own keys
  const directEdges = graph.edges.filter(
    e => ownPubkeys.includes(e.from) && e.to === targetPubkey && !e.revoked
  );

  for (const edge of directEdges) {
    score += edge.level * 20; // Max 100 for ULTIMATE (5 * 20)
  }

  // Transitive trust (2nd degree)
  const secondDegreeNodes = graph.edges
    .filter(e => ownPubkeys.includes(e.from) && !e.revoked && e.level >= TrustLevel.FULL)
    .map(e => e.to);

  for (const intermediateNode of secondDegreeNodes) {
    const transitiveEdges = graph.edges.filter(
      e => e.from === intermediateNode && e.to === targetPubkey && !e.revoked
    );

    for (const edge of transitiveEdges) {
      score += edge.level * 20 * weights[2];
    }
  }

  // Boomerang trust bonus (bidirectional)
  const outgoing = graph.edges.filter(e => e.from === targetPubkey && !e.revoked);
  const incoming = graph.edges.filter(e => e.to === targetPubkey && !e.revoked);

  const bidirectional = outgoing.filter(out =>
    incoming.some(inc => inc.from === out.to)
  );

  if (bidirectional.length > 0) {
    score += 10; // Bonus for mutual trust
  }

  return Math.min(Math.round(score), 100);
}

// =============================================================================
// Helpers
// =============================================================================

function truncatePubkey(pubkey, prefixLen = 8, suffixLen = 6) {
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return `${pubkey.slice(0, prefixLen)}...${pubkey.slice(-suffixLen)}`;
}
