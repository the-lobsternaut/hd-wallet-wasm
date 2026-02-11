/**
 * Blockchain Trust Transactions
 *
 * KeySpace-inspired trust model: all trust relationships are published
 * as on-chain transactions using OP_RETURN (Bitcoin), memo fields (Solana),
 * or transaction data (Ethereum).
 *
 * Binary encoding format (v2):
 *   Trust:      [0x54][0x01][level][timestamp:4][pubkey:32-33] = 40-41 bytes
 *   Revocation: [0x52][0x01][timestamp:4][txhash:32]          = 38 bytes
 */

import { apiUrl } from './address-derivation.js';

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
// Binary Constants
// =============================================================================

const MAGIC_TRUST = 0x54;    // 'T'
const MAGIC_REVOKE = 0x52;   // 'R'
const VERSION = 0x01;

// Legacy ASCII prefixes
const LEGACY_TRUST_PREFIX = 'TRUST';
const LEGACY_REVOKE_PREFIX = 'REVOKE';
const SOLANA_TRUST_RPC_ENDPOINTS = [
  'https://solana-rpc.publicnode.com',
  'https://mainnet.helius-rpc.com/?api-key=1d8740dc-e5f4-421c-b823-e1bad1889eda',
  'https://api.mainnet-beta.solana.com',
];
const SOLANA_TRUST_MAX_SIGNATURES = 40;
const SOLANA_TRUST_REQUEST_DELAY_MS = 350;
const SOLANA_TRUST_UNAVAILABLE_COOLDOWN_MS = 5 * 60 * 1000;
let _solanaTrustLastRequestAt = 0;
let _solanaTrustUnavailableUntil = 0;

// =============================================================================
// Binary Encoding Helpers
// =============================================================================

function writeUint32(buf, offset, value) {
  buf[offset]     = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readUint32(buf, offset) {
  return (
    ((buf[offset] << 24) >>> 0) +
    (buf[offset + 1] << 16) +
    (buf[offset + 2] << 8) +
    buf[offset + 3]
  ) >>> 0;
}

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  if (typeof btoa === 'function') {
    return btoa(String.fromCharCode(...bytes));
  }
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// =============================================================================
// Binary Trust Encoding (v2)
// =============================================================================

/**
 * Encode trust metadata as compact binary Uint8Array.
 *
 * Format:
 *   Byte [0]:    Magic 0x54 ('T')
 *   Byte [1]:    Version 0x01
 *   Byte [2]:    Trust level (0x01-0x05)
 *   Bytes [3-6]: Timestamp as uint32 (seconds since epoch)
 *   Bytes [7-N]: Recipient pubkey bytes (33 for secp256k1, 32 for ed25519)
 *
 * @param {number} level - Trust level (1-5)
 * @param {string} recipientPubkey - Hex-encoded public key
 * @param {number} [timestamp] - Unix timestamp in milliseconds (default: now)
 * @returns {Uint8Array} Binary encoded trust metadata
 */
export function encodeTrustMetadata(level, recipientPubkey, timestamp = Date.now()) {
  if (level < 1 || level > 5) {
    throw new Error(`Invalid trust level: ${level}`);
  }

  const pubkeyBytes = hexToBytes(recipientPubkey);
  const timeSec = Math.floor(timestamp / 1000);
  const buf = new Uint8Array(7 + pubkeyBytes.length);

  buf[0] = MAGIC_TRUST;
  buf[1] = VERSION;
  buf[2] = level;
  writeUint32(buf, 3, timeSec);
  buf.set(pubkeyBytes, 7);

  return buf;
}

/**
 * Encode revocation metadata as compact binary Uint8Array.
 *
 * Format:
 *   Byte [0]:    Magic 0x52 ('R')
 *   Byte [1]:    Version 0x01
 *   Bytes [2-5]: Timestamp as uint32 (seconds since epoch)
 *   Bytes [6-37]: Original tx hash (32 bytes)
 *
 * @param {string} originalTxHash - Hex-encoded transaction hash
 * @param {number} [timestamp] - Unix timestamp in milliseconds (default: now)
 * @returns {Uint8Array} Binary encoded revocation metadata
 */
export function encodeRevocationMetadata(originalTxHash, timestamp = Date.now()) {
  const hashBytes = hexToBytes(originalTxHash);
  if (hashBytes.length !== 32) {
    throw new Error(`Expected 32-byte tx hash, got ${hashBytes.length}`);
  }

  const timeSec = Math.floor(timestamp / 1000);
  const buf = new Uint8Array(38);

  buf[0] = MAGIC_REVOKE;
  buf[1] = VERSION;
  writeUint32(buf, 2, timeSec);
  buf.set(hashBytes, 6);

  return buf;
}

/**
 * Legacy ASCII encoder for backwards compatibility.
 * Format: TRUST:<version>:<level>:<timestamp>:<recipientPubkey>
 */
export function encodeTrustMetadataLegacy(level, recipientPubkey, timestamp = Date.now()) {
  if (level < 1 || level > 5) {
    throw new Error(`Invalid trust level: ${level}`);
  }
  return `${LEGACY_TRUST_PREFIX}:1:${level}:${timestamp}:${recipientPubkey}`;
}

// =============================================================================
// Parsing (binary + legacy ASCII)
// =============================================================================

/**
 * Parse trust metadata from either binary (Uint8Array) or legacy ASCII string.
 * Detects format by checking the first byte: 0x54 = binary trust, 0x52 = binary revoke.
 *
 * @param {Uint8Array|string} metadata - Binary buffer or ASCII string
 * @returns {object|null} Parsed trust/revocation object, or null
 */
export function parseTrustMetadata(metadata) {
  // Binary path
  if (metadata instanceof Uint8Array || metadata instanceof ArrayBuffer) {
    const buf = metadata instanceof ArrayBuffer ? new Uint8Array(metadata) : metadata;
    return parseBinaryMetadata(buf);
  }

  // If it's a string, check if the first char signals binary
  if (typeof metadata === 'string') {
    // Could be base64-encoded binary; try legacy ASCII first
    const legacy = parseLegacyMetadata(metadata);
    if (legacy) return legacy;

    // Try base64 decode
    try {
      const bytes = base64ToBytes(metadata);
      if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
        return parseBinaryMetadata(bytes);
      }
    } catch (_) {
      // not base64
    }
  }

  return null;
}

function parseBinaryMetadata(buf) {
  if (!buf || buf.length < 38) return null;

  if (buf[0] === MAGIC_TRUST && buf[1] === VERSION && buf.length >= 39) {
    const level = buf[2];
    if (level < 1 || level > 5) return null;
    const timestamp = readUint32(buf, 3) * 1000;
    const recipientPubkey = bytesToHex(buf.slice(7));

    return {
      type: 'trust',
      version: String(buf[1]),
      level,
      timestamp,
      recipientPubkey,
    };
  }

  if (buf[0] === MAGIC_REVOKE && buf[1] === VERSION && buf.length >= 38) {
    const timestamp = readUint32(buf, 2) * 1000;
    const originalTxHash = bytesToHex(buf.slice(6, 38));

    return {
      type: 'revocation',
      version: String(buf[1]),
      originalTxHash,
      timestamp,
    };
  }

  return null;
}

function parseLegacyMetadata(str) {
  const parts = str.split(':');

  if (parts[0] === LEGACY_TRUST_PREFIX && parts.length >= 5) {
    return {
      type: 'trust',
      version: parts[1],
      level: parseInt(parts[2], 10),
      timestamp: parseInt(parts[3], 10),
      recipientPubkey: parts[4],
    };
  }

  if (parts[0] === LEGACY_REVOKE_PREFIX && parts.length >= 4) {
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
 * Build Bitcoin OP_RETURN output data for trust transaction.
 * Uses compact binary encoding; total payload is 40-41 bytes (well within 80-byte limit).
 */
export function buildBitcoinTrustOpReturn(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);

  if (bytes.length > 80) {
    throw new Error('Trust metadata exceeds OP_RETURN size limit (80 bytes)');
  }

  // OP_RETURN format: 0x6a (OP_RETURN) + length + data
  return {
    scriptPubKey: `6a${bytes.length.toString(16).padStart(2, '0')}${bytesToHex(bytes)}`,
    metadata: bytes,
  };
}

/**
 * Parse Bitcoin OP_RETURN data from transaction.
 * Handles both binary and legacy ASCII payloads.
 */
export function parseBitcoinOpReturn(scriptPubKey) {
  if (!scriptPubKey.startsWith('6a')) return null;

  const dataHex = scriptPubKey.slice(4);
  const bytes = hexToBytes(dataHex);

  // Try binary first
  if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
    return parseBinaryMetadata(bytes);
  }

  // Fall back to legacy ASCII
  const text = new TextDecoder().decode(bytes);
  return parseLegacyMetadata(text);
}

// =============================================================================
// Solana Memo Trust Transactions
// =============================================================================

/**
 * Build Solana memo instruction for trust transaction.
 * Returns base64-encoded binary for the memo field.
 */
export function buildSolanaTrustMemo(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);
  return bytesToBase64(bytes);
}

/**
 * Parse Solana memo from transaction.
 * Handles both base64-encoded binary and legacy ASCII memos.
 */
export function parseSolanaMemo(memo) {
  if (!memo) return null;

  // Try base64 decode for binary format
  try {
    const bytes = base64ToBytes(memo);
    if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
      return parseBinaryMetadata(bytes);
    }
  } catch (_) {
    // not valid base64
  }

  // Fall back to legacy ASCII
  return parseLegacyMetadata(memo);
}

// =============================================================================
// Ethereum Data Field Trust Transactions
// =============================================================================

/**
 * Build Ethereum transaction data field for trust transaction.
 * Returns hex-encoded binary with 0x prefix.
 */
export function buildEthereumTrustData(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);
  return '0x' + bytesToHex(bytes);
}

/**
 * Parse Ethereum transaction data field.
 * Handles both binary and legacy ASCII payloads.
 */
export function parseEthereumData(dataHex) {
  if (!dataHex || dataHex === '0x') return null;

  const bytes = hexToBytes(dataHex);

  // Try binary first
  if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
    return parseBinaryMetadata(bytes);
  }

  // Fall back to legacy ASCII
  const text = new TextDecoder().decode(bytes);
  return parseLegacyMetadata(text);
}

// =============================================================================
// Trust Transaction Scanners
// =============================================================================

/**
 * Scan Bitcoin blockchain for trust transactions.
 * Uses block explorer API to query OP_RETURN transactions.
 */
export async function scanBitcoinTrustTransactions(address) {
  try {
    const response = await fetch(`https://blockstream.info/api/address/${address}/txs`);
    if (!response.ok) throw new Error('Failed to fetch Bitcoin transactions');

    const txs = await response.json();
    const trustTxs = [];

    for (const tx of txs) {
      for (const output of tx.vout) {
        if (output.scriptpubkey_type === 'op_return') {
          const parsed = parseBitcoinOpReturn(output.scriptpubkey);
          if (parsed) {
            trustTxs.push({
              txHash: tx.txid,
              blockHeight: tx.status.block_height,
              timestamp: tx.status.block_time * 1000,
              from: address,
              chain: 'bitcoin',
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
 * Scan Solana blockchain for trust transactions.
 * Uses RPC to get transactions with memo instructions.
 */
export async function scanSolanaTrustTransactions(address) {
  const isRateLimited = (msg) => {
    const t = (msg || '').toLowerCase();
    return t.includes('429') || t.includes('rate') || t.includes('limit') || t.includes('too many');
  };
  const isEndpointUnavailable = (msg) => {
    const t = (msg || '').toLowerCase();
    return t.includes('403') || t.includes('404') || t.includes('forbidden') || t.includes('not found');
  };
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const waitForThrottle = async () => {
    const elapsed = Date.now() - _solanaTrustLastRequestAt;
    if (elapsed < SOLANA_TRUST_REQUEST_DELAY_MS) {
      await sleep(SOLANA_TRUST_REQUEST_DELAY_MS - elapsed);
    }
    _solanaTrustLastRequestAt = Date.now();
  };
  const solanaRpcCall = async (method, params) => {
    let lastError = 'Unknown Solana RPC error';

    for (const endpoint of SOLANA_TRUST_RPC_ENDPOINTS) {
      try {
        await waitForThrottle();
        const response = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params,
          }),
        });

        if (!response.ok) {
          lastError = `HTTP ${response.status}`;
          continue;
        }

        const data = await response.json();
        if (data.error) {
          lastError = data.error.message || 'Solana RPC returned error';
          continue;
        }

        return { ok: true, result: data.result };
      } catch (e) {
        lastError = e?.message || 'Solana RPC fetch failed';
      }
    }

    return { ok: false, error: lastError };
  };

  try {
    if (Date.now() < _solanaTrustUnavailableUntil) {
      return [];
    }

    const sigResp = await solanaRpcCall('getSignaturesForAddress', [address, { limit: SOLANA_TRUST_MAX_SIGNATURES }]);
    if (!sigResp.ok) {
      if (isRateLimited(sigResp.error) || isEndpointUnavailable(sigResp.error)) {
        _solanaTrustUnavailableUntil = Date.now() + SOLANA_TRUST_UNAVAILABLE_COOLDOWN_MS;
      }
      throw new Error(`Failed to fetch Solana signatures (${sigResp.error})`);
    }

    const signatures = Array.isArray(sigResp.result) ? sigResp.result : [];

    const trustTxs = [];

    for (const sig of signatures) {
      const txResp = await solanaRpcCall('getTransaction', [sig.signature, { encoding: 'jsonParsed' }]);
      if (!txResp.ok) continue;
      const tx = txResp.result;

      if (!tx || !tx.meta) continue;

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
              chain: 'solana',
              ...parsed,
            });
          }
        }
      }
    }

    return trustTxs;
  } catch (err) {
    console.warn('Solana trust scan skipped:', err.message || err);
    return [];
  }
}

/**
 * Scan Ethereum blockchain for trust transactions.
 * Uses Etherscan API to query 0-value transactions with data.
 */
export async function scanEthereumTrustTransactions(address) {
  try {
    console.warn('Ethereum trust scanning requires Etherscan API key');
    return [];
  } catch (err) {
    console.error('Ethereum trust scan failed:', err);
    return [];
  }
}

// =============================================================================
// Trust Relationship Analyzer
// =============================================================================

/**
 * Analyze trust relationships from a set of transactions relative to own addresses.
 *
 * Groups transactions by counterparty address and determines direction:
 *   - 'outbound': we sent trust to them
 *   - 'inbound': they sent trust to us
 *   - 'mutual': both directions exist
 *
 * @param {string[]} ownAddresses - Array of addresses belonging to the user
 * @param {object[]} transactions - Array of trust transaction objects (from scanners)
 * @returns {object[]} Array of relationship summaries
 */
export function analyzeTrustRelationships(ownAddresses, transactions) {
  const addrs = Array.isArray(ownAddresses) ? ownAddresses : Object.values(ownAddresses || {}).filter(Boolean);
  const ownSet = new Set(addrs.map(a => a.toLowerCase()));
  const counterparties = new Map(); // address -> { outbound: [], inbound: [] }

  for (const tx of transactions) {
    if (tx.type !== 'trust') continue;

    const fromAddr = (tx.from || '').toLowerCase();
    const toAddr = (tx.recipientPubkey || '').toLowerCase();
    const isFromUs = ownSet.has(fromAddr);
    const isToUs = ownSet.has(toAddr);

    const txRecord = {
      txHash: tx.txHash,
      timestamp: tx.timestamp,
      level: tx.level,
      type: tx.type,
      chain: tx.chain || 'unknown',
    };

    if (isFromUs && !isToUs) {
      // Outbound: we sent trust to them
      const key = tx.recipientPubkey;
      if (!counterparties.has(key)) {
        counterparties.set(key, { outbound: [], inbound: [] });
      }
      counterparties.get(key).outbound.push({ ...txRecord, direction: 'outbound' });
    } else if (!isFromUs && isToUs) {
      // Inbound: they sent trust to us
      const key = tx.from;
      if (!counterparties.has(key)) {
        counterparties.set(key, { outbound: [], inbound: [] });
      }
      counterparties.get(key).inbound.push({ ...txRecord, direction: 'inbound' });
    }
  }

  const results = [];

  for (const [address, data] of counterparties) {
    const allTxs = [...data.outbound, ...data.inbound];
    allTxs.sort((a, b) => b.timestamp - a.timestamp);

    let direction;
    if (data.outbound.length > 0 && data.inbound.length > 0) {
      direction = 'mutual';
    } else if (data.outbound.length > 0) {
      direction = 'outbound';
    } else {
      direction = 'inbound';
    }

    // Use the most recent trust level
    const latest = allTxs[0];

    results.push({
      address,
      chain: latest.chain,
      level: latest.level,
      direction,
      txCount: allTxs.length,
      lastSeen: latest.timestamp,
      transactions: allTxs,
    });
  }

  // Sort by most recently seen
  results.sort((a, b) => b.lastSeen - a.lastSeen);

  return results;
}

// =============================================================================
// Trust Graph Builder
// =============================================================================

/**
 * Build trust graph from scanned transactions.
 * Returns nodes (pubkeys) and edges (trust relationships).
 */
export function buildTrustGraph(trustTxs) {
  const nodes = new Map();
  const edges = [];
  const revocations = new Map();

  // First pass: collect revocations
  for (const tx of trustTxs) {
    if (tx.type === 'revocation') {
      revocations.set(tx.originalTxHash, tx.timestamp);
    }
  }

  // Second pass: build graph
  for (const tx of trustTxs) {
    if (tx.type === 'trust') {
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
 * Calculate trust score for a pubkey based on graph.
 * Implements weighted transitive trust (web of trust).
 */
export function calculateTrustScore(graph, targetPubkey, ownPubkeys = []) {
  let score = 0;

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
      score += edge.level * 20 * 0.5;
    }
  }

  // Boomerang trust bonus (bidirectional)
  const outgoing = graph.edges.filter(e => e.from === targetPubkey && !e.revoked);
  const incoming = graph.edges.filter(e => e.to === targetPubkey && !e.revoked);

  const bidirectional = outgoing.filter(out =>
    incoming.some(inc => inc.from === out.to)
  );

  if (bidirectional.length > 0) {
    score += 10;
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
