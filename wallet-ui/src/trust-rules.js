/**
 * Trust Rules Module
 *
 * Defines all trust rule types with their evaluators.
 * Each rule evaluator takes (rule, context) and returns { passed, message, severity }.
 */

// =============================================================================
// Rule Type Registry
// =============================================================================

const ruleEvaluators = {};

function registerRule(type, evaluator) {
  ruleEvaluators[type] = evaluator;
}

export function getEvaluator(type) {
  return ruleEvaluators[type] || null;
}

export function getRuleTypes() {
  return Object.keys(ruleEvaluators);
}

// =============================================================================
// Rule Metadata (for UI)
// =============================================================================

export const RULE_METADATA = {
  minimum_total_value: { label: 'Minimum Total Value', category: 'value', params: ['minValue', 'currency'] },
  per_key_minimum: { label: 'Per-Key Minimum', category: 'value', params: ['keyId', 'minValue', 'currency'] },
  max_concentration: { label: 'Max Concentration', category: 'value', params: ['maxPercent'] },
  key_diversity: { label: 'Key Diversity', category: 'value', params: ['minNetworks'] },
  m_of_n_funded: { label: 'M-of-N Funded', category: 'network', params: ['m', 'keyIds'] },
  all_networks_funded: { label: 'All Networks Funded', category: 'network', params: ['keyIds'] },
  certificate_valid: { label: 'Certificate Valid', category: 'certificate', params: ['keyIdentityId'] },
  certificate_chain_depth: { label: 'Chain Depth', category: 'certificate', params: ['minDepth'] },
  certificate_algorithm: { label: 'Certificate Algorithm', category: 'certificate', params: ['allowedCurves'] },
  xpub_signed: { label: 'XPUB Signed', category: 'certificate', params: [] },
  key_age_limit: { label: 'Key Age Limit', category: 'lifecycle', params: ['maxAgeDays'] },
  multi_curve_requirement: { label: 'Multi-Curve Requirement', category: 'lifecycle', params: ['minCurves'] },
  nist_curve_required: { label: 'NIST Curve Required', category: 'lifecycle', params: [] },
  org_key_present: { label: 'Org Key Present', category: 'organizational', params: ['orgId'] },
  personnel_cert_signed_by_org: { label: 'Personnel Cert Signed by Org', category: 'organizational', params: ['orgId'] },
  min_personnel_keys: { label: 'Min Personnel Keys', category: 'organizational', params: ['orgId', 'minKeys'] },
  all_networks_funded: { label: 'All Networks Funded', category: 'network', params: ['keyIds'] },
};

// =============================================================================
// Value-Based Rules
// =============================================================================

registerRule('minimum_total_value', (rule, ctx) => {
  const { minValue = 0, currency = 'USD' } = rule.params;
  const total = ctx.totalValue || 0;
  return {
    passed: total >= minValue,
    message: total >= minValue
      ? `Total value ${total.toFixed(2)} meets minimum ${minValue}`
      : `Total value ${total.toFixed(2)} below minimum ${minValue}`,
    severity: rule.severity,
  };
});

registerRule('per_key_minimum', (rule, ctx) => {
  const { keyId, minValue = 0 } = rule.params;
  const balance = ctx.balances?.[keyId] || 0;
  const value = balance * (ctx.prices?.[keyId] || 0);
  return {
    passed: value >= minValue,
    message: value >= minValue
      ? `Key ${keyId} value ${value.toFixed(2)} meets minimum`
      : `Key ${keyId} value ${value.toFixed(2)} below minimum ${minValue}`,
    severity: rule.severity,
  };
});

registerRule('max_concentration', (rule, ctx) => {
  const { maxPercent = 50 } = rule.params;
  const total = ctx.totalValue || 0;
  if (total === 0) return { passed: true, message: 'No value to concentrate', severity: rule.severity };

  let maxConcentration = 0;
  let maxNetwork = '';
  for (const [net, bal] of Object.entries(ctx.balances || {})) {
    const value = bal * (ctx.prices?.[net.toUpperCase()] || 0);
    const pct = (value / total) * 100;
    if (pct > maxConcentration) {
      maxConcentration = pct;
      maxNetwork = net;
    }
  }
  return {
    passed: maxConcentration <= maxPercent,
    message: maxConcentration <= maxPercent
      ? `Max concentration ${maxConcentration.toFixed(1)}% within limit`
      : `${maxNetwork} concentration ${maxConcentration.toFixed(1)}% exceeds ${maxPercent}% limit`,
    severity: rule.severity,
  };
});

registerRule('key_diversity', (rule, ctx) => {
  const { minNetworks = 3 } = rule.params;
  let funded = 0;
  for (const bal of Object.values(ctx.balances || {})) {
    if (parseFloat(bal) > 0) funded++;
  }
  return {
    passed: funded >= minNetworks,
    message: funded >= minNetworks
      ? `${funded} networks funded (minimum ${minNetworks})`
      : `Only ${funded} networks funded, need ${minNetworks}`,
    severity: rule.severity,
  };
});

// =============================================================================
// Network / M-of-N Rules
// =============================================================================

registerRule('m_of_n_funded', (rule, ctx) => {
  const { m = 2, keyIds = [] } = rule.params;
  const n = keyIds.length;
  let funded = 0;
  for (const id of keyIds) {
    if (parseFloat(ctx.balances?.[id] || 0) > 0) funded++;
  }
  return {
    passed: funded >= m,
    message: funded >= m
      ? `${funded} of ${n} keys funded (need ${m})`
      : `Only ${funded} of ${n} keys funded, need ${m}`,
    severity: rule.severity,
  };
});

registerRule('all_networks_funded', (rule, ctx) => {
  const { keyIds = [] } = rule.params;
  const unfunded = keyIds.filter(id => !(parseFloat(ctx.balances?.[id] || 0) > 0));
  return {
    passed: unfunded.length === 0,
    message: unfunded.length === 0
      ? `All ${keyIds.length} networks funded`
      : `${unfunded.length} networks unfunded: ${unfunded.join(', ')}`,
    severity: rule.severity,
  };
});

// =============================================================================
// Certificate Rules
// =============================================================================

registerRule('certificate_valid', (rule, ctx) => {
  const { keyIdentityId } = rule.params;
  const cert = ctx.certificates?.[keyIdentityId];
  if (!cert) return { passed: false, message: `No certificate for key ${keyIdentityId}`, severity: rule.severity };
  const now = Date.now();
  const valid = now >= cert.validFrom && now <= cert.validTo;
  return {
    passed: valid,
    message: valid ? 'Certificate is valid' : 'Certificate expired or not yet valid',
    severity: rule.severity,
  };
});

registerRule('certificate_chain_depth', (rule, ctx) => {
  const { minDepth = 2 } = rule.params;
  const maxDepth = ctx.maxChainDepth || 0;
  return {
    passed: maxDepth >= minDepth,
    message: maxDepth >= minDepth
      ? `Chain depth ${maxDepth} meets minimum ${minDepth}`
      : `Chain depth ${maxDepth} below minimum ${minDepth}`,
    severity: rule.severity,
  };
});

registerRule('certificate_algorithm', (rule, ctx) => {
  const { allowedCurves = ['P-256', 'P-384'] } = rule.params;
  const certs = Object.values(ctx.certificates || {});
  const invalid = certs.filter(c => c.curve && !allowedCurves.includes(c.curve));
  return {
    passed: invalid.length === 0,
    message: invalid.length === 0
      ? `All certificates use allowed curves`
      : `${invalid.length} certificates use disallowed curves`,
    severity: rule.severity,
  };
});

registerRule('xpub_signed', (rule, ctx) => {
  const signed = !!ctx.xpubSignature;
  return {
    passed: signed,
    message: signed ? 'XPUB is signed by BTC key' : 'XPUB not signed by BTC key',
    severity: rule.severity,
  };
});

// =============================================================================
// Key Lifecycle Rules
// =============================================================================

registerRule('key_age_limit', (rule, ctx) => {
  const { maxAgeDays = 365 } = rule.params;
  const now = Date.now();
  const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
  const identities = Object.values(ctx.identities || {});
  const expired = identities.filter(k => (now - (k.createdAt || 0)) > maxAgeMs);
  return {
    passed: expired.length === 0,
    message: expired.length === 0
      ? `All keys within ${maxAgeDays}-day age limit`
      : `${expired.length} keys exceed ${maxAgeDays}-day age limit`,
    severity: rule.severity,
  };
});

registerRule('multi_curve_requirement', (rule, ctx) => {
  const { minCurves = 2 } = rule.params;
  const curves = new Set();
  for (const k of Object.values(ctx.identities || {})) {
    if (k.curve) curves.add(k.curve);
  }
  return {
    passed: curves.size >= minCurves,
    message: curves.size >= minCurves
      ? `${curves.size} distinct curves (need ${minCurves})`
      : `Only ${curves.size} curves, need ${minCurves}`,
    severity: rule.severity,
  };
});

registerRule('nist_curve_required', (rule, ctx) => {
  const nistCurves = ['P-256', 'P-384', 'P-521'];
  const hasNist = Object.values(ctx.identities || {}).some(k => nistCurves.includes(k.curve));
  return {
    passed: hasNist,
    message: hasNist ? 'NIST curve key present' : 'No NIST curve key found',
    severity: rule.severity,
  };
});

// =============================================================================
// Organizational Rules
// =============================================================================

registerRule('org_key_present', (rule, ctx) => {
  const { orgId } = rule.params;
  const orgKeys = Object.values(ctx.identities || {}).filter(k => k.orgId === orgId && k.role === 'root');
  return {
    passed: orgKeys.length > 0,
    message: orgKeys.length > 0 ? 'Organization root key present' : 'No organization root key',
    severity: rule.severity,
  };
});

registerRule('personnel_cert_signed_by_org', (rule, ctx) => {
  const { orgId } = rule.params;
  const personnel = Object.values(ctx.identities || {}).filter(k => k.orgId === orgId && k.role === 'personnel');
  const unsigned = personnel.filter(k => !ctx.certificates?.[k.id]?.issuerCertId);
  return {
    passed: unsigned.length === 0,
    message: unsigned.length === 0
      ? 'All personnel certs chain to org'
      : `${unsigned.length} personnel certs not signed by org`,
    severity: rule.severity,
  };
});

registerRule('min_personnel_keys', (rule, ctx) => {
  const { orgId, minKeys = 2 } = rule.params;
  const count = Object.values(ctx.identities || {}).filter(k => k.orgId === orgId && k.role === 'personnel').length;
  return {
    passed: count >= minKeys,
    message: count >= minKeys
      ? `${count} personnel keys (need ${minKeys})`
      : `Only ${count} personnel keys, need ${minKeys}`,
    severity: rule.severity,
  };
});

// =============================================================================
// Policy / Rule Model Helpers
// =============================================================================

let _nextId = 0;
function genId() {
  return `${Date.now()}-${++_nextId}-${Math.random().toString(36).slice(2, 8)}`;
}

export function createPolicy(name, orgId = null) {
  return {
    id: genId(),
    name,
    orgId,
    rules: [],
    enabled: true,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
}

export function addRule(policy, type, params = {}, severity = 'warn', description = '') {
  const rule = {
    id: genId(),
    type,
    params,
    severity,
    description: description || (RULE_METADATA[type]?.label || type),
  };
  policy.rules.push(rule);
  policy.updatedAt = Date.now();
  return rule;
}

export function removeRule(policy, ruleId) {
  policy.rules = policy.rules.filter(r => r.id !== ruleId);
  policy.updatedAt = Date.now();
}

export function updateRule(policy, ruleId, updates) {
  const rule = policy.rules.find(r => r.id === ruleId);
  if (rule) {
    Object.assign(rule, updates);
    policy.updatedAt = Date.now();
  }
}
