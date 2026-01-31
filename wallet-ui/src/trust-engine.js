/**
 * Trust Engine Module
 *
 * Evaluates trust policies against context (balances, keys, certs, prices).
 * Produces trust scores and per-rule breakdowns.
 */

import { getEvaluator } from './trust-rules.js';

// Severity weights for trust score calculation
const SEVERITY_WEIGHT = { block: 3, warn: 2, info: 1 };

/**
 * Evaluate a single rule against context.
 *
 * @param {Object} rule — { id, type, params, severity, description }
 * @param {Object} context — Runtime context with balances, prices, identities, etc.
 * @returns {Object} { ruleId, type, passed, message, severity }
 */
export function evaluateRule(rule, context) {
  const evaluator = getEvaluator(rule.type);
  if (!evaluator) {
    return {
      ruleId: rule.id,
      type: rule.type,
      passed: false,
      message: `Unknown rule type: ${rule.type}`,
      severity: rule.severity,
    };
  }
  const result = evaluator(rule, context);
  return {
    ruleId: rule.id,
    type: rule.type,
    passed: result.passed,
    message: result.message,
    severity: result.severity || rule.severity,
  };
}

/**
 * Evaluate all rules in a policy.
 *
 * @param {Object} policy — { id, name, rules[], enabled }
 * @param {Object} context — Runtime context
 * @returns {Object} { policyId, name, results[], passed, score, blockers }
 */
export function evaluatePolicy(policy, context) {
  if (!policy.enabled) {
    return {
      policyId: policy.id,
      name: policy.name,
      results: [],
      passed: true,
      score: 100,
      blockers: [],
    };
  }

  const results = policy.rules.map(rule => evaluateRule(rule, context));
  const blockers = results.filter(r => !r.passed && r.severity === 'block');
  const passed = blockers.length === 0;

  // Score: weighted pass rate
  let totalWeight = 0;
  let passedWeight = 0;
  for (const r of results) {
    const w = SEVERITY_WEIGHT[r.severity] || 1;
    totalWeight += w;
    if (r.passed) passedWeight += w;
  }
  const score = totalWeight > 0 ? Math.round((passedWeight / totalWeight) * 100) : 100;

  return { policyId: policy.id, name: policy.name, results, passed, score, blockers };
}

/**
 * Evaluate multiple policies and produce an aggregate trust score.
 *
 * @param {Object[]} policies — Array of trust policies
 * @param {Object} context — Runtime context
 * @returns {Object} { score, policyResults[], allPassed, totalBlockers }
 */
export function getTrustScore(policies, context) {
  const enabledPolicies = policies.filter(p => p.enabled);
  if (enabledPolicies.length === 0) {
    return { score: 100, policyResults: [], allPassed: true, totalBlockers: 0 };
  }

  const policyResults = enabledPolicies.map(p => evaluatePolicy(p, context));

  // Aggregate score: average of policy scores
  const totalScore = policyResults.reduce((sum, pr) => sum + pr.score, 0);
  const score = Math.round(totalScore / policyResults.length);

  const totalBlockers = policyResults.reduce((sum, pr) => sum + pr.blockers.length, 0);
  const allPassed = totalBlockers === 0;

  return { score, policyResults, allPassed, totalBlockers };
}

/**
 * Build a trust evaluation context from wallet state.
 *
 * @param {Object} opts — { balances, prices, identities, certificates, xpubSignature, maxChainDepth }
 * @returns {Object} context object for rule evaluation
 */
export function buildContext(opts = {}) {
  const balances = opts.balances || {};
  const prices = opts.prices || {};

  // Calculate total value
  let totalValue = 0;
  for (const [net, bal] of Object.entries(balances)) {
    totalValue += (parseFloat(bal) || 0) * (prices[net.toUpperCase()] || 0);
  }

  return {
    balances,
    prices,
    totalValue,
    identities: opts.identities || {},
    certificates: opts.certificates || {},
    xpubSignature: opts.xpubSignature || null,
    maxChainDepth: opts.maxChainDepth || 0,
  };
}
