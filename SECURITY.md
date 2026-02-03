# Security Policy

## Overview

HD Wallet WASM is a cryptographic library for hierarchical deterministic wallet operations. This document describes the security model, threat assumptions, and best practices for secure usage.

## Security Model

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Trusted Execution Environment                                  │
│  (Your application code + this library)                         │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Your App      │  │  HD Wallet WASM │  │  WebCrypto API  │ │
│  │   (JavaScript)  │◄─┤  (WASM Module)  │  │  (Browser)      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Trust Boundary
                              │
┌─────────────────────────────────────────────────────────────────┐
│  Untrusted                                                      │
│  • Network traffic (use HTTPS)                                  │
│  • Third-party scripts (use CSP)                                │
│  • Browser extensions (user responsibility)                     │
│  • Other browser tabs (same-origin policy protects)             │
└─────────────────────────────────────────────────────────────────┘
```

### Assumptions

This library assumes:

1. **Controlled execution environment**: Only your code runs on the page
2. **No malicious extensions**: Browser extensions with page access can read memory
3. **HTTPS transport**: All network communication is encrypted
4. **Secure entropy source**: Host provides cryptographically secure randomness

### What This Library Protects Against

- Memory scraping after key use (secure wiping)
- Timing attacks on cryptographic operations (constant-time comparisons)
- Weak entropy from single sources (entropy mixing)
- Accidental key exposure (masked storage)

### What This Library Does NOT Protect Against

- Compromised JavaScript execution environment
- Malicious browser extensions with page access
- Physical access to the device
- Compromised dependencies (mitigate with pinning/auditing)

## WASM Memory Model

WASM linear memory is a single `ArrayBuffer` accessible to JavaScript via `HEAPU8.buffer`. This is the same security model as MetaMask and other browser-based wallets.

**Key insight**: If you control what JavaScript runs on your page (via CSP, dependency auditing, etc.), this is not exploitable. The threat is losing control of code execution, not the memory model itself.

### Mitigations Implemented

1. **MaskedKey**: Private keys are XOR-masked when stored, requiring both mask and data to recover
2. **SecureWipe**: Memory is overwritten before deallocation using volatile writes
3. **Entropy mixing**: Injected entropy is mixed with timestamps and counters
4. **Fail-safe**: Operations fail rather than proceeding with weak protection

## Secure Usage Guidelines

### 1. Content Security Policy (Required)

Always deploy with a strict CSP to prevent XSS:

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' 'wasm-unsafe-eval';
    style-src 'self' 'unsafe-inline';
    connect-src 'self';
    frame-ancestors 'none';
">
```

### 2. Dependency Management

Pin all dependencies with integrity hashes:

```bash
npm ci --ignore-scripts
npm audit signatures
```

### 3. Entropy Initialization

Always inject entropy before key operations in WASM environments:

```javascript
// Inject entropy from crypto.getRandomValues
const entropy = new Uint8Array(64);
crypto.getRandomValues(entropy);
hdwallet.injectEntropy(entropy);
```

### 4. Key Lifecycle

Minimize the time keys exist in memory:

```javascript
// Good: derive, use, wipe immediately
const key = HDKey.fromSeed(seed);
const signature = key.sign(message);
key.wipe();  // Explicit cleanup

// The library also auto-wipes via FinalizationRegistry,
// but explicit wipe() is preferred
```

### 5. Avoid Logging Sensitive Data

Never log mnemonics, private keys, or seeds:

```javascript
// BAD
console.log(mnemonic);
console.log(key.privateKey);

// GOOD
console.log('Key derived successfully');
```

## Vulnerability Disclosure

### Reporting Security Issues

**Do NOT open public issues for security vulnerabilities.**

Please report security vulnerabilities to: [security contact email]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix development**: Depends on severity
- **Public disclosure**: After fix is released (coordinated disclosure)

### Security Advisories

Security advisories will be published via:
- GitHub Security Advisories
- Release notes
- Direct notification to known users (for critical issues)

## Cryptographic Details

### Algorithms Used

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key derivation (BIP-32) | HMAC-SHA512 | Crypto++ |
| Seed generation (BIP-39) | PBKDF2-SHA512 (2048 rounds) | Crypto++ |
| Signing (Bitcoin/Ethereum) | ECDSA secp256k1 | Crypto++ |
| Signing (Solana/Polkadot) | Ed25519 | Crypto++ |
| Hashing | SHA-256, SHA-512, Keccak-256, RIPEMD-160 | Crypto++ |
| Key encryption (optional) | AES-256-GCM | Crypto++ |
| FIPS mode (optional) | Various | OpenSSL 3.x FIPS provider |

### Entropy Sources (Priority Order)

1. Host-provided callback (highest priority)
2. HMAC-DRBG entropy pool (with mixing)
3. WASI `random_get` syscall
4. Platform CSPRNG (native builds only)

### Constant-Time Operations

The following operations use constant-time algorithms:
- Private key validation
- HMAC comparison
- Memory comparison (secureCompare)

## Audit History

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
| 2026-02-03 | Internal Red Team | Full codebase | [RED_TEAM.md](.claude/RED_TEAM.md) |

## Version History

| Version | Security Changes |
|---------|-----------------|
| 1.1.5 | MaskedKey fail-safe, entropy mixing, dependency pinning |

---

*Last updated: 2026-02-03*
