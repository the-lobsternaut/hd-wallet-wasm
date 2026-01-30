# PKI Trust Policy & Rules Engine

Full design document for adding a trust policy rules engine, organizational key hierarchy, X.509 certificate support, and encrypted settings persistence to the wallet-ui.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      wallet-ui                          │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Keys Tab │  │Bond Tab  │  │Trust Tab │  │Org Tab │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘ │
│       │              │             │             │      │
│  ┌────▼──────────────▼─────────────▼─────────────▼───┐ │
│  │                   app.js (state)                   │ │
│  └────┬──────────────┬─────────────┬─────────────┬───┘ │
│       │              │             │             │      │
│  ┌────▼────┐  ┌──────▼─────┐ ┌────▼────┐ ┌─────▼────┐ │
│  │trust-   │  │pki-x509.js │ │pki-     │ │pki-      │ │
│  │rules.js │  │(@peculiar/ │ │org.js   │ │storage.js│ │
│  │         │  │ x509)      │ │         │ │          │ │
│  └────┬────┘  └──────┬─────┘ └────┬────┘ └─────┬────┘ │
│       │              │            │             │      │
│  ┌────▼──────────────▼────────────▼─────────────▼───┐  │
│  │              trust-engine.js                      │  │
│  │         (evaluates rules against context)         │  │
│  └──────────────────────┬────────────────────────────┘  │
│                         │                               │
│  ┌──────────────────────▼────────────────────────────┐  │
│  │           wallet-storage.js (AES-256-GCM)         │  │
│  │         Encrypted persistence layer               │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Client-side only** — all crypto operations use WebCrypto API, no server
2. **NIST compliance for X.509** — certificates use P-256 or P-384 curves only (RFC 5280)
3. **Crypto curves for blockchain** — secp256k1, ed25519, x25519 for wallet operations
4. **HD derivation** — all keys derive from the BIP44 HD root where possible
5. **Encrypted at rest** — all PKI settings stored via existing AES-256-GCM infrastructure
6. **Portable** — trust policies exportable as encrypted blobs embeddable in vCards

---

## Data Models

### Organization

```javascript
{
  id: string,              // UUID
  name: string,            // "Acme Corp"
  dn: {
    CN: string,            // Common Name — org display name
    O:  string,            // Organization
    OU: string,            // Organizational Unit (department)
    C:  string,            // Country (2-letter ISO)
    ST: string,            // State/Province
    L:  string,            // Locality/City
  },
  parentOrgId: string|null, // For nested orgs (e.g., department under company)
  createdAt: number,        // Unix timestamp
}
```

**DN string format:** `CN=Engineering, OU=Engineering, O=Acme Corp, C=US`

**Hierarchy example:**
```
Acme Corp (root org)
├── Engineering (OU)
│   ├── alice (personnel key)
│   └── bob (personnel key)
└── Operations (OU)
    └── charlie (personnel key)
```

### KeyIdentity

```javascript
{
  id: string,              // UUID
  orgId: string,           // Parent organization
  label: string,           // "alice", "Engineering Root Key"
  role: 'root'|'intermediate'|'personnel',
  dn: {                    // Full DN for this identity
    CN: string,            // "Alice Smith"
    O:  string,            // Inherited from org
    OU: string,            // Inherited from org
    C:  string,
    ST: string,
    L:  string,
  },
  curve: 'P-256'|'P-384'|'secp256k1'|'ed25519'|'x25519',
  publicKey: string,       // Hex-encoded
  privateKeyRef: string,   // Reference to encrypted key in storage
  derivationPath: string|null,  // BIP44 path if HD-derived, e.g. "m/44'/0'/0'/0/0"
  certId: string|null,     // Associated X.509 certificate ID
  createdAt: number,
}
```

### TrustPolicy

```javascript
{
  id: string,
  name: string,            // "Production Security Policy"
  orgId: string|null,      // Scoped to org, or null for global
  rules: TrustRule[],
  enabled: boolean,
  createdAt: number,
  updatedAt: number,
}
```

### TrustRule

```javascript
{
  id: string,
  type: string,            // Rule type identifier (see catalog below)
  params: object,          // Type-specific parameters
  severity: 'info'|'warn'|'block',
  description: string,     // Human-readable description
}
```

### Certificate

```javascript
{
  id: string,
  keyIdentityId: string,   // The key this cert is for
  x509PEM: string,         // Full PEM-encoded X.509 certificate
  issuerCertId: string|null, // null = self-signed root
  subject: string,         // DN string
  issuer: string,          // DN string
  validFrom: number,       // Unix timestamp
  validTo: number,         // Unix timestamp
  serialNumber: string,
  fingerprint: string,     // SHA-256 of DER encoding
  extensions: {
    xpubSignature: string|null,  // secp256k1 ECDSA sig of xpub, stored as custom OID
  },
}
```

---

## Trust Rule Catalog

### Value-Based Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `minimum_total_value` | Aggregate fiat value across all keys must exceed threshold | `{ minValue: number, currency: string }` |
| `per_key_minimum` | Specific key must hold at least X value | `{ keyId: string, minValue: number, currency: string }` |
| `max_concentration` | No single network may hold more than X% of total value | `{ maxPercent: number }` |
| `key_diversity` | Require balances spread across at least N distinct networks | `{ minNetworks: number }` |

### Network / M-of-N Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `m_of_n_funded` | At least M of N specified network keys must have non-zero balance | `{ m: number, keyIds: string[] }` |
| `all_networks_funded` | Every specified network must have non-zero balance | `{ keyIds: string[] }` |

### Certificate Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `certificate_valid` | Associated X.509 cert must not be expired | `{ keyIdentityId: string }` |
| `certificate_chain_depth` | Cert chain must have at least N levels | `{ minDepth: number }` |
| `certificate_algorithm` | Cert must use specified curve | `{ allowedCurves: string[] }` |
| `xpub_signed` | xpub must be signed by first BTC signing key (m/44'/0'/0'/0/0) | `{}` |

### Key Lifecycle Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `key_age_limit` | Key must have been created/rotated within last N days | `{ maxAgeDays: number }` |
| `multi_curve_requirement` | Identity must have keys on at least N distinct curves | `{ minCurves: number }` |
| `nist_curve_required` | At least one key must use a NIST curve (P-256/P-384) | `{}` |

### Organizational Rules

| Rule Type | Description | Parameters |
|-----------|-------------|------------|
| `org_key_present` | Organization must have a root key | `{ orgId: string }` |
| `personnel_cert_signed_by_org` | Personnel certs must chain to the org root cert | `{ orgId: string }` |
| `min_personnel_keys` | Org must have at least N personnel keys | `{ orgId: string, minKeys: number }` |

---

## X.509 Certificate Architecture

### Curve Requirements

X.509 certificates **must** use NIST curves for interoperability with existing PKI infrastructure:
- **P-256** (secp256r1 / prime256v1) — 128-bit security, recommended default
- **P-384** (secp384r1) — 192-bit security, for higher assurance

Blockchain curves (secp256k1, ed25519) are **not used** in X.509 certs but are referenced via custom extensions.

### Certificate Hierarchy

```
Root CA Certificate (self-signed, P-384)
  Subject: CN=Acme Corp Root CA, O=Acme Corp, C=US
  Key: P-384 ECDSA
  Extensions: BasicConstraints(CA:TRUE), KeyUsage(keyCertSign, cRLSign)
    │
    ├── Intermediate CA Certificate (signed by Root)
    │   Subject: CN=Engineering CA, OU=Engineering, O=Acme Corp, C=US
    │   Key: P-256 ECDSA
    │   Extensions: BasicConstraints(CA:TRUE, pathLen:0)
    │     │
    │     ├── End Entity Certificate (signed by Intermediate)
    │     │   Subject: CN=Alice, OU=Engineering, O=Acme Corp, C=US
    │     │   Key: P-256 ECDSA
    │     │   Extensions:
    │     │     KeyUsage(digitalSignature)
    │     │     X-HD-XPUB: <xpub string>
    │     │     X-XPUB-SIG: <secp256k1 ECDSA signature of xpub>
    │     │
    │     └── End Entity Certificate (Bob)
    │         Subject: CN=Bob, OU=Engineering, O=Acme Corp, C=US
    │
    └── Intermediate CA Certificate (Operations dept)
        Subject: CN=Operations CA, OU=Operations, O=Acme Corp, C=US
```

### xpub Signature Embedding

The xpub is signed with the first BTC signing key (`m/44'/0'/0'/0/0`) using secp256k1 ECDSA, and embedded in the X.509 certificate as a custom extension:

- **Custom OID:** `1.3.6.1.4.1.XXXXX.1.1` (xpub value, UTF-8 string)
- **Custom OID:** `1.3.6.1.4.1.XXXXX.1.2` (secp256k1 ECDSA signature, DER-encoded)
- **Custom OID:** `1.3.6.1.4.1.XXXXX.1.3` (signing public key, compressed secp256k1 point)

This allows any verifier to:
1. Extract the xpub from the certificate extension
2. Extract the signature and the BTC public key
3. Verify the signature using secp256k1 ECDSA
4. Derive BTC address from the public key and confirm it matches the expected key

### Library: @peculiar/x509

Browser-compatible X.509 library built on WebCrypto API.

```javascript
import * as x509 from '@peculiar/x509';

// Set crypto provider
x509.cryptoProvider.set(crypto);

// Generate self-signed root CA
const rootKeys = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']
);
const rootCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: '01',
  name: 'CN=Root CA, O=Acme Corp, C=US',
  notBefore: new Date(),
  notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000),
  keys: rootKeys,
  signingAlgorithm: { name: 'ECDSA', hash: 'SHA-384' },
  extensions: [
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ],
});
```

---

## Encrypted Settings Persistence

### Storage Format

PKI settings are stored as a single encrypted JSON blob using the existing AES-256-GCM infrastructure from `wallet-storage.js`:

```javascript
{
  version: 1,
  organizations: Organization[],
  identities: KeyIdentity[],
  policies: TrustPolicy[],
  certificates: Certificate[],
}
```

### Encryption Flow

1. Serialize settings to JSON
2. Encrypt using existing `WalletStorage.encrypt(json, key, iv)` (AES-256-GCM)
3. Store in localStorage under key `pki-settings-encrypted`
4. Metadata stored under `pki-settings-metadata`

### vCard Embedding

For portability, the encrypted settings blob can be embedded in a vCard:

```vcard
item10.X-ABLabel:X-TRUST-POLICY
item10.X-ABRELATEDNAMES:<base64-encoded AES-256-GCM ciphertext>
```

On import, the recipient can decrypt using a shared key (derived from the same master seed or exchanged out-of-band).

---

## New Modules

| File | Purpose |
|------|---------|
| `wallet-ui/src/pki-storage.js` | Save/load/export/import encrypted PKI settings |
| `wallet-ui/src/pki-org.js` | Organization and KeyIdentity CRUD operations |
| `wallet-ui/src/trust-rules.js` | Rule type definitions and individual evaluators |
| `wallet-ui/src/trust-engine.js` | Policy evaluation, trust score calculation |
| `wallet-ui/src/pki-x509.js` | X.509 cert generation, chain ops, import/export |

---

## Implementation Tasks

### Phase 1: Data Models & Storage Foundation

- [ ] Define `Organization` model in `pki-org.js`
- [ ] Define `KeyIdentity` model in `pki-org.js`
- [ ] Define `TrustPolicy` and `TrustRule` models in `trust-rules.js`
- [ ] Define `Certificate` model in `pki-x509.js`
- [ ] Add storage keys to `constants.js`: `PKI_SETTINGS_KEY`, `PKI_SETTINGS_META_KEY`
- [ ] Create `pki-storage.js` module
- [ ] Implement `savePKISettings(settings, encryptionKey, iv)` reusing AES-256-GCM from `wallet-storage.js`
- [ ] Implement `loadPKISettings(encryptionKey, iv)` decryption
- [ ] Implement `exportSettingsBlob()` returning base64 encrypted blob for vCard embedding
- [ ] Implement `importSettingsBlob(blob, key)` to restore from vCard
- [ ] Integrate with existing PIN/passkey unlock flow so PKI settings load alongside wallet data

### Phase 2: Trust Policy Rules Engine

#### 2.1 Rule Evaluators
- [ ] Create `trust-rules.js` module with rule type registry
- [ ] Implement `minimum_total_value` evaluator
- [ ] Implement `m_of_n_funded` evaluator
- [ ] Implement `per_key_minimum` evaluator
- [ ] Implement `key_diversity` evaluator
- [ ] Implement `max_concentration` evaluator
- [ ] Implement `certificate_valid` evaluator
- [ ] Implement `certificate_chain_depth` evaluator
- [ ] Implement `certificate_algorithm` evaluator
- [ ] Implement `key_age_limit` evaluator
- [ ] Implement `multi_curve_requirement` evaluator
- [ ] Implement `xpub_signed` evaluator
- [ ] Implement `nist_curve_required` evaluator
- [ ] Implement `org_key_present` evaluator
- [ ] Implement `personnel_cert_signed_by_org` evaluator
- [ ] Implement `min_personnel_keys` evaluator
- [ ] Implement `all_networks_funded` evaluator

#### 2.2 Engine Core
- [ ] Create `trust-engine.js` module
- [ ] Implement `evaluateRule(rule, context)` → `{ passed, message, severity }`
- [ ] Implement `evaluatePolicy(policy, context)` → aggregate result with per-rule breakdown
- [ ] Build `context` from: current balances, key inventory, certificate store, price data, org data
- [ ] Implement `getTrustScore(policies)` → 0–100 numeric score (weighted by severity: block=3x, warn=2x, info=1x)
- [ ] Replace current trust meter logic (`Math.log10(totalConverted + 1) * 33`) with trust score

#### 2.3 Policy CRUD
- [ ] Implement `createPolicy(name, orgId)`
- [ ] Implement `addRule(policyId, ruleType, params, severity)`
- [ ] Implement `removeRule(policyId, ruleId)`
- [ ] Implement `updateRule(policyId, ruleId, params)`
- [ ] Implement `togglePolicy(policyId, enabled)`
- [ ] Implement `deletePolicy(policyId)`
- [ ] Auto-save to encrypted storage on every mutation

### Phase 3: Key Hierarchy & Organizations

#### 3.1 Organization Management
- [ ] Create `pki-org.js` module
- [ ] Implement `createOrganization({ name, dn })`
- [ ] Implement `updateOrganization(orgId, fields)`
- [ ] Implement `deleteOrganization(orgId)` with cascade delete of identities
- [ ] Support nested organizations via `parentOrgId`
- [ ] Implement `buildDNString(org)` → `CN=..., OU=..., O=..., C=...`
- [ ] Implement `getOrgHierarchy(rootOrgId)` → tree structure

#### 3.2 Key Identity Management
- [ ] Implement `createKeyIdentity({ orgId, label, role, curve, derivationPath })`
- [ ] For HD-derivable curves (secp256k1, ed25519): derive from HD root using BIP44 path
- [ ] For NIST curves (P-256, P-384): use `crypto.subtle.generateKey` with ECDSA
- [ ] Concatenate org DN + identity CN for full DN path
- [ ] Implement `listIdentities(orgId)` with role filtering
- [ ] Implement `getIdentity(id)`
- [ ] Implement `deleteIdentity(id)`

#### 3.3 vCard Integration
- [ ] Extend `generateVCard()` in `app.js` to include organization keys in `person.KEY` array
- [ ] Add DN path as custom `X-DN` vCard field
- [ ] Embed encrypted trust policy blob as `X-TRUST-POLICY` vCard extension
- [ ] On vCard import: detect and parse `X-TRUST-POLICY`, offer to load settings
- [ ] On vCard import: detect and parse `X-DN`, populate org/identity data

### Phase 4: X.509 Certificate Support

#### 4.1 Library Setup
- [ ] Add `@peculiar/x509` to `wallet-ui/package.json`
- [ ] Create `pki-x509.js` module
- [ ] Initialize `x509.cryptoProvider.set(crypto)` on load

#### 4.2 Certificate Generation
- [ ] Implement `generateSelfSignedCert(keyIdentity, { subject, validityYears })` — root CA, NIST curves only
- [ ] Implement `generateSignedCert(keyIdentity, issuerCert, issuerKey, { subject, validityYears, isCA })` — intermediate or end entity
- [ ] Implement `signXpubWithBTCKey(xpub)` — sign with key at m/44'/0'/0'/0/0 using secp256k1 ECDSA
- [ ] Embed xpub + signature as custom X.509 extensions (custom OIDs)
- [ ] Store generated certs in Certificate model, persist via `pki-storage.js`

#### 4.3 Certificate Chain
- [ ] Implement `buildCertChain(endEntityCertId)` — traverse `issuerCertId` links to root
- [ ] Implement `verifyCertChain(chain)` — validate signatures and expiry at each level
- [ ] Implement `getCertificateStatus(certId)` → valid / expired / no-chain / unknown

#### 4.4 Import / Export
- [ ] Implement `importPEM(pemString)` — parse X.509 PEM into Certificate model
- [ ] Implement `exportPEM(certId)` — serialize to PEM string
- [ ] Implement `importFromFile(file)` — handle .pem, .crt, .cer, .der file types
- [ ] Add certificate public keys to vCard `KEY` entries with appropriate type

### Phase 5: UI Components

#### 5.1 Trust Policy Tab
- [ ] Add "Trust Policy" tab button to keys-modal tab bar in `wallet-template.html`
- [ ] Create `trust-policy-tab-content` div
- [ ] Policy list view: name, org scope, enabled toggle, rule count, trust score badge
- [ ] "Create Policy" form: name, org selector, initial rules
- [ ] Rule editor: rule-type dropdown, parameter inputs per type, severity selector
- [ ] Per-rule status indicators (pass/fail/warn)
- [ ] Trust score visualization: upgrade trust meter to show rule-by-rule breakdown
- [ ] Import/Export buttons for encrypted policy blobs

#### 5.2 Organizations Tab
- [ ] Add "Organizations" tab or section to keys-modal
- [ ] Organization list with create/edit/delete
- [ ] DN editor form: CN, O, OU, C, ST, L fields
- [ ] Key identity list per org with role badges (root / intermediate / personnel)
- [ ] Tree view showing org hierarchy with nested departments
- [ ] Certificate status chip next to each key (green=valid, red=expired, gray=none)

#### 5.3 Certificate Management
- [ ] Certificate detail viewer: subject, issuer, validity, serial, fingerprint, extensions
- [ ] Chain visualization: Root → Intermediate → End Entity
- [ ] Import button (file picker for .pem/.crt/.cer)
- [ ] Generate button (form: subject DN, validity, issuer selection, curve)
- [ ] Export buttons: PEM download, copy-to-clipboard

#### 5.4 Styling
- [ ] Follow existing glass-morphism pattern (`glass-btn`, `glass-input`, `glass-select`)
- [ ] Trust score colors: green (80–100), yellow (50–79), red (0–49)
- [ ] Certificate badges: green=valid, red=expired, gray=none
- [ ] Org tree uses indentation + connector lines (CSS borders)

### Phase 6: Integration & Testing

#### 6.1 App.js Wiring
- [ ] Import new modules (`pki-storage`, `pki-org`, `trust-rules`, `trust-engine`, `pki-x509`)
- [ ] Add PKI state to the `state` object: `state.pki = { orgs, identities, policies, certs }`
- [ ] Wire Trust Policy tab event listeners in `setupMainAppHandlers()`
- [ ] Modify `updateAdversarialSecurity()` to run trust engine evaluation after balance fetch
- [ ] Modify `generateVCard()` to embed org keys and encrypted trust policy blob
- [ ] Modify login flow to load PKI settings on wallet unlock
- [ ] Modify logout to clear PKI state

#### 6.2 Testing
- [ ] Unit tests for each rule type evaluator
- [ ] Unit tests for policy evaluation and trust score calculation
- [ ] Unit tests for X.509 cert generation, chain building, and verification
- [ ] Unit tests for encrypted settings export/import round-trip
- [ ] Integration test: create org → add identity → generate cert → create policy → evaluate
- [ ] Cross-browser test: WebCrypto ECDSA with P-256/P-384 in Chrome, Firefox, Safari

#### 6.3 Documentation
- [ ] Document trust rule types and parameters in this file
- [ ] Document DN structure and org hierarchy model
- [ ] Document vCard extension fields (`X-TRUST-POLICY`, `X-DN`)
- [ ] Document encrypted blob format for interoperability
- [ ] Document custom X.509 OIDs for xpub signature embedding

---

## References

- [RFC 5280 — X.509 PKI Certificate Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [NIST SP 800-57 — Key Management Recommendations](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt3r1.pdf)
- [NIST SP 800-78 — PIV Cryptographic Algorithms](https://csrc.nist.rip/library/NIST%20SP%20800-078-2%20Cryptographic%20Algorithms%20and%20Key%20Sizes%20for%20Personal%20Identification%20Verification%20(PIV),%202010-02.pdf)
- [@peculiar/x509 — Browser X.509 Library](https://github.com/PeculiarVentures/x509)
- [PKIjs — WebCrypto PKI Library](https://pkijs.org/)
- [SEAL Multisig Best Practices](https://frameworks.securityalliance.org/wallet-security/secure-multisig-best-practices/)
- [X.509 Certificate Structure](https://en.wikipedia.org/wiki/X.509)
