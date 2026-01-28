# HD Wallet WASM

[![CI](https://github.com/DigitalArsenal/hd-wallet-wasm/actions/workflows/ci.yml/badge.svg)](https://github.com/DigitalArsenal/hd-wallet-wasm/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/hd-wallet-wasm.svg)](https://www.npmjs.com/package/hd-wallet-wasm)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A comprehensive hierarchical deterministic (HD) wallet implementation in pure C++ with Crypto++, compiled to WebAssembly for cross-platform compatibility.

## Overview

HD Wallet WASM provides a complete implementation of BIP-32/39/44 hierarchical deterministic wallets with extensive multi-chain and multi-curve support. The library is written in pure C++ using the Crypto++ cryptographic library and compiles to WebAssembly, enabling use in browsers, Node.js, and any WASI-compatible runtime (Go, Rust, Python, etc.).

**Key capabilities:**

- **BIP Standards**: Full implementation of BIP-32 (HD derivation), BIP-39 (mnemonics), and BIP-44/49/84 (derivation paths)
- **Multi-Curve Cryptography**: secp256k1, Ed25519, NIST P-256, NIST P-384, and X25519
- **Multi-Chain Support**: Bitcoin, Ethereum, Cosmos, Solana, Polkadot, and 50+ coins via SLIP-44
- **Hardware Wallet Abstraction**: Unified API for KeepKey, Trezor, and Ledger devices
- **WebAssembly**: Pure C++ compiled to WASM for cross-language interoperability

## Features

- **Mnemonic Generation & Validation**
  - 12, 15, 18, 21, or 24 word phrases
  - Support for 10 languages (English, Japanese, Korean, Spanish, Chinese, French, Italian, Czech, Portuguese)
  - Word suggestion and autocomplete

- **HD Key Derivation**
  - BIP-32 hierarchical deterministic keys
  - Hardened and non-hardened derivation
  - Extended public/private key serialization (xprv/xpub)

- **Multi-Curve Support**
  - secp256k1 (Bitcoin, Ethereum, Cosmos)
  - Ed25519 (Solana, Polkadot)
  - NIST P-256 (secp256r1)
  - NIST P-384 (secp384r1)
  - X25519 (key exchange)

- **Blockchain Support**
  - Bitcoin: P2PKH, P2SH, P2WPKH, P2WSH, Taproot addresses; transaction building and signing
  - Ethereum: EIP-55 checksum addresses, EIP-191 message signing, EIP-712 typed data, legacy and EIP-1559 transactions
  - Cosmos/Tendermint: Amino and Direct signing
  - Solana: Ed25519 addresses and signing
  - Polkadot: SS58 addresses, Sr25519/Ed25519 signing

- **Hardware Wallet Support**
  - Unified abstraction for KeepKey, Trezor, and Ledger
  - Device enumeration, connection management
  - Transaction and message signing via device

- **Security**
  - Secure memory wiping (prevents compiler optimization)
  - SecureVector/SecureArray for automatic cleanup
  - Memory locking to prevent swapping (mlock)
  - Optional FIPS-compliant mode

- **Cryptographic Utilities**
  - Hash functions: SHA-256, SHA-512, Keccak-256, RIPEMD-160, BLAKE2b/s
  - Key derivation: HKDF, PBKDF2, scrypt
  - Encoding: Base58, Base58Check, Bech32, Hex, Base64

## Installation

### NPM

```bash
npm install hd-wallet-wasm
```

### CDN

```html
<!-- ES Module -->
<script type="module">
  import HDWalletWasm from 'https://unpkg.com/hd-wallet-wasm/dist/hd-wallet.js';

  const wallet = await HDWalletWasm();
  // Use wallet...
</script>
```

### Building from Source

**Prerequisites:**
- CMake 3.16+
- C++17 compiler (GCC 8+, Clang 10+, MSVC 2019+)
- Emscripten SDK (for WASM builds)

```bash
# Clone the repository
git clone https://github.com/DigitalArsenal/hd-wallet-wasm.git
cd hd-wallet-wasm

# Native build
cmake -B build -S .
cmake --build build

# WASM build (requires Emscripten)
emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON
cmake --build build
```

## Quick Start

### Generating a Mnemonic

```javascript
import HDWalletWasm, { Curve, BitcoinAddressType, Network, WasiFeature } from 'hd-wallet-wasm';

const wallet = await HDWalletWasm();

// Generate a 24-word mnemonic
const mnemonic = wallet.mnemonic.generate(24);
console.log('Mnemonic:', mnemonic);

// Validate mnemonic
const isValid = wallet.mnemonic.validate(mnemonic);
console.log('Valid:', isValid);

// Convert to seed (with optional passphrase)
const seed = wallet.mnemonic.toSeed(mnemonic, 'optional passphrase');
```

### Deriving Keys

```javascript
// Create master key from seed
const masterKey = wallet.hdkey.fromSeed(seed);

// Derive using BIP-44 path for Ethereum
// m/44'/60'/0'/0/0
const ethKey = masterKey.derivePath("m/44'/60'/0'/0/0");

// Get private and public keys
const privateKey = ethKey.privateKey();
const publicKey = ethKey.publicKey();

// Serialize as extended keys
const xprv = masterKey.toXprv();
const xpub = masterKey.toXpub();

// Wipe sensitive data when done
ethKey.wipe();
masterKey.wipe();
```

### Getting Addresses

```javascript
// Bitcoin addresses (various formats)
const btcKey = masterKey.derivePath("m/84'/0'/0'/0/0");
const p2wpkh = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2WPKH);
const p2pkh = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2PKH);
const taproot = wallet.bitcoin.getAddress(btcKey.publicKey(), BitcoinAddressType.P2TR);

// Ethereum address
const ethKey = masterKey.derivePath("m/44'/60'/0'/0/0");
const ethAddress = wallet.ethereum.getAddress(ethKey.publicKey());
const checksumAddress = wallet.ethereum.getChecksumAddress(ethAddress);

// Solana address (Ed25519)
const solSeed = wallet.mnemonic.toSeed(mnemonic);
const solKey = wallet.hdkey.fromSeed(solSeed, Curve.ED25519);
const solAddress = wallet.solana.getAddress(solKey.derivePath("m/44'/501'/0'/0'").publicKey());

// Cosmos address
const cosmosKey = masterKey.derivePath("m/44'/118'/0'/0/0");
const cosmosAddress = wallet.cosmos.getAddress(cosmosKey.publicKey(), 'cosmos');
```

### Signing Messages

```javascript
// Bitcoin signed message
const btcSignature = wallet.bitcoin.signMessage('Hello Bitcoin!', btcKey.privateKey());

// Ethereum signed message (EIP-191)
const ethSignature = wallet.ethereum.signMessage('Hello Ethereum!', ethKey.privateKey());

// Ethereum typed data (EIP-712)
const typedData = {
  types: { /* ... */ },
  primaryType: 'Mail',
  domain: { /* ... */ },
  message: { /* ... */ }
};
const typedSignature = wallet.ethereum.signTypedData(typedData, ethKey.privateKey());

// Raw curve signing
const messageHash = wallet.utils.keccak256(new TextEncoder().encode('message'));
const { signature, recoveryId } = wallet.curves.secp256k1.signRecoverable(messageHash, privateKey);
const recovered = wallet.curves.secp256k1.recover(messageHash, signature, recoveryId);
```

### Building Transactions

```javascript
// Bitcoin transaction
const btcTx = wallet.bitcoin.tx.create()
  .addInput('txid...', 0)
  .addOutput('bc1q...', 50000n)
  .sign(0, btcKey.privateKey());

const btcRawTx = btcTx.serialize();
const txid = btcTx.getTxid();

// Ethereum transaction (EIP-1559)
const ethTx = wallet.ethereum.tx.createEIP1559({
  nonce: 0,
  maxFeePerGas: 30000000000n,
  maxPriorityFeePerGas: 1000000000n,
  gasLimit: 21000n,
  to: '0x...',
  value: 1000000000000000000n,
  chainId: 1
}).sign(ethKey.privateKey());

const ethRawTx = ethTx.serialize();
```

## API Reference

Full API documentation is available at [https://digitalarsenal.github.io/hd-wallet-wasm/](https://digitalarsenal.github.io/hd-wallet-wasm/).

### Main APIs

| API | Description |
|-----|-------------|
| `mnemonic` | BIP-39 mnemonic generation, validation, and conversion |
| `hdkey` | BIP-32 HD key derivation and serialization |
| `curves` | Multi-curve cryptography (secp256k1, Ed25519, P-256, P-384, X25519) |
| `bitcoin` | Bitcoin addresses, message signing, transaction building |
| `ethereum` | Ethereum addresses, EIP-191/712 signing, transactions |
| `cosmos` | Cosmos/Tendermint addresses and signing |
| `solana` | Solana addresses and signing |
| `polkadot` | Polkadot/Substrate addresses and signing |
| `hardware` | Hardware wallet abstraction (KeepKey, Trezor, Ledger) |
| `keyring` | Multi-wallet key management |
| `utils` | Hash functions, encoding, key derivation |

### Low-Level C API

The library exports 200+ C functions for direct WASM interop:

```javascript
// Direct ccall usage
const mnemonic = wallet.ccall('hd_mnemonic_generate', 'string', ['number'], [24]);
const isValid = wallet.ccall('hd_mnemonic_validate', 'number', ['string'], [mnemonic]);
```

## Building

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `HD_WALLET_BUILD_WASM` | OFF | Build WebAssembly targets |
| `HD_WALLET_BUILD_TESTS` | ON | Build test suite |
| `HD_WALLET_USE_CRYPTOPP` | ON | Use Crypto++ backend |
| `HD_WALLET_USE_OPENSSL` | ON | Use OpenSSL for FIPS-approved algorithms |
| `HD_WALLET_FIPS_MODE` | OFF | Enable FIPS-compliant mode |
| `HD_WALLET_ENABLE_BITCOIN` | ON | Enable Bitcoin support |
| `HD_WALLET_ENABLE_ETHEREUM` | ON | Enable Ethereum support |
| `HD_WALLET_ENABLE_COSMOS` | ON | Enable Cosmos support |
| `HD_WALLET_ENABLE_SOLANA` | ON | Enable Solana support |
| `HD_WALLET_ENABLE_POLKADOT` | ON | Enable Polkadot support |

### Build Targets

| Target | Description | Output |
|--------|-------------|--------|
| `hd_wallet_wasm` | WASI standalone module | `.wasm` |
| `hd_wallet_wasm_js` | JavaScript ES6 module | `.js` + `.wasm` |
| `hd_wallet_wasm_inline` | Single-file (inlined WASM) | `.js` |
| `hd_wallet_wasm_npm` | NPM package | `wasm/dist/` |

### Native Build

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# Run tests
ctest --test-dir build --output-on-failure
```

### WASM Build

```bash
# Install Emscripten locally (first time only)
cd packages
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
cd ../..

# Activate Emscripten (each session)
source packages/emsdk/emsdk_env.sh

# Configure and build
emcmake cmake -B build-wasm -S . -DHD_WALLET_BUILD_WASM=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm --parallel

# Output in build-wasm/wasm/ and wasm/dist/
```

### FIPS-Compliant Build (OpenSSL)

For FIPS 140-3 compliance, the library can be built with OpenSSL 3.0.9 FIPS Provider:

```bash
# Step 1: Build OpenSSL for WASM (first time only)
cd openssl-fips
./build.sh
cd ..

# Step 2: Build with OpenSSL backend
emcmake cmake -B build-wasm -S . \
  -DHD_WALLET_BUILD_WASM=ON \
  -DHD_WALLET_USE_OPENSSL=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build-wasm --parallel
```

**Algorithm Routing with OpenSSL:**

| Algorithm | OpenSSL Mode | Default Mode |
|-----------|--------------|--------------|
| SHA-256/384/512 | OpenSSL FIPS | Crypto++ |
| HMAC-SHA256/512 | OpenSSL FIPS | Crypto++ |
| HKDF-SHA256/384 | OpenSSL FIPS | Crypto++ |
| PBKDF2-SHA512 | OpenSSL FIPS | Crypto++ |
| AES-256-GCM | OpenSSL FIPS | Crypto++ |
| ECDSA P-256/P-384 | OpenSSL FIPS | Crypto++ |
| ECDH P-256/P-384 | OpenSSL FIPS | Crypto++ |
| secp256k1 | Crypto++ | Crypto++ |
| Ed25519/X25519 | Crypto++ | Crypto++ |
| Keccak-256 | Crypto++ | Crypto++ |
| BLAKE2b/s | Crypto++ | Crypto++ |

**Initializing FIPS mode at runtime:**

```javascript
const wallet = await HDWalletWasm();

// Initialize FIPS mode (if compiled with OpenSSL)
const fipsEnabled = wallet.initFips();
console.log('FIPS mode:', fipsEnabled);

// Check if OpenSSL backend is active
console.log('OpenSSL:', wallet.isOpenSSL());
console.log('FIPS active:', wallet.isOpenSSLFips());
```

**Note:** secp256k1 (Bitcoin/Ethereum) and Ed25519 (Solana) are not FIPS-approved and always use Crypto++.

## Testing

### Native Tests

```bash
# Build and run C++ tests
cmake -B build -S . -DHD_WALLET_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

### JavaScript Tests

```bash
cd wasm
npm install
npm test

# Individual test suites
npm run test:bip39
npm run test:bip32
npm run test:vectors
```

### Test Vectors

The library is validated against official BIP-39/BIP-32 test vectors from the Trezor reference implementation.

## Security

### Key Separation

The library enforces key separation best practices:

- Signing keys and encryption keys are derived from separate paths
- Hardware wallet operations use isolated derivation paths
- Public keys can be derived without exposing private keys (neutered keys)

### Secure Memory

All sensitive cryptographic material uses secure memory handling:

```cpp
// C++ - SecureVector automatically wipes on destruction
SecureVector<uint8_t> privateKey = deriveKey(...);
// Memory is securely wiped when privateKey goes out of scope

// JavaScript - explicit wipe
const key = wallet.hdkey.fromSeed(seed);
// ... use key ...
key.wipe(); // Securely wipes memory
```

Key security features:

- **Secure wiping**: Uses volatile writes to prevent compiler optimization from removing memory clearing
- **Memory locking**: On supported platforms, sensitive memory is locked to prevent swapping to disk
- **Automatic cleanup**: SecureVector, SecureArray, and SecureString types automatically wipe on destruction

### WASI Considerations

When running in WASI environments:

- **Entropy**: The library requires entropy injection for mnemonic generation. Use `injectEntropy()` to provide cryptographically secure random bytes
- **Hardware wallets**: Require host bridge callbacks for USB/HID communication
- **Network operations**: Require WASI sockets or host bridge

The library provides runtime warnings when features are unavailable:

```javascript
if (!wallet.wasiHasFeature(WasiFeature.RANDOM)) {
  console.warn(wallet.wasiGetWarningMessage(WasiFeature.RANDOM));
  // "Random number generation requires entropy injection in WASI environment"
}
```

### Recommendations

1. **Never log or persist mnemonics/private keys** - Use the library's secure storage mechanisms
2. **Always wipe keys when done** - Call `.wipe()` on HDKey objects
3. **Use hardware wallets for high-value operations** - The abstraction layer provides consistent security
4. **Validate addresses before sending** - Use the `validateAddress()` methods
5. **Use checksummed addresses for Ethereum** - Prevents typos

## Project Structure

```
hd-wallet-wasm/
├── CMakeLists.txt           # Build configuration
├── include/hd_wallet/       # C++ headers
│   ├── bip32.h              # HD key derivation
│   ├── bip39.h              # Mnemonic generation
│   ├── coins/               # Chain implementations
│   ├── tx/                  # Transaction builders
│   └── hw/                  # Hardware wallet abstraction
├── src/                     # Implementation files
├── test/                    # C++ test suite
├── wasm/                    # JavaScript bindings
│   ├── src/index.mjs        # High-level JS API
│   ├── src/index.d.ts       # TypeScript definitions
│   └── dist/                # NPM package output
└── docs/                    # Documentation site
```

## License

Apache-2.0

```
Copyright 2024-2025 DigitalArsenal

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Related Projects

- [Crypto++](https://www.cryptopp.com/) - Cryptographic library used for all crypto operations
- [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - HD wallet specification
- [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) - Mnemonic specification
- [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) - Coin type registry
