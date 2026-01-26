# HD Wallet WASM

A comprehensive hierarchical deterministic (HD) wallet implementation in pure C++, compiled to WebAssembly for cross-language compatibility.

## Features

- **BIP Standards Compliance**
  - BIP-32: Hierarchical deterministic key derivation
  - BIP-39: Mnemonic code generation and validation
  - BIP-44/49/84: Multi-account hierarchy and derivation paths
  - SLIP-44: Standard coin type registry

- **Multi-Curve Cryptography**
  - secp256k1 (Bitcoin, Ethereum)
  - Ed25519 (Solana, Polkadot)
  - NIST P-256 (secp256r1)
  - NIST P-384 (secp384r1)
  - X25519 (key exchange)

- **Multi-Chain Support**
  - Bitcoin (P2PKH, P2SH, P2WPKH, P2WSH, Taproot)
  - Ethereum and EVM chains
  - Solana
  - Cosmos/Tendermint
  - Polkadot/Substrate
  - 50+ coin types via SLIP-44

- **Advanced Capabilities**
  - Transaction building and signing
  - Hardware wallet abstraction (Trezor, Ledger, KeepKey)
  - WASI bridge for host callbacks
  - Secure memory wiping
  - Optional FIPS-compliant mode

## Installation

### NPM

```bash
npm install @digitalarsenal/hd-wallet-wasm
```

### From Source

Prerequisites:
- CMake 3.16+
- C++17 compiler
- Emscripten SDK (for WASM builds)

```bash
# Native build
cmake -B build -S .
cmake --build build

# WASM build
emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON
cmake --build build
```

## Usage

### JavaScript/TypeScript

```javascript
import HDWalletWasm from '@digitalarsenal/hd-wallet-wasm';

const wallet = await HDWalletWasm();

// Generate mnemonic
const mnemonic = wallet.ccall('hd_mnemonic_generate', 'string', ['number'], [24]);

// Derive seed
const seed = wallet.ccall('hd_mnemonic_to_seed', 'number', ['string', 'string'], [mnemonic, '']);

// Create HD key from seed
const key = wallet.ccall('hd_key_from_seed', 'number', ['number', 'number'], [seed, 64]);

// Derive Bitcoin address
const path = "m/44'/0'/0'/0/0";
const childKey = wallet.ccall('hd_key_derive_path', 'number', ['number', 'string'], [key, path]);
const address = wallet.ccall('hd_btc_get_address_p2wpkh', 'string', ['number'], [childKey]);
```

### WASI (Go, Rust, Python)

The standalone WASM module can be loaded via any WASI-compatible runtime:

```go
// Go with wazero
import "github.com/tetratelabs/wazero"

ctx := context.Background()
r := wazero.NewRuntime(ctx)
wasm, _ := os.ReadFile("hd-wallet.wasm")
mod, _ := r.InstantiateWithConfig(ctx, wasm, wazero.NewModuleConfig())

// Call exported functions
result, _ := mod.ExportedFunction("hd_mnemonic_generate").Call(ctx, 24)
```

## Build Targets

| Target | Description | Output |
|--------|-------------|--------|
| `hd_wallet_wasm` | WASI standalone module | `.wasm` |
| `hd_wallet_wasm_js` | JavaScript ES6 module | `.js` + `.wasm` |
| `hd_wallet_wasm_inline` | Single-file (inlined WASM) | `.js` |
| `hd_wallet_wasm_npm` | NPM package | `wasm/dist/` |

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `HD_WALLET_BUILD_WASM` | OFF | Build WebAssembly targets |
| `HD_WALLET_BUILD_TESTS` | ON | Build test suite |
| `HD_WALLET_USE_CRYPTOPP` | ON | Use Crypto++ backend |
| `HD_WALLET_FIPS_MODE` | OFF | Enable FIPS-compliant mode |
| `HD_WALLET_ENABLE_BITCOIN` | ON | Enable Bitcoin support |
| `HD_WALLET_ENABLE_ETHEREUM` | ON | Enable Ethereum support |
| `HD_WALLET_ENABLE_COSMOS` | ON | Enable Cosmos support |
| `HD_WALLET_ENABLE_SOLANA` | ON | Enable Solana support |
| `HD_WALLET_ENABLE_POLKADOT` | ON | Enable Polkadot support |

## WASI Bridge

The library includes a WASI bridge system for host integration:

- **Entropy injection** - Required for secure random number generation
- **USB/HID communication** - Hardware wallet support
- **Network operations** - RPC and blockchain communication
- **Filesystem access** - Key storage and recovery

Features are detected at runtime with appropriate warnings when unavailable.

## API Overview

The library exports 200+ functions covering:

- Memory management (`hd_alloc`, `hd_dealloc`, `hd_secure_wipe`)
- BIP-39 mnemonics (`hd_mnemonic_generate`, `hd_mnemonic_to_seed`)
- BIP-32 HD keys (`hd_key_from_seed`, `hd_key_derive_path`)
- Multi-curve operations (`hd_curve_derive_*`, `hd_secp256k1_sign`, `hd_ed25519_sign`)
- Hash functions (`hd_hash_sha256`, `hd_hash_keccak256`, `hd_hash_blake2b`)
- Chain-specific addresses and transactions (`hd_btc_*`, `hd_eth_*`, `hd_sol_*`)
- Hardware wallet abstraction (`hd_hw_*`)
- Keyring management (`hd_keyring_*`)

## Project Structure

```
hd-wallet-wasm/
├── CMakeLists.txt           # Build configuration
├── include/hd_wallet/       # C++ headers
│   ├── bip32.h              # HD key derivation
│   ├── bip39.h              # Mnemonic generation
│   ├── curves.h             # Multi-curve support
│   ├── coins/               # Chain implementations
│   ├── tx/                  # Transaction builders
│   └── hw/                  # Hardware wallet abstraction
├── src/                     # Implementation files
├── test/                    # Test suite
└── wasm/                    # JavaScript bindings
    └── dist/                # NPM package output
```

## Related Projects

- [cryptopp-wasm](https://github.com/ArtFlag/cryptopp-wasm) - Crypto++ WebAssembly build
- [spacedatastandards.org](https://spacedatastandards.org) - Space data standards
- [flatbuffers](https://google.github.io/flatbuffers/) - Efficient serialization

## License

MIT License

## Contributing

Contributions welcome. Please open an issue or submit a pull request.
