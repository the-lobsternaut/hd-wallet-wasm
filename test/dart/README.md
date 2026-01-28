# HD Wallet WASM - Dart Test Suite

Comprehensive Dart test suite for the hd-wallet-wasm WASI module.

## Overview

This test suite validates the hd-wallet-wasm WebAssembly module from Dart using the `wasm_run` package (which uses wasmtime/wasmi under the hood). It tests:

- **Memory Management**: WASM memory allocation and deallocation
- **BIP-39 Mnemonic Generation**: 12 and 24-word phrase generation
- **BIP-39 Mnemonic Validation**: Checksum and wordlist verification
- **BIP-39 Seed Derivation**: Mnemonic to 64-byte seed conversion with optional passphrase
- **BIP-32 Key Derivation**: Master key creation and path-based derivation
- **Hash Functions**: SHA-256 computation
- **AES-GCM Encryption**: Authenticated encryption/decryption

## Prerequisites

1. **Dart SDK** (>= 3.0.0)
2. **Built WASM module** at `../../build-wasm/wasm/hd-wallet.wasm`

### Building the WASM Module

If you haven't built the WASM module yet:

```bash
# From the repository root
source packages/emsdk/emsdk_env.sh  # Activate Emscripten
emcmake cmake -B build-wasm -S . -DHD_WALLET_BUILD_WASM=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm
```

The WASM file will be at `build-wasm/wasm/hd-wallet.wasm`.

## Installation

```bash
cd test/dart
dart pub get
```

## Running Tests

```bash
# Run all tests
dart test

# Run with verbose output
dart test --reporter expanded

# Run specific test group
dart test --name "Mnemonic Generation"

# Run a single test
dart test --name "generates 24-word mnemonic"
```

## Test Structure

```
test/dart/
├── pubspec.yaml           # Dependencies
├── README.md              # This file
└── test/
    └── hd_wallet_test.dart  # Main test file
```

## API Coverage

### WASM Functions Tested

| Function | Description |
|----------|-------------|
| `hd_alloc` | Allocate memory in WASM |
| `hd_dealloc` | Free allocated memory |
| `hd_mnemonic_generate` | Generate BIP-39 mnemonic |
| `hd_mnemonic_validate` | Validate BIP-39 mnemonic |
| `hd_mnemonic_to_seed` | Convert mnemonic to 64-byte seed |
| `hd_key_from_seed` | Create master key from seed |
| `hd_key_derive_path` | Derive key at BIP-32/44 path |
| `hd_key_get_private` | Get 32-byte private key |
| `hd_key_get_public` | Get 33-byte compressed public key |
| `hd_key_destroy` | Clean up key handle |
| `hd_hash_sha256` | Compute SHA-256 hash |
| `hd_aes_gcm_encrypt` | AES-256-GCM authenticated encryption |
| `hd_aes_gcm_decrypt` | AES-256-GCM authenticated decryption |
| `hd_inject_entropy` | Inject entropy for WASI environment |

### Test Groups

1. **Memory Management**
   - Allocation and deallocation
   - Read/write bytes
   - Read/write strings

2. **Mnemonic Generation (BIP-39)**
   - 12-word generation
   - 24-word generation
   - Uniqueness verification

3. **Mnemonic Validation (BIP-39)**
   - Valid 12-word and 24-word mnemonics
   - Invalid word detection
   - Invalid checksum detection
   - Generated mnemonic validation

4. **Mnemonic to Seed**
   - 64-byte seed generation
   - Passphrase support
   - Deterministic output

5. **Key Derivation (BIP-32)**
   - Master key creation
   - Private/public key extraction
   - BIP-44 path derivation
   - Deterministic derivation

6. **Hash Functions (SHA-256)**
   - Empty string hash
   - Known test vectors
   - Comparison with Dart crypto library

7. **AES-GCM Encryption**
   - Empty plaintext
   - Simple messages
   - Additional authenticated data (AAD)
   - Wrong key rejection
   - Tampered ciphertext rejection
   - Wrong AAD rejection
   - Large data handling

8. **Integration Tests**
   - Full wallet flow (generate -> validate -> derive)
   - Encryption with derived keys

## Memory Management

The test suite properly manages WASM memory:

```dart
// Always allocate before use
final ptr = wallet.alloc(size);

// Write data
wallet.writeBytes(ptr, data);

// Use the data...

// Always deallocate when done
wallet.dealloc(ptr);
```

Key handles must also be cleaned up:

```dart
final keyHandle = wallet.keyFromSeed(seed);
// Use the key...
wallet.destroyKey(keyHandle);
```

## Troubleshooting

### WASM Module Not Found

```
StateError: WASM module not found at ../../build-wasm/wasm/hd-wallet.wasm
```

Build the WASM module first (see Prerequisites).

### WASI Not Supported

The `wasm_run` package supports WASI through wasmtime_wasi or wasmi_wasi depending on the target platform. WASI imports should be handled automatically.

### Entropy Issues

In WASI environments, random number generation requires entropy injection. The test suite automatically injects entropy on initialization.

## Dependencies

- `wasm_run: ^0.2.0` - WASI runtime for Dart (uses wasmtime/wasmi)
- `test: ^1.24.0` - Dart test framework
- `convert: ^3.1.1` - Encoding utilities
- `crypto: ^3.0.3` - For SHA-256 verification

## License

This test suite is part of the hd-wallet-wasm project, licensed under Apache-2.0.
