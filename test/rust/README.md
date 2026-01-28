# HD Wallet WASM Rust Test Suite

This directory contains a comprehensive Rust test suite for the hd-wallet-wasm WASI module.

## Prerequisites

1. **Rust toolchain**: Install Rust via [rustup](https://rustup.rs/)
2. **Built WASM module**: The tests expect the WASM module at `../../build-wasm/wasm/hd-wallet.wasm`

## Building the WASM Module

Before running tests, build the WASM module from the project root:

```bash
# From project root
mkdir -p build-wasm && cd build-wasm
emcmake cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Running Tests

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_mnemonic_generate

# Run tests matching a pattern
cargo test mnemonic

# Run tests with verbose output
cargo test -- --nocapture --test-threads=1
```

## Test Coverage

The test suite covers the following functionality:

### Memory Management
- `hd_alloc` / `hd_dealloc` - Memory allocation and deallocation
- `hd_secure_wipe` - Secure memory wiping

### BIP-39 Mnemonic Operations
- `hd_mnemonic_generate` - Generate random mnemonic phrases (12, 15, 18, 21, 24 words)
- `hd_mnemonic_validate` - Validate mnemonic phrases (checksum, word validity)
- `hd_mnemonic_to_seed` - Convert mnemonic to 64-byte seed
- `hd_entropy_to_mnemonic` - Convert entropy bytes to mnemonic

### BIP-32 Key Derivation
- `hd_key_from_seed` - Create master key from seed
- `hd_key_derive_path` - Derive keys using BIP-44 paths
- `hd_key_get_private` / `hd_key_get_public` - Extract keys
- `hd_key_serialize_xprv` / `hd_key_serialize_xpub` - Serialize extended keys
- `hd_key_destroy` - Clean up key handles

### Hash Functions
- `hd_hash_sha256` - SHA-256 hash
- `hd_hash_sha512` - SHA-512 hash
- `hd_hash_keccak256` - Keccak-256 (Ethereum)
- `hd_hash_ripemd160` - RIPEMD-160
- `hd_hash_hash160` - Hash160 (RIPEMD160(SHA256))

### Key Derivation Functions
- `hd_kdf_hkdf` - HKDF-SHA256
- `hd_kdf_pbkdf2` - PBKDF2-SHA256

### Encryption
- `hd_aes_gcm_encrypt` - AES-256-GCM encryption
- `hd_aes_gcm_decrypt` - AES-256-GCM decryption with authentication

### ECDH Key Exchange
- `hd_ecdh_secp256k1` - Elliptic curve Diffie-Hellman

### Digital Signatures
- `hd_secp256k1_sign` - ECDSA signing
- `hd_secp256k1_verify` - ECDSA verification

## Test Vectors

The test suite includes official BIP-39 test vectors to ensure compatibility with other wallet implementations.

## Architecture

The tests use the `wasmtime` crate to:

1. Load the WASI module
2. Allocate memory in WASM linear memory
3. Call exported functions
4. Read results from WASM memory
5. Properly clean up allocated resources

### WasmModule Helper

The `WasmModule` struct provides convenient methods for:
- `alloc(size)` - Allocate memory
- `dealloc(ptr)` - Free memory
- `write_bytes(ptr, data)` - Write data to WASM memory
- `read_bytes(ptr, len)` - Read data from WASM memory
- `write_string(ptr, s)` - Write null-terminated string
- `read_string(ptr, max_len)` - Read null-terminated string
- `inject_entropy(data)` - Inject entropy for WASI environment

## Error Codes

Tests verify proper error handling using error codes from `types.h`:

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 2 | INVALID_ARGUMENT | Invalid argument |
| 100 | NO_ENTROPY | No entropy available (inject first) |
| 200 | INVALID_WORD | Word not in wordlist |
| 201 | INVALID_CHECKSUM | Mnemonic checksum failed |
| 403 | VERIFICATION_FAILED | Signature verification failed |

## Troubleshooting

### Module not found
```
WASM module not found at: ../../build-wasm/wasm/hd-wallet.wasm
```
Build the WASM module first (see instructions above).

### Memory errors
Ensure all allocated memory is properly deallocated after use. The test helper functions track allocations but do not automatically free them.

### Entropy errors
For cryptographic operations, entropy must be injected first. Use `setup_module()` which automatically injects 64 bytes of entropy.

## License

MIT License - See project root for details.
