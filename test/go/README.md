# HD Wallet WASM Go Test Suite

Comprehensive Go test suite for the hd-wallet-wasm WASI module using [wazero](https://github.com/tetratelabs/wazero) - a pure Go WebAssembly runtime.

## Prerequisites

- Go 1.21 or later
- The WASM module built at `../../build-wasm/wasm/hd-wallet.wasm`

## Building the WASM Module

Before running tests, ensure the WASM module is built:

```bash
cd ../..
mkdir -p build-wasm && cd build-wasm
emcmake cmake .. -DCMAKE_BUILD_TYPE=Release
make hd_wallet_wasm
```

## Running Tests

```bash
# Run all tests
go test -v ./...

# Run specific tests
go test -v -run TestMnemonicGeneration
go test -v -run TestAESGCM
go test -v -run TestFullWorkflow

# Run with race detector
go test -v -race ./...

# Run benchmarks
go test -bench=. -benchmem
```

## Test Coverage

The test suite covers:

### Memory Management
- `hd_alloc` / `hd_dealloc` - Memory allocation and deallocation
- Read/write operations to WASM memory

### Entropy Management
- `hd_inject_entropy` - Inject entropy for cryptographic operations
- `hd_get_entropy_status` - Check entropy availability

### BIP-39 Mnemonic Operations
- `hd_mnemonic_generate` - Generate 12/15/18/21/24 word mnemonics
- `hd_mnemonic_validate` - Validate mnemonic phrases
- `hd_mnemonic_to_seed` - Convert mnemonic to 64-byte seed

### BIP-32 HD Key Derivation
- `hd_key_from_seed` - Create master key from seed
- `hd_key_derive_path` - Derive child keys using BIP-44 paths
- `hd_key_get_private` / `hd_key_get_public` - Extract key bytes
- `hd_key_destroy` - Clean up key handles

### Cryptographic Hash Functions
- `hd_hash_sha256` - SHA-256 hashing

### AES-GCM Encryption
- `hd_aes_gcm_encrypt` - Authenticated encryption
- `hd_aes_gcm_decrypt` - Authenticated decryption
- Tamper detection tests

## Test Structure

```
test/go/
  go.mod              # Go module definition
  hd_wallet_test.go   # Test implementation
  README.md           # This file
```

## HDWallet Test Helper

The test file includes an `HDWallet` struct that wraps the WASM module and provides convenient Go methods:

```go
hd := NewHDWallet(t)
defer hd.Close()

// Inject entropy
hd.InjectEntropy(entropy)

// Generate mnemonic
mnemonic, err := hd.GenerateMnemonic(24, 0) // 24 words, English

// Validate mnemonic
result, err := hd.ValidateMnemonic(mnemonic, 0)

// Convert to seed
seed, err := hd.MnemonicToSeed(mnemonic, "passphrase")

// Derive keys
keyHandle, err := hd.KeyFromSeed(seed, 0) // secp256k1
derivedKey, err := hd.KeyDerivePath(keyHandle, "m/44'/60'/0'/0/0")

// Hash data
hash, err := hd.HashSHA256(data)

// Encrypt/decrypt
ciphertext, tag, err := hd.AesGcmEncrypt(key, plaintext, iv, aad)
plaintext, err := hd.AesGcmDecrypt(key, ciphertext, iv, aad, tag)
```

## BIP-39 Test Vectors

The tests use standard BIP-39 test vectors from https://github.com/trezor/python-mnemonic:

```
Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
Passphrase: TREZOR
Seed: c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
```

## Error Handling

The WASM module returns error codes for failed operations:

| Code | Meaning |
|------|---------|
| 0 | Success (OK) |
| -2 | Invalid argument |
| -3 | Unsupported (e.g., non-English wordlist) |
| -4 | Buffer too small |
| -100 | No entropy available |
| -200 | Invalid word in mnemonic |
| -201 | Invalid checksum |
| -202 | Invalid word count |
| -301 | Invalid path format |
| -302 | Non-hardened derivation for Ed25519 |

## Wazero Features Used

- Pure Go runtime (no CGO required)
- WASI preview 1 support
- Memory import/export
- Function call interface
- Module lifecycle management

## Troubleshooting

### WASM file not found
Ensure the WASM module is built and located at `../../build-wasm/wasm/hd-wallet.wasm`

### Memory errors
The test suite includes proper memory management. If you encounter issues:
1. Check that all allocated pointers are properly freed
2. Ensure buffer sizes are correct
3. Verify that strings are null-terminated

### Important: Memory Handling with Wazero
When reading data from WASM memory using wazero, **always make a copy** of the returned byte slice. The `memory.Read()` function returns a slice that references internal wazero memory, which can be overwritten by subsequent WASM operations.

```go
// WRONG - data may be corrupted by later operations
data, _ := hd.memory.Read(ptr, size)
return data

// CORRECT - make a copy immediately
data, _ := hd.memory.Read(ptr, size)
result := make([]byte, size)
copy(result, data)
return result
```

### Function not found
If a function is not found, verify it's exported in the WASM module. Check the CMakeLists.txt for the list of exported functions.

## License

This test suite is part of the hd-wallet-wasm project.
