# HD Wallet WASM - Python Test Suite

This directory contains a comprehensive Python test suite for the hd-wallet-wasm WASI module using wasmtime-py.

## Prerequisites

- Python 3.10 or later
- The WASM module built at `../../build-wasm/wasm/hd-wallet.wasm`

## Installation

1. Create a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
.\venv\Scripts\activate   # On Windows
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Running Tests

Run all tests:

```bash
pytest test_hd_wallet.py -v
```

Run specific test classes:

```bash
# Mnemonic tests only
pytest test_hd_wallet.py::TestMnemonic -v

# Key derivation tests only
pytest test_hd_wallet.py::TestKeyDerivation -v

# Hash function tests only
pytest test_hd_wallet.py::TestHashFunctions -v

# AES-GCM tests only
pytest test_hd_wallet.py::TestAESGCM -v

# Integration tests only
pytest test_hd_wallet.py::TestIntegration -v
```

Run with verbose output and show print statements:

```bash
pytest test_hd_wallet.py -v -s
```

Run a specific test:

```bash
pytest test_hd_wallet.py::TestMnemonic::test_generate_24_word_mnemonic -v
```

## Test Coverage

The test suite covers:

### BIP-39 Mnemonic Functions
- Mnemonic generation (12, 15, 18, 21, 24 words)
- Mnemonic validation
- Invalid checksum detection
- Invalid word detection
- Mnemonic to seed conversion (with/without passphrase)
- BIP-39 test vector verification

### BIP-32 Key Derivation
- Master key creation from seed
- Key derivation paths (BIP-44 style)
- Hardened and non-hardened derivation
- Public key extraction (compressed format)
- Private key extraction
- Key serialization (xprv/xpub format)
- Key depth and fingerprint

### Hash Functions
- SHA-256
- SHA-512
- Keccak-256 (Ethereum hash)
- RIPEMD-160
- Verification against Python hashlib

### AES-GCM Encryption
- Encrypt/decrypt roundtrip
- Additional Authenticated Data (AAD)
- Authentication tag verification
- Tamper detection
- Wrong key detection

### Memory Management
- Allocation/deallocation
- Memory isolation verification

### Integration Tests
- Full wallet creation flow
- Hash chains
- Key encryption workflows

## API Reference

The `HDWalletWasm` class provides Python wrappers for the WASI module exports:

### Memory Management
- `alloc(size)` - Allocate memory in WASM
- `dealloc(ptr)` - Free memory in WASM
- `write_bytes(ptr, data)` - Write bytes to WASM memory
- `read_bytes(ptr, length)` - Read bytes from WASM memory

### Mnemonic Functions
- `mnemonic_generate(word_count, language)` - Generate mnemonic
- `mnemonic_validate(mnemonic, language)` - Validate mnemonic
- `mnemonic_to_seed(mnemonic, passphrase)` - Convert to seed

### Key Functions
- `key_from_seed(seed, curve)` - Create master key
- `key_derive_path(key_handle, path)` - Derive at path
- `key_get_public(key_handle)` - Get public key
- `key_get_private(key_handle)` - Get private key
- `key_serialize_xprv(key_handle)` - Serialize to xprv
- `key_serialize_xpub(key_handle)` - Serialize to xpub
- `key_destroy(key_handle)` - Free key

### Hash Functions
- `hash_sha256(data)` - SHA-256 hash
- `hash_sha512(data)` - SHA-512 hash
- `hash_keccak256(data)` - Keccak-256 hash
- `hash_ripemd160(data)` - RIPEMD-160 hash

### Encryption Functions
- `aes_gcm_encrypt(key, plaintext, iv, aad)` - Encrypt
- `aes_gcm_decrypt(key, ciphertext, iv, tag, aad)` - Decrypt

## Error Codes

The test suite uses error codes from the library:

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | Success |
| 2 | INVALID_ARGUMENT | Invalid argument |
| 100 | NO_ENTROPY | No entropy available |
| 200 | INVALID_WORD | Invalid mnemonic word |
| 201 | INVALID_CHECKSUM | Invalid checksum |
| 202 | INVALID_MNEMONIC_LENGTH | Invalid word count |
| 300 | INVALID_SEED | Invalid seed |
| 301 | INVALID_PATH | Invalid derivation path |
| 403 | VERIFICATION_FAILED | Signature/auth verification failed |

## Troubleshooting

### WASM module not found

Make sure you've built the WASM module:

```bash
cd ../..
# Follow build instructions in main README
```

The test expects the module at `../../build-wasm/wasm/hd-wallet.wasm`

### wasmtime import errors

Ensure you have a recent version of wasmtime-py:

```bash
pip install --upgrade wasmtime
```

### Test failures

Some tests may fail if:
- The WASM module was built without certain features
- Entropy injection is required but not working
- Memory limits are exceeded

Check the error messages for specific details.

## Contributing

When adding new tests:

1. Use descriptive test names that explain what's being tested
2. Include both positive and negative test cases
3. Clean up resources (destroy keys, deallocate memory)
4. Add docstrings explaining the test purpose
5. Use the existing fixtures (`wallet`) for WASM module access
