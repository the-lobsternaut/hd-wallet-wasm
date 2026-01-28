# OpenSSL FIPS WebAssembly Build

This directory contains the build infrastructure for compiling OpenSSL 3.0.9 with FIPS Provider to WebAssembly using Emscripten.

## Overview

OpenSSL 3.0.9 is specifically chosen because it has FIPS 140-3 validation (Certificate #4282). This allows the hd-wallet-wasm library to use FIPS-approved cryptographic algorithms when required.

## Quick Start

```bash
# Build OpenSSL for WASM
./build.sh

# This produces:
# - dist/lib/libcrypto.a      OpenSSL crypto library (WASM)
# - dist/lib/fips.a           FIPS provider module
# - dist/include/openssl/     OpenSSL headers
```

## Prerequisites

- **Emscripten SDK**: The build script will look for Emscripten in:
  1. `../build-wasm/_deps/emsdk-src/` (installed by CMake FetchContent)
  2. System PATH (`emcc` command)

- **Perl**: Required for OpenSSL's configure script

## Build Process

The `build.sh` script performs the following steps:

1. **Download OpenSSL 3.0.9** from the official GitHub releases
2. **Configure** with Emscripten-compatible flags:
   - `no-asm` - Disable assembly (not compatible with WASM)
   - `no-threads` - Disable pthread (simplifies WASM)
   - `no-shared` - Static libraries only
   - `enable-fips` - Build FIPS provider
3. **Build** using `emmake make`
4. **Install** libraries and headers to `dist/`

## Configuration Flags

The following flags are used for the WASM build:

| Flag | Reason |
|------|--------|
| `no-asm` | WebAssembly cannot use x86/ARM assembly |
| `no-threads` | Simplifies WASM build (no pthread) |
| `no-shared` | Static linking only (no .so/.dll) |
| `no-dso` | No dynamic shared objects |
| `no-engine` | Deprecated in OpenSSL 3.x |
| `no-async` | Avoids pthread requirements |
| `no-sock` | No socket operations |
| `enable-fips` | Build FIPS provider module |

## Integration with hd-wallet-wasm

After building OpenSSL, configure the main project with:

```bash
emcmake cmake -B build-wasm -S .. \
  -DHD_WALLET_BUILD_WASM=ON \
  -DHD_WALLET_USE_OPENSSL=ON

cmake --build build-wasm
```

## Algorithm Routing

When built with OpenSSL, the following algorithms are routed through OpenSSL's EVP API:

**FIPS-approved (via OpenSSL):**
- SHA-256, SHA-384, SHA-512
- HMAC-SHA256, HMAC-SHA512
- HKDF-SHA256, HKDF-SHA384
- PBKDF2-SHA512
- AES-256-GCM
- ECDSA P-256, P-384
- ECDH P-256, P-384

**Non-FIPS (always Crypto++):**
- secp256k1 (Bitcoin/Ethereum curve)
- Ed25519 (Solana, Cosmos)
- X25519 (key exchange)
- Keccak-256 (Ethereum hash)
- BLAKE2b, BLAKE2s
- RIPEMD-160
- scrypt

## File Structure

```
openssl-fips/
├── build.sh          Build script
├── README.md         This file
├── build/            Build artifacts (created by build.sh)
│   └── openssl-3.0.9/
└── dist/             Output (created by build.sh)
    ├── lib/
    │   ├── libcrypto.a
    │   └── fips.a
    └── include/
        └── openssl/
```

## FIPS 140-3 Validation

OpenSSL 3.0.9 FIPS Provider:
- **Certificate Number**: #4282
- **Validation Date**: 2023
- **Security Level**: Level 1
- **Algorithms**: See [NIST CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282)

## Troubleshooting

### Build fails with "emcc not found"
1. Ensure Emscripten is installed
2. Run the main CMake build first to install Emscripten via FetchContent
3. Or activate Emscripten manually: `source /path/to/emsdk/emsdk_env.sh`

### "Perl not found"
OpenSSL's configure script requires Perl. Install with:
- macOS: `brew install perl`
- Ubuntu: `apt install perl`
- Windows: Use Strawberry Perl

### libcrypto.a is too large
The default build includes all algorithms. For smaller size:
- Add `no-ssl3 no-tls1` to disable older protocols
- Add `no-des no-rc4` to disable legacy ciphers

## License

OpenSSL is dual-licensed under the Apache License 2.0 and the OpenSSL License.
See https://www.openssl.org/source/license.html
