# hd-wallet-wasm — Tasks

Derived from a full audit of the codebase, WASM exports, JS wrappers, and test suite (v1.3.0, 180+ tests passing).

---

## HIGH — Bugs

### 1. ~~P-256 ECDH returns incorrect shared secrets~~ FIXED
**Files changed**: `src/wasm_exports.cpp`
**Fix**: Replaced `CryptoPP::ECDH<ECP>::Domain::Agree()` with manual `DecodePoint` + `ScalarMultiply` pattern (same as working secp256k1 ECDH). Accepts both compressed and uncompressed public keys.
**Tests**: Added mutual agreement test (Alice+Bob) in `wasm/test/test_low_edge_cases.mjs`.
**Note**: Requires WASM rebuild to take effect.

### 2. ~~P-384 ECDH returns incorrect shared secrets~~ FIXED
**Files changed**: `src/wasm_exports.cpp`
**Fix**: Same approach as P-256 — manual `DecodePoint` + `ScalarMultiply` for P-384 curve.
**Tests**: Added mutual agreement test (Alice+Bob) in `wasm/test/test_low_edge_cases.mjs`.
**Note**: Requires WASM rebuild to take effect.

### 3. ~~`deriveBatch(master, startIndex, 0)` returns garbage data~~ FIXED
**Files changed**: `src/aligned_api.cpp`, `wasm/src/aligned.mjs`
**Fix**: C++ side: reordered validation to return 0 when count=0 before checking results buffer. JS side: added early return `if (count === 0) return [];`.
**Tests**: Added count=0 test in `wasm/test/test_low_edge_cases.mjs`.
**Note**: C++ fix requires WASM rebuild; JS guard works immediately.

---

## MEDIUM — Missing WASM Exports

### 4. ~~`_hd_curve_compress_pubkey` not in WASM_EXPORTED_FUNCTIONS~~ FIXED
**Files changed**: `CMakeLists.txt`
**Fix**: Added `"_hd_curve_compress_pubkey"` to `WASM_EXPORTED_FUNCTIONS`.
**Note**: Requires WASM rebuild to take effect.

### 5. ~~Encoding functions dead WASM paths~~ FIXED
**Files changed**: `wasm/src/index.mjs`
**Fix**: Removed `getWasmFunction` calls from `encodeHex`, `decodeHex`, `encodeBase64`, `decodeBase64`; now call JS fallback implementations directly. Smaller, simpler code.

### 6. ~~Keyring `requireWasmFunction` error messages~~ FIXED
**Files changed**: `wasm/src/index.mjs`
**Fix**: Added explicit `ErrorCode.NOT_SUPPORTED, 'Keyring is not available in the WASM build'` to the three keyring `requireWasmFunction` calls for clear error messages.

---

## LOW — Test Coverage Gaps

### 7. ~~Transaction tests are minimal~~ FIXED
**Files changed**: `wasm/test/test_transactions.mjs`
**Fix**: Added 5 new tests: BTC legacy P2PKH, ETH legacy via `create()`, multi-input BTC (2 in, 2 out) with fee validation, BTC serialize→parse→re-serialize round-trip, ETH EIP-1559 round-trip.

### 8. ~~Non-English mnemonic wordlists not compiled into WASM~~ FIXED
**Status**: FIXED (design decision implemented as English-only)
**Files**: `include/hd_wallet/bip39.h`, `src/bip39.cpp`, `wasm/src/index.mjs`
**Fix**: Enforced English-only support across API layers.
- `bip39.cpp` now treats non-English as unsupported and returns `NOT_SUPPORTED`.
- `index.mjs` getWordlist now throws `NOT_SUPPORTED` for unsupported locales.
- Documentation updated to explicitly reflect English-only behavior.

### 9. WASI build has no transaction support
**Status**: FIXED
**Files**: `CMakeLists.txt`
**Fix**: Added tx sources and exported tx symbols to the pure WASI target.
- `src/tx/transaction.cpp`, `src/tx/bitcoin_tx.cpp`, `src/tx/ethereum_tx.cpp` now build into WASI.
- Added Bitcoin and Ethereum tx exports (`_hd_btc_tx_*`, `_hd_eth_tx_*`) to `WASI_EXPORTED_FUNCTIONS`.

---

## CLEANUP — Documentation & Consistency

### 10. ~~VERIFICATION_TASKS.md S2 finding is stale~~ N/A
VERIFICATION_TASKS.md no longer exists.

### 11. ~~`_hd_wasi_get_warning_message` dead code~~ FIXED
**Files changed**: `wasm/src/index.mjs`
**Fix**: Replaced `getWasmFunction` call with direct JS return: `'WASI warning API unavailable in this build'`.

### 12. ~~Hardware wallet dead code~~ FIXED
**Files changed**: `wasm/src/index.mjs`
**Fix**: Replaced per-method `requireWasmFunction`/`getWasmFunction` calls with a single `this.isAvailable()` guard at the top of `connect()`. Device methods call `wasm._hd_hw_*` directly.
