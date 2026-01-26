# HD Wallet WASM - Comprehensive Hierarchical Deterministic Wallet Implementation
#
# A pure C++ implementation providing all HD wallet functionality similar to
# ShapeShift's hdwallet, compiled to WebAssembly for cross-language compatibility.
#
# Features:
#   - BIP-32/39/44/49/84 HD key derivation
#   - Multi-curve support (secp256k1, Ed25519, P-256, P-384, X25519)
#   - Multi-chain support (Bitcoin, Ethereum, Solana, Cosmos, etc.)
#   - Transaction building and signing
#   - Address generation (all formats)
#   - Hardware wallet abstraction (with WASI bridge support)
#   - FIPS-compliant mode option
#
# WASI Limitations (with warnings):
#   - USB/HID device access (requires host bridge)
#   - Network operations (requires WASI sockets or host bridge)
#   - Filesystem (requires WASI filesystem capability)
#   - Random number generation (requires entropy injection)
#
# Usage:
#   emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON
#   cmake --build build --target hd_wallet_wasm
#
# Targets:
#   hd_wallet_wasm     - WASI standalone module
#   hd_wallet_wasm_js  - JavaScript ES6 module
#   hd_wallet_wasm_npm - NPM package

cmake_minimum_required(VERSION 3.16...3.28)

# Version
set(HD_WALLET_VERSION_MAJOR 0)
set(HD_WALLET_VERSION_MINOR 1)
set(HD_WALLET_VERSION_PATCH 0)

project(HDWalletWasm
  VERSION ${HD_WALLET_VERSION_MAJOR}.${HD_WALLET_VERSION_MINOR}.${HD_WALLET_VERSION_PATCH}
  LANGUAGES CXX
  DESCRIPTION "HD Wallet WASM - Comprehensive BIP-32/39/44 implementation"
)

# Options
option(HD_WALLET_BUILD_WASM "Build WebAssembly module" OFF)
option(HD_WALLET_BUILD_TESTS "Build tests" ON)
option(HD_WALLET_USE_CRYPTOPP "Use Crypto++ for cryptographic operations" ON)
option(HD_WALLET_FIPS_MODE "Enable FIPS-compliant mode" OFF)
option(HD_WALLET_ENABLE_BITCOIN "Enable Bitcoin support" ON)
option(HD_WALLET_ENABLE_ETHEREUM "Enable Ethereum support" ON)
option(HD_WALLET_ENABLE_COSMOS "Enable Cosmos/Tendermint support" ON)
option(HD_WALLET_ENABLE_SOLANA "Enable Solana support" ON)
option(HD_WALLET_ENABLE_POLKADOT "Enable Polkadot support" ON)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# =============================================================================
# Crypto++ Dependency
# =============================================================================

if(HD_WALLET_USE_CRYPTOPP)
  include(FetchContent)
  FetchContent_Declare(
    cryptopp-cmake
    GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
    GIT_TAG        CRYPTOPP_8_9_0
  )
  set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  set(CRYPTOPP_INSTALL OFF CACHE BOOL "" FORCE)

  if(EMSCRIPTEN)
    # Disable assembly for WASM builds
    set(CRYPTOPP_DISABLE_ASM ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_DISABLE_SSSE3 ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_DISABLE_AESNI ON CACHE BOOL "" FORCE)
    set(CRYPTOPP_USE_INTERMEDIATE_OBJECTS_TARGET OFF CACHE BOOL "" FORCE)
  endif()

  FetchContent_MakeAvailable(cryptopp-cmake)
  add_definitions(-DHD_WALLET_USE_CRYPTOPP=1)
  message(STATUS "Using Crypto++ for cryptographic operations")
endif()

# =============================================================================
# Source Files
# =============================================================================

set(HD_WALLET_HEADERS
  # Core
  include/hd_wallet/config.h
  include/hd_wallet/types.h
  include/hd_wallet/error.h
  include/hd_wallet/utils.h
  include/hd_wallet/secure_memory.h
  # BIP Standards
  include/hd_wallet/bip39.h
  include/hd_wallet/bip32.h
  include/hd_wallet/bip44.h
  include/hd_wallet/slip44.h
  # Cryptography
  include/hd_wallet/curves.h
  include/hd_wallet/hash.h
  include/hd_wallet/ecdsa.h
  include/hd_wallet/eddsa.h
  include/hd_wallet/ecdh.h
  # Coins/Chains
  include/hd_wallet/coins/coin.h
  include/hd_wallet/coins/bitcoin.h
  include/hd_wallet/coins/ethereum.h
  include/hd_wallet/coins/cosmos.h
  include/hd_wallet/coins/solana.h
  include/hd_wallet/coins/polkadot.h
  # Transactions
  include/hd_wallet/tx/transaction.h
  include/hd_wallet/tx/bitcoin_tx.h
  include/hd_wallet/tx/ethereum_tx.h
  # Hardware Wallet Abstraction
  include/hd_wallet/hw/hw_wallet.h
  include/hd_wallet/hw/hw_transport.h
  include/hd_wallet/hw/keepkey.h
  include/hd_wallet/hw/trezor.h
  include/hd_wallet/hw/ledger.h
  # Keyring and Key Manager
  include/hd_wallet/keyring.h
  include/hd_wallet/key_manager.h
  # WASI
  include/hd_wallet/wasi_bridge.h
  # Aligned Binary API
  include/hd_wallet/aligned_api.h
)

set(HD_WALLET_SOURCES
  # Core
  src/utils.cpp
  src/secure_memory.cpp
  src/error.cpp
  # BIP Standards
  src/bip39.cpp
  src/bip32.cpp
  src/bip44.cpp
  # Cryptography
  src/curves.cpp
  src/hash.cpp
  src/ecdsa.cpp
  src/eddsa.cpp
  src/ecdh.cpp
  # Coins
  src/coins/coin.cpp
  src/coins/bitcoin.cpp
  src/coins/ethereum.cpp
  src/coins/cosmos.cpp
  src/coins/solana.cpp
  src/coins/polkadot.cpp
  # Transactions
  src/tx/transaction.cpp
  src/tx/bitcoin_tx.cpp
  src/tx/ethereum_tx.cpp
  # Hardware Wallet Abstraction
  src/hw/hw_wallet.cpp
  src/hw/hw_transport.cpp
  src/hw/keepkey.cpp
  src/hw/trezor.cpp
  src/hw/ledger.cpp
  # Keyring and Key Manager
  src/keyring.cpp
  src/key_manager.cpp
  # WASI Bridge
  src/wasi_bridge.cpp
  # Aligned Binary API
  src/aligned_api.cpp
)

# =============================================================================
# Static Library (for native builds and linking)
# =============================================================================

if(NOT EMSCRIPTEN)
  add_library(hd_wallet STATIC ${HD_WALLET_SOURCES})
  target_include_directories(hd_wallet
    PUBLIC
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned>
      $<INSTALL_INTERFACE:include>
  )

  if(HD_WALLET_USE_CRYPTOPP)
    target_link_libraries(hd_wallet PUBLIC cryptopp)
  endif()

  if(HD_WALLET_FIPS_MODE)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_FIPS_MODE=1)
  endif()

  # Chain-specific flags
  if(HD_WALLET_ENABLE_BITCOIN)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_BITCOIN=1)
  endif()
  if(HD_WALLET_ENABLE_ETHEREUM)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_ETHEREUM=1)
  endif()
  if(HD_WALLET_ENABLE_COSMOS)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_COSMOS=1)
  endif()
  if(HD_WALLET_ENABLE_SOLANA)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_SOLANA=1)
  endif()
  if(HD_WALLET_ENABLE_POLKADOT)
    target_compile_definitions(hd_wallet PUBLIC HD_WALLET_ENABLE_POLKADOT=1)
  endif()
endif()

# =============================================================================
# WASM Build
# =============================================================================

if(HD_WALLET_BUILD_WASM OR EMSCRIPTEN)
  message(STATUS "")
  message(STATUS "=== HD Wallet WASM Build ===")
  message(STATUS "")

  set(WASM_OUTPUT_DIR "${CMAKE_BINARY_DIR}/wasm" CACHE PATH "WASM output directory")
  set(WASM_NPM_DIR "${CMAKE_SOURCE_DIR}/wasm/dist" CACHE PATH "NPM package output directory")

  file(MAKE_DIRECTORY "${WASM_OUTPUT_DIR}")
  file(MAKE_DIRECTORY "${WASM_NPM_DIR}")

  if(EMSCRIPTEN)
    # WASM source files - core functionality only
    # Excludes files that depend on unimplemented ECDSA functions
    set(HD_WALLET_WASM_SOURCES
      src/utils.cpp
      src/secure_memory.cpp
      src/error.cpp
      src/bip39.cpp
      src/bip32.cpp
      src/bip44.cpp
      src/curves.cpp
      src/hash.cpp
      src/ecdsa.cpp
      src/eddsa.cpp
      src/ecdh.cpp
      src/wasi_bridge.cpp
    )

    # ==========================================================================
    # Exported Functions - Core API for Go/WASI integration
    # Only includes functions that are actually implemented in the minimal build
    # ==========================================================================

    set(WASM_EXPORTED_FUNCTIONS
      # ========== Memory Management ==========
      "_malloc"
      "_free"
      "_hd_alloc"
      "_hd_dealloc"
      "_hd_secure_wipe"

      # ========== Module Info ==========
      "_hd_get_version"
      "_hd_get_version_string"
      "_hd_has_cryptopp"
      "_hd_is_fips_mode"

      # ========== WASI Bridge ==========
      "_hd_wasi_has_feature"
      "_hd_wasi_get_warning"

      # ========== Entropy ==========
      "_hd_inject_entropy"
      "_hd_get_entropy_status"

      # ========== BIP-39 Mnemonic ==========
      "_hd_mnemonic_generate"
      "_hd_mnemonic_validate"
      "_hd_mnemonic_to_seed"
      "_hd_mnemonic_to_entropy"
      "_hd_entropy_to_mnemonic"
      "_hd_mnemonic_get_wordlist"
      "_hd_mnemonic_suggest_word"
      "_hd_mnemonic_check_word"

      # ========== BIP-32 HD Keys ==========
      "_hd_key_from_seed"
      "_hd_key_derive_path"
      "_hd_key_get_private"
      "_hd_key_get_public"
      "_hd_key_get_chain_code"
      "_hd_key_destroy"

      # ========== BIP-44 Paths ==========
      "_hd_path_build"
      "_hd_path_parse"

      # ========== Ed25519 ==========
      "_hd_ed25519_sign"
      "_hd_ed25519_verify"

      # ========== X25519 ECDH ==========
      "_hd_ecdh_x25519"

      # ========== Hash Functions ==========
      "_hd_hash_sha256"
      "_hd_hash_sha512"

      # ========== SLIP-10 Key Derivation ==========
      "_hd_slip10_ed25519_derive_path"
      "_hd_ed25519_pubkey_from_seed"
      "_hd_x25519_pubkey"
      "_hd_ecdh_x25519"
    )
    string(JOIN "," EXPORTED_FUNCS_STR ${WASM_EXPORTED_FUNCTIONS})

    # WASM compile options
    set(WASM_COMPILE_OPTIONS
      -DHD_WALLET_WASM=1
      -DHD_WALLET_USE_CRYPTOPP=1
    )

    if(HD_WALLET_FIPS_MODE)
      list(APPEND WASM_COMPILE_OPTIONS -DHD_WALLET_FIPS_MODE=1)
    endif()

    # Chain-specific flags
    list(APPEND WASM_COMPILE_OPTIONS
      -DHD_WALLET_ENABLE_BITCOIN=1
      -DHD_WALLET_ENABLE_ETHEREUM=1
      -DHD_WALLET_ENABLE_COSMOS=1
      -DHD_WALLET_ENABLE_SOLANA=1
      -DHD_WALLET_ENABLE_POLKADOT=1
    )

    # =========================================================================
    # Target: WASI standalone module (for Go, Rust, Python via WASI runtimes)
    # =========================================================================
    add_executable(hd_wallet_wasm ${HD_WALLET_WASM_SOURCES})
    target_include_directories(hd_wallet_wasm PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
    )
    # Build with exceptions enabled but trap on throw
    # This allows Crypto++ to compile but will abort if an exception is thrown
    # -fignore-exceptions tells the compiler to ignore try/catch blocks (no-op)
    target_compile_options(hd_wallet_wasm PRIVATE ${WASM_COMPILE_OPTIONS} -fignore-exceptions)
    target_link_libraries(hd_wallet_wasm PRIVATE cryptopp)
    set_target_properties(hd_wallet_wasm PROPERTIES
      OUTPUT_NAME "hd-wallet"
      SUFFIX ".wasm"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm PRIVATE
      -sSTANDALONE_WASM=1
      -sPURE_WASI=1
      -sWASM=1
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCS_STR}]"
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sDISABLE_EXCEPTION_CATCHING=1
      -fignore-exceptions
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: Pure WASI module (for Go/wazero, Rust/wasmtime, Python/wasmer)
    # This build disables C++ exceptions for true WASI compatibility
    # =========================================================================
    # WASI sources: minimal set without exception-using code
    set(HD_WALLET_WASI_SOURCES
      src/utils.cpp
      src/secure_memory.cpp
      src/error.cpp
      src/bip39.cpp
      src/bip32.cpp
      src/bip44.cpp
      src/curves.cpp
      src/hash.cpp
      src/ecdsa.cpp
      src/eddsa.cpp
      src/ecdh.cpp
      src/wasi_bridge.cpp
    )

    # WASI exports: core functions only (no aligned, keyring, key_manager, hw, coins, tx)
    set(WASI_EXPORTED_FUNCTIONS
      # Memory Management
      "_malloc"
      "_free"
      "_hd_alloc"
      "_hd_dealloc"
      "_hd_secure_wipe"
      # Module Info
      "_hd_get_version"
      "_hd_get_version_string"
      "_hd_has_cryptopp"
      "_hd_is_fips_mode"
      "_hd_get_supported_coins"
      "_hd_get_supported_curves"
      # WASI Bridge
      "_hd_wasi_has_feature"
      "_hd_wasi_set_callback"
      "_hd_wasi_get_warning"
      # Entropy
      "_hd_inject_entropy"
      "_hd_get_entropy_status"
      # BIP-39 Mnemonic
      "_hd_mnemonic_generate"
      "_hd_mnemonic_validate"
      "_hd_mnemonic_to_seed"
      "_hd_mnemonic_to_entropy"
      "_hd_entropy_to_mnemonic"
      "_hd_mnemonic_get_wordlist"
      "_hd_mnemonic_suggest_word"
      "_hd_mnemonic_check_word"
      # BIP-32 HD Keys
      "_hd_key_from_seed"
      "_hd_key_from_xprv"
      "_hd_key_from_xpub"
      "_hd_key_derive_path"
      "_hd_key_derive_child"
      "_hd_key_derive_hardened"
      "_hd_key_get_private"
      "_hd_key_get_public"
      "_hd_key_get_chain_code"
      "_hd_key_get_fingerprint"
      "_hd_key_get_parent_fingerprint"
      "_hd_key_get_depth"
      "_hd_key_get_child_index"
      "_hd_key_serialize_xprv"
      "_hd_key_serialize_xpub"
      "_hd_key_neutered"
      "_hd_key_is_neutered"
      "_hd_key_wipe"
      "_hd_key_clone"
      "_hd_key_destroy"
      # BIP-44/49/84 Paths
      "_hd_path_build"
      "_hd_path_parse"
      "_hd_path_to_string"
      "_hd_path_get_purpose"
      "_hd_path_get_coin_type"
      "_hd_path_get_account"
      "_hd_path_get_change"
      "_hd_path_get_index"
      # Multi-Curve Keys
      "_hd_curve_derive_secp256k1"
      "_hd_curve_derive_ed25519"
      "_hd_curve_derive_p256"
      "_hd_curve_derive_p384"
      "_hd_curve_derive_x25519"
      "_hd_curve_pubkey_from_privkey"
      "_hd_curve_compress_pubkey"
      "_hd_curve_decompress_pubkey"
      # ECDSA Signing (secp256k1)
      "_hd_secp256k1_sign"
      "_hd_secp256k1_sign_recoverable"
      "_hd_secp256k1_verify"
      "_hd_secp256k1_recover"
      # EdDSA Signing (Ed25519)
      "_hd_ed25519_sign"
      "_hd_ed25519_verify"
      # ECDSA Signing (P-256/P-384)
      "_hd_p256_sign"
      "_hd_p256_verify"
      "_hd_p384_sign"
      "_hd_p384_verify"
      # ECDH Key Exchange
      "_hd_ecdh_secp256k1"
      "_hd_ecdh_p256"
      "_hd_ecdh_p384"
      "_hd_ecdh_x25519"
      # Hash Functions
      "_hd_hash_sha256"
      "_hd_hash_sha512"
      "_hd_hash_keccak256"
      "_hd_hash_ripemd160"
      "_hd_hash_hash160"
      "_hd_hash_blake2b"
      "_hd_hash_blake2s"
      # Key Derivation
      "_hd_kdf_hkdf"
      "_hd_kdf_pbkdf2"
      "_hd_kdf_scrypt"
      # Key Validation
      "_hd_validate_private_key"
      "_hd_validate_public_key"
      "_hd_validate_path"
      "_hd_public_key_from_private"
      # Path Building
      "_hd_build_path"
      "_hd_build_signing_path"
      "_hd_build_encryption_path"
      # Encoding Utilities
      "_hd_encode_base58"
      "_hd_decode_base58"
      "_hd_encode_base58check"
      "_hd_decode_base58check"
      "_hd_encode_bech32"
      "_hd_decode_bech32"
      "_hd_encode_hex"
      "_hd_decode_hex"
      "_hd_encode_base64"
      "_hd_decode_base64"
    )
    string(JOIN "," WASI_EXPORTED_FUNCS_STR ${WASI_EXPORTED_FUNCTIONS})

    add_executable(hd_wallet_wasm_wasi ${HD_WALLET_WASI_SOURCES})
    target_include_directories(hd_wallet_wasm_wasi PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
    )
    target_compile_options(hd_wallet_wasm_wasi PRIVATE
      ${WASM_COMPILE_OPTIONS}
      -fno-exceptions
      -DHD_WALLET_NO_EXCEPTIONS=1
    )
    target_link_libraries(hd_wallet_wasm_wasi PRIVATE cryptopp)
    set_target_properties(hd_wallet_wasm_wasi PROPERTIES
      OUTPUT_NAME "hd-wallet-wasi"
      SUFFIX ".wasm"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm_wasi PRIVATE
      -sSTANDALONE_WASM=1
      -sPURE_WASI=1
      -sWASM=1
      -sERROR_ON_UNDEFINED_SYMBOLS=1
      "-sEXPORTED_FUNCTIONS=[${WASI_EXPORTED_FUNCS_STR}]"
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -fno-exceptions
      -sDISABLE_EXCEPTION_CATCHING=1
      -sDISABLE_EXCEPTION_THROWING=1
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: JavaScript ES6 module (browsers and Node.js)
    # =========================================================================
    add_executable(hd_wallet_wasm_js ${HD_WALLET_WASM_SOURCES})
    target_include_directories(hd_wallet_wasm_js PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
    )
    target_compile_options(hd_wallet_wasm_js PRIVATE ${WASM_COMPILE_OPTIONS} -fexceptions)
    target_link_libraries(hd_wallet_wasm_js PRIVATE cryptopp)
    set_target_properties(hd_wallet_wasm_js PROPERTIES
      OUTPUT_NAME "hd-wallet"
      SUFFIX ".js"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm_js PRIVATE
      -sWASM=1
      -sMODULARIZE=1
      -sEXPORT_NAME=HDWalletWasm
      -sEXPORT_ES6=1
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCS_STR}]"
      -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP32
      -sENVIRONMENT=web,node
      -sNO_EXIT_RUNTIME=1
      -fexceptions
      -sDISABLE_EXCEPTION_THROWING=0
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: Single-file version (inlined WASM)
    # =========================================================================
    add_executable(hd_wallet_wasm_inline ${HD_WALLET_WASM_SOURCES})
    target_include_directories(hd_wallet_wasm_inline PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
      ${CMAKE_CURRENT_SOURCE_DIR}/generated/aligned
    )
    target_compile_options(hd_wallet_wasm_inline PRIVATE ${WASM_COMPILE_OPTIONS} -fexceptions)
    target_link_libraries(hd_wallet_wasm_inline PRIVATE cryptopp)
    set_target_properties(hd_wallet_wasm_inline PROPERTIES
      OUTPUT_NAME "hd-wallet-inline"
      SUFFIX ".js"
      RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
    )
    target_link_options(hd_wallet_wasm_inline PRIVATE
      -sWASM=1
      -sMODULARIZE=1
      -sEXPORT_NAME=HDWalletWasm
      -sEXPORT_ES6=1
      -sSINGLE_FILE=1
      -sALLOW_MEMORY_GROWTH=1
      -sINITIAL_MEMORY=32MB
      -sMAXIMUM_MEMORY=512MB
      -sSTACK_SIZE=2MB
      -sERROR_ON_UNDEFINED_SYMBOLS=0
      -Wno-undefined
      "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCS_STR}]"
      -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8,HEAP32
      -sENVIRONMENT=web,node
      -sNO_EXIT_RUNTIME=1
      -fexceptions
      -sDISABLE_EXCEPTION_THROWING=0
      --no-entry
      $<$<CONFIG:Release>:-O3>
      $<$<CONFIG:Release>:-flto>
      $<$<CONFIG:Debug>:-g>
    )

    # =========================================================================
    # Target: NPM package
    # =========================================================================
    add_custom_target(hd_wallet_wasm_npm ALL
      DEPENDS hd_wallet_wasm_inline hd_wallet_wasm
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WASM_OUTPUT_DIR}/hd-wallet-inline.js"
        "${WASM_NPM_DIR}/hd-wallet.js"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${WASM_OUTPUT_DIR}/hd-wallet.wasm"
        "${WASM_NPM_DIR}/hd-wallet.wasm"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/wasm/src/index.d.ts"
        "${WASM_NPM_DIR}/index.d.ts"
      COMMENT "NPM package created in ${WASM_NPM_DIR}"
    )

    message(STATUS "WASM targets configured:")
    message(STATUS "  hd_wallet_wasm        - WASI standalone module (.wasm)")
    message(STATUS "  hd_wallet_wasm_js     - JavaScript ES6 module (.js + .wasm)")
    message(STATUS "  hd_wallet_wasm_inline - Single file (inlined WASM)")
    message(STATUS "  hd_wallet_wasm_npm    - NPM package")
    message(STATUS "")
    message(STATUS "WASI Bridge Features (require host callbacks):")
    message(STATUS "  - USB/HID (hardware wallets)")
    message(STATUS "  - Network (RPC, node communication)")
    message(STATUS "  - Filesystem (key storage)")
    message(STATUS "  - Entropy source (random numbers)")
    message(STATUS "")

  else()
    # Not running with Emscripten - provide instructions
    message(STATUS "")
    message(STATUS "To build WASM, use Emscripten toolchain:")
    message(STATUS "  emcmake cmake -B build -S . -DHD_WALLET_BUILD_WASM=ON")
    message(STATUS "  cmake --build build")
    message(STATUS "")
  endif()
endif()

# =============================================================================
# Tests (native only)
# =============================================================================

if(HD_WALLET_BUILD_TESTS AND NOT EMSCRIPTEN)
  enable_testing()

  # Fetch test vectors
  FetchContent_Declare(
    test_vectors
    URL https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json
    DOWNLOAD_NO_EXTRACT TRUE
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/test_data
  )
  FetchContent_MakeAvailable(test_vectors)

  add_executable(hd_wallet_tests
    test/test_main.cpp
    test/test_bip39.cpp
    test/test_bip32.cpp
    test/test_curves.cpp
    test/test_bitcoin.cpp
    test/test_ethereum.cpp
    test/test_vectors.cpp
  )
  target_link_libraries(hd_wallet_tests PRIVATE hd_wallet)
  target_include_directories(hd_wallet_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/test
  )
  target_compile_definitions(hd_wallet_tests PRIVATE
    TEST_VECTORS_PATH="${CMAKE_BINARY_DIR}/test_data"
  )

  add_test(NAME hd_wallet_tests COMMAND hd_wallet_tests)

  message(STATUS "Tests enabled: hd_wallet_tests")
endif()

# =============================================================================
# Documentation
# =============================================================================

find_package(Doxygen)
if(DOXYGEN_FOUND)
  add_custom_target(docs
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_SOURCE_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
  )
endif()

# =============================================================================
# Installation
# =============================================================================

if(NOT EMSCRIPTEN)
  include(GNUInstallDirs)

  # Install the library (without EXPORT since cryptopp is a fetched dependency)
  install(TARGETS hd_wallet
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  install(DIRECTORY include/hd_wallet
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  )

  # Note: CMake export is disabled because cryptopp is fetched via FetchContent
  # and cannot be included in the export set. Users should link to hd_wallet
  # and let CMake handle the transitive cryptopp dependency.
endif()
