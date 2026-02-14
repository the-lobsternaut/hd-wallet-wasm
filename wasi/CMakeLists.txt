cmake_minimum_required(VERSION 3.16)
project(hd_wallet_wasi C CXX)

# ===========================================================================
# DEPRECATED: This build uses TweetNaCl primitives without full Crypto++
# security hardening. For production use, prefer the Emscripten WASI target
# (hd_wallet_wasm_wasi) in the main CMakeLists.txt, which includes:
#   - Crypto++ with constant-time operations and audited primitives
#   - HMAC-DRBG entropy pool with backtracking resistance
#   - MaskedKey XOR-masking for private keys in memory
#   - SecureAllocator with auto-wipe on deallocation
#   - Optional OpenSSL FIPS 140-3 mode (Certificate #4282)
#
# Build the preferred target:
#   emcmake cmake -B build-wasi -S . -DHD_WALLET_BUILD_WASM=ON
#   cmake --build build-wasi --target hd_wallet_wasm_wasi
# ===========================================================================
message(WARNING
  "wasi/CMakeLists.txt builds a DEPRECATED standalone WASI module without "
  "Crypto++ security hardening or FIPS support. Use the Emscripten WASI target "
  "(hd_wallet_wasm_wasi in the main CMakeLists.txt) for production.")

# This CMakeLists builds a pure WASI module using wasi-sdk
# Designed for Go/wazero, Rust/wasmtime, Python/wasmer integration
#
# Usage:
#   mkdir build-wasi && cd build-wasi
#   cmake ../wasi -DCMAKE_TOOLCHAIN_FILE=../cmake/wasi-sdk.cmake
#   make

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# WASI-specific flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti -DHD_WALLET_NO_EXCEPTIONS")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHD_WALLET_NO_EXCEPTIONS")

# Optimization
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Parent directory for includes and sources
get_filename_component(PARENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)

# Source files - self-contained crypto implementation
set(HD_WALLET_WASI_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wasi_main.cpp
)

# Define exported functions
set(WASI_EXPORTS
  # Memory
  hd_alloc
  hd_dealloc
  hd_secure_dealloc
  hd_secure_wipe
  # Entropy
  hd_inject_entropy
  hd_get_entropy_status
  # Mnemonic
  hd_mnemonic_generate
  hd_mnemonic_validate
  hd_mnemonic_to_seed
  # SLIP-10 Ed25519
  hd_slip10_ed25519_derive_path
  hd_ed25519_pubkey_from_seed
  # Ed25519 signing
  hd_ed25519_sign
  hd_ed25519_verify
  # X25519
  hd_x25519_pubkey
  hd_ecdh_x25519
  # Version
  hd_get_version
)

# Build export list for linker
set(WASI_EXPORT_FLAGS "")
foreach(func ${WASI_EXPORTS})
  list(APPEND WASI_EXPORT_FLAGS "-Wl,--export=${func}")
endforeach()

add_executable(hd_wallet_wasi ${HD_WALLET_WASI_SOURCES})

target_include_directories(hd_wallet_wasi PRIVATE
  ${PARENT_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# WASI linker flags - build as reactor (library) not command
target_link_options(hd_wallet_wasi PRIVATE
  -mexec-model=reactor
  -Wl,--export=malloc
  -Wl,--export=free
  ${WASI_EXPORT_FLAGS}
)

# Output name
set_target_properties(hd_wallet_wasi PROPERTIES
  OUTPUT_NAME "hd-wallet"
  SUFFIX ".wasm"
)

message(STATUS "Building pure WASI module for Go/wazero integration")
message(STATUS "Exported functions: ${WASI_EXPORTS}")
