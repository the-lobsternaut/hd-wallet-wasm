/**
 * @file config.h
 * @brief HD Wallet WASM Configuration
 *
 * Build-time configuration and feature flags for the HD Wallet library.
 * Detects compilation environment and sets appropriate defaults.
 */

#ifndef HD_WALLET_CONFIG_H
#define HD_WALLET_CONFIG_H

// Version information
#define HD_WALLET_VERSION_MAJOR 0
#define HD_WALLET_VERSION_MINOR 1
#define HD_WALLET_VERSION_PATCH 5
#define HD_WALLET_VERSION_STRING "0.1.5"

// =============================================================================
// Build Environment Detection
// =============================================================================

// Detect WASM/WASI environment
#if defined(__EMSCRIPTEN__) || defined(HD_WALLET_WASM)
  #define HD_WALLET_IS_WASM 1
#else
  #define HD_WALLET_IS_WASM 0
#endif

// Detect WASI (pure WASM without Emscripten JS glue)
#if defined(__wasi__) || (HD_WALLET_IS_WASM && !defined(__EMSCRIPTEN__))
  #define HD_WALLET_IS_WASI 1
#else
  #define HD_WALLET_IS_WASI 0
#endif

// =============================================================================
// Cryptographic Backend
// =============================================================================

#ifndef HD_WALLET_USE_CRYPTOPP
  #define HD_WALLET_USE_CRYPTOPP 1
#endif

// =============================================================================
// FIPS Compliance Mode
// =============================================================================

#ifndef HD_WALLET_FIPS_MODE
  #define HD_WALLET_FIPS_MODE 0
#endif

#if HD_WALLET_FIPS_MODE
  // In FIPS mode, disable non-approved algorithms
  #define HD_WALLET_ENABLE_ED25519 0  // Ed25519 not FIPS approved
  #define HD_WALLET_ENABLE_X25519 0   // X25519 not FIPS approved
#else
  #define HD_WALLET_ENABLE_ED25519 1
  #define HD_WALLET_ENABLE_X25519 1
#endif

// Always enable FIPS-approved curves
#define HD_WALLET_ENABLE_SECP256K1 1
#define HD_WALLET_ENABLE_P256 1
#define HD_WALLET_ENABLE_P384 1

// =============================================================================
// Chain/Coin Support
// =============================================================================

#ifndef HD_WALLET_ENABLE_BITCOIN
  #define HD_WALLET_ENABLE_BITCOIN 1
#endif

#ifndef HD_WALLET_ENABLE_ETHEREUM
  #define HD_WALLET_ENABLE_ETHEREUM 1
#endif

#ifndef HD_WALLET_ENABLE_COSMOS
  #define HD_WALLET_ENABLE_COSMOS 1
#endif

#ifndef HD_WALLET_ENABLE_SOLANA
  #define HD_WALLET_ENABLE_SOLANA 1
#endif

#ifndef HD_WALLET_ENABLE_POLKADOT
  #define HD_WALLET_ENABLE_POLKADOT 1
#endif

// =============================================================================
// WASI Feature Flags
// =============================================================================

/**
 * WASI capabilities that may or may not be available at runtime.
 * When running in a WASI environment, these features require host support
 * or bridge callbacks to function.
 */
namespace hd_wallet {

enum class WasiFeature {
  /// Random number generation (requires entropy injection in pure WASI)
  RANDOM = 0,

  /// Filesystem access (requires WASI filesystem capability)
  FILESYSTEM = 1,

  /// Network operations (requires WASI sockets or host bridge)
  NETWORK = 2,

  /// USB/HID device access (requires host bridge - not native WASI)
  USB_HID = 3,

  /// Clock/time access (may require WASI clock capability)
  CLOCK = 4,

  /// Environment variables
  ENVIRONMENT = 5,

  /// Total count
  COUNT = 6
};

/**
 * WASI warning codes returned when features are unavailable
 */
enum class WasiWarning {
  /// No warning - feature is available
  NONE = 0,

  /// Feature requires entropy injection first
  NEEDS_ENTROPY = 1,

  /// Feature requires host bridge callback
  NEEDS_BRIDGE = 2,

  /// Feature not available in WASI environment
  NOT_AVAILABLE_WASI = 3,

  /// Feature disabled in FIPS mode
  DISABLED_FIPS = 4,

  /// Feature requires specific WASI capability
  NEEDS_CAPABILITY = 5
};

} // namespace hd_wallet

// =============================================================================
// Memory Configuration
// =============================================================================

// Secure memory wiping (prevent compiler optimization)
#ifndef HD_WALLET_SECURE_WIPE
  #define HD_WALLET_SECURE_WIPE 1
#endif

// Maximum mnemonic word count
#define HD_WALLET_MAX_MNEMONIC_WORDS 24

// Maximum derivation path depth
#define HD_WALLET_MAX_PATH_DEPTH 10

// Key sizes
#define HD_WALLET_SEED_SIZE 64
#define HD_WALLET_CHAIN_CODE_SIZE 32
#define HD_WALLET_PRIVATE_KEY_SIZE 32
#define HD_WALLET_PUBLIC_KEY_SIZE_COMPRESSED 33
#define HD_WALLET_PUBLIC_KEY_SIZE_UNCOMPRESSED 65

// =============================================================================
// Export Macros
// =============================================================================

#if HD_WALLET_IS_WASM
  // Note: extern "C" is provided by HD_WALLET_C_EXPORT when used together
  #define HD_WALLET_EXPORT __attribute__((visibility("default")))
#else
  #ifdef _WIN32
    #ifdef HD_WALLET_BUILDING_DLL
      #define HD_WALLET_EXPORT __declspec(dllexport)
    #else
      #define HD_WALLET_EXPORT __declspec(dllimport)
    #endif
  #else
    #define HD_WALLET_EXPORT __attribute__((visibility("default")))
  #endif
#endif

// C export for WASM bindings
#ifdef __cplusplus
  #define HD_WALLET_C_EXPORT extern "C"
#else
  #define HD_WALLET_C_EXPORT
#endif

#endif // HD_WALLET_CONFIG_H
