/**
 * @file types.h
 * @brief Common Types for HD Wallet
 *
 * Core type definitions used throughout the HD Wallet library.
 */

#ifndef HD_WALLET_TYPES_H
#define HD_WALLET_TYPES_H

#include "config.h"

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>

namespace hd_wallet {

// =============================================================================
// Basic Types
// =============================================================================

/// 32-byte array (private keys, chain codes, etc.)
using Bytes32 = std::array<uint8_t, 32>;

/// 33-byte array (compressed public keys)
using Bytes33 = std::array<uint8_t, 33>;

/// 64-byte array (seeds, uncompressed public keys without prefix)
using Bytes64 = std::array<uint8_t, 64>;

/// 65-byte array (uncompressed public keys with prefix)
using Bytes65 = std::array<uint8_t, 65>;

/// Variable-length byte vector
using ByteVector = std::vector<uint8_t>;

// =============================================================================
// Error Codes
// =============================================================================

/**
 * Error codes returned by HD Wallet functions
 */
enum class Error : int32_t {
  /// Success
  OK = 0,

  // General errors (1-99)
  /// Unknown error
  UNKNOWN = 1,
  /// Invalid argument
  INVALID_ARGUMENT = 2,
  /// Operation not supported
  NOT_SUPPORTED = 3,
  /// Out of memory
  OUT_OF_MEMORY = 4,
  /// Internal error
  INTERNAL = 5,

  // Entropy errors (100-199)
  /// No entropy available (WASI)
  NO_ENTROPY = 100,
  /// Insufficient entropy
  INSUFFICIENT_ENTROPY = 101,

  // BIP-39 errors (200-299)
  /// Invalid mnemonic word
  INVALID_WORD = 200,
  /// Invalid mnemonic checksum
  INVALID_CHECKSUM = 201,
  /// Invalid mnemonic length
  INVALID_MNEMONIC_LENGTH = 202,
  /// Invalid entropy length
  INVALID_ENTROPY_LENGTH = 203,

  // BIP-32 errors (300-399)
  /// Invalid seed length
  INVALID_SEED = 300,
  /// Invalid derivation path
  INVALID_PATH = 301,
  /// Invalid child index (>= 2^31 for non-hardened)
  INVALID_CHILD_INDEX = 302,
  /// Cannot derive public key from public key (hardened)
  HARDENED_FROM_PUBLIC = 303,
  /// Invalid extended key format
  INVALID_EXTENDED_KEY = 304,

  // Cryptographic errors (400-499)
  /// Invalid private key
  INVALID_PRIVATE_KEY = 400,
  /// Invalid public key
  INVALID_PUBLIC_KEY = 401,
  /// Invalid signature
  INVALID_SIGNATURE = 402,
  /// Signature verification failed
  VERIFICATION_FAILED = 403,
  /// Key derivation failed
  KEY_DERIVATION_FAILED = 404,

  // Transaction errors (500-599)
  /// Invalid transaction format
  INVALID_TRANSACTION = 500,
  /// Insufficient funds
  INSUFFICIENT_FUNDS = 501,
  /// Invalid address
  INVALID_ADDRESS = 502,

  // Hardware wallet errors (600-699)
  /// Device not connected
  DEVICE_NOT_CONNECTED = 600,
  /// Device communication error
  DEVICE_COMM_ERROR = 601,
  /// Operation cancelled by user
  USER_CANCELLED = 602,
  /// Device busy
  DEVICE_BUSY = 603,
  /// Unsupported operation on this device
  DEVICE_NOT_SUPPORTED = 604,

  // WASI bridge errors (700-799)
  /// Bridge callback not set
  BRIDGE_NOT_SET = 700,
  /// Bridge callback failed
  BRIDGE_FAILED = 701,
  /// Feature requires bridge in WASI
  NEEDS_BRIDGE = 702,

  // FIPS errors (800-899)
  /// Algorithm not allowed in FIPS mode
  FIPS_NOT_ALLOWED = 800
};

/**
 * Convert error code to human-readable string
 */
const char* errorToString(Error error);

// =============================================================================
// Curve Types
// =============================================================================

/**
 * Elliptic curve types supported by the library
 */
enum class Curve : uint8_t {
  /// secp256k1 (Bitcoin, Ethereum)
  SECP256K1 = 0,

  /// Ed25519 (Solana, Polkadot)
  ED25519 = 1,

  /// NIST P-256 (secp256r1)
  P256 = 2,

  /// NIST P-384 (secp384r1)
  P384 = 3,

  /// X25519 (key exchange only)
  X25519 = 4
};

/**
 * Get curve name string
 */
const char* curveToString(Curve curve);

/**
 * Get private key size for curve
 */
size_t curvePrivateKeySize(Curve curve);

/**
 * Get compressed public key size for curve
 */
size_t curvePublicKeyCompressedSize(Curve curve);

/**
 * Get uncompressed public key size for curve
 */
size_t curvePublicKeyUncompressedSize(Curve curve);

// =============================================================================
// Coin Types (SLIP-44)
// =============================================================================

/**
 * Standard SLIP-44 coin types
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
enum class CoinType : uint32_t {
  // secp256k1 curves
  BITCOIN = 0,
  BITCOIN_TESTNET = 1,
  LITECOIN = 2,
  DOGECOIN = 3,
  ETHEREUM = 60,
  ETHEREUM_CLASSIC = 61,
  ROOTSTOCK = 137,
  BITCOIN_CASH = 145,
  BINANCE = 714,

  // Ed25519 curves
  SOLANA = 501,
  STELLAR = 148,
  CARDANO = 1815,
  POLKADOT = 354,
  KUSAMA = 434,
  TEZOS = 1729,

  // Cosmos ecosystem
  COSMOS = 118,
  TERRA = 330,
  OSMOSIS = 118,  // Uses same as Cosmos

  // Custom/reserved
  NIST_P256 = 0x100,   // 256
  NIST_P384 = 0x180,   // 384
  X25519 = 0x7919
};

/**
 * Get coin type name string
 */
const char* coinTypeToString(CoinType coin);

/**
 * Get curve for coin type
 */
Curve coinTypeToCurve(CoinType coin);

// =============================================================================
// Key Purpose (BIP-44 chain/change)
// =============================================================================

/**
 * Key purpose - determines external (signing) vs internal (encryption) chain
 */
enum class KeyPurpose : uint8_t {
  /// External chain (change=0) - for public-facing operations (signing)
  SIGNING = 0,

  /// Internal chain (change=1) - for private operations (encryption)
  ENCRYPTION = 1
};

// =============================================================================
// Address Types
// =============================================================================

/**
 * Bitcoin address types
 */
enum class BitcoinAddressType : uint8_t {
  /// Legacy P2PKH (starts with 1)
  P2PKH = 0,

  /// Pay-to-Script-Hash (starts with 3)
  P2SH = 1,

  /// Native SegWit P2WPKH (starts with bc1q)
  P2WPKH = 2,

  /// Native SegWit P2WSH (starts with bc1q)
  P2WSH = 3,

  /// Taproot P2TR (starts with bc1p)
  P2TR = 4
};

/**
 * Network type (mainnet vs testnet)
 */
enum class Network : uint8_t {
  MAINNET = 0,
  TESTNET = 1
};

// =============================================================================
// Result Type
// =============================================================================

/**
 * Result type for operations that may fail
 */
template<typename T>
struct Result {
  Error error;
  T value;

  bool ok() const { return error == Error::OK; }

  static Result success(T&& val) {
    return Result{Error::OK, std::forward<T>(val)};
  }

  static Result fail(Error err) {
    return Result{err, T{}};
  }
};

/**
 * Specialization for void results
 */
template<>
struct Result<void> {
  Error error;

  bool ok() const { return error == Error::OK; }

  static Result success() {
    return Result{Error::OK};
  }

  static Result fail(Error err) {
    return Result{err};
  }
};

using VoidResult = Result<void>;

} // namespace hd_wallet

#endif // HD_WALLET_TYPES_H
