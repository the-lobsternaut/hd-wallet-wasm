/**
 * @file bip32.h
 * @brief BIP-32 Hierarchical Deterministic Keys
 *
 * Implementation of BIP-32: Hierarchical Deterministic Wallets.
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 *
 * Features:
 * - Master key generation from seed
 * - Child key derivation (normal and hardened)
 * - Path-based derivation (e.g., "m/44'/60'/0'/0/0")
 * - Extended key serialization (xprv/xpub)
 * - Key neutering (private -> public)
 *
 * Path Notation:
 * - m = master key
 * - / = derivation step
 * - ' or h = hardened derivation (index + 2^31)
 * - Example: m/44'/60'/0'/0/0
 */

#ifndef HD_WALLET_BIP32_H
#define HD_WALLET_BIP32_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hd_wallet {
namespace bip32 {

// =============================================================================
// Constants
// =============================================================================

/// Hardened derivation threshold (2^31)
constexpr uint32_t HARDENED_OFFSET = 0x80000000;

/// Check if index is hardened
constexpr bool isHardened(uint32_t index) {
  return index >= HARDENED_OFFSET;
}

/// Make index hardened
constexpr uint32_t harden(uint32_t index) {
  return index | HARDENED_OFFSET;
}

/// Remove hardened flag from index
constexpr uint32_t unharden(uint32_t index) {
  return index & ~HARDENED_OFFSET;
}

// Extended key version bytes (mainnet)
constexpr uint32_t XPRV_VERSION = 0x0488ADE4;  // xprv
constexpr uint32_t XPUB_VERSION = 0x0488B21E;  // xpub

// Extended key version bytes (testnet)
constexpr uint32_t TPRV_VERSION = 0x04358394;  // tprv
constexpr uint32_t TPUB_VERSION = 0x043587CF;  // tpub

// BIP-49 version bytes (P2SH-P2WPKH)
constexpr uint32_t YPRV_VERSION = 0x049D7878;  // yprv
constexpr uint32_t YPUB_VERSION = 0x049D7CB2;  // ypub

// BIP-84 version bytes (native SegWit)
constexpr uint32_t ZPRV_VERSION = 0x04B2430C;  // zprv
constexpr uint32_t ZPUB_VERSION = 0x04B24746;  // zpub

// =============================================================================
// Derivation Path
// =============================================================================

/**
 * Parsed derivation path component
 */
struct PathComponent {
  uint32_t index;
  bool hardened;

  PathComponent(uint32_t idx, bool hard = false)
    : index(idx), hardened(hard) {}

  /// Get the full index value (with hardened flag if applicable)
  uint32_t fullIndex() const {
    return hardened ? (index | HARDENED_OFFSET) : index;
  }
};

/**
 * Parsed derivation path
 */
struct DerivationPath {
  std::vector<PathComponent> components;

  /// Check if path is valid (non-empty)
  bool isValid() const { return !components.empty(); }

  /// Get path depth
  size_t depth() const { return components.size(); }

  /// Convert to string (e.g., "m/44'/60'/0'/0/0")
  std::string toString() const;

  /// Create from string
  static Result<DerivationPath> parse(const std::string& path);

  /// Create BIP-44 path: m/44'/coin'/account'/change/index
  static DerivationPath bip44(
    uint32_t coin_type,
    uint32_t account = 0,
    uint32_t change = 0,
    uint32_t index = 0
  );

  /// Create BIP-49 path: m/49'/coin'/account'/change/index
  static DerivationPath bip49(
    uint32_t coin_type,
    uint32_t account = 0,
    uint32_t change = 0,
    uint32_t index = 0
  );

  /// Create BIP-84 path: m/84'/coin'/account'/change/index
  static DerivationPath bip84(
    uint32_t coin_type,
    uint32_t account = 0,
    uint32_t change = 0,
    uint32_t index = 0
  );
};

// =============================================================================
// Extended Key
// =============================================================================

/**
 * BIP-32 Extended Key
 *
 * Represents a node in the HD key tree, containing:
 * - Private key (optional, not present for neutered keys)
 * - Public key (always present)
 * - Chain code (for key derivation)
 * - Metadata (depth, parent fingerprint, child index)
 */
class ExtendedKey {
public:
  /**
   * Create extended key from seed (master key)
   *
   * @param seed 64-byte seed (from BIP-39 or other source)
   * @param curve Elliptic curve (default: secp256k1)
   * @return Result containing master extended key
   */
  static Result<ExtendedKey> fromSeed(
    const Bytes64& seed,
    Curve curve = Curve::SECP256K1
  );

  /**
   * Create extended key from seed vector
   */
  static Result<ExtendedKey> fromSeed(
    const ByteVector& seed,
    Curve curve = Curve::SECP256K1
  );

  /**
   * Parse extended key from serialized format (xprv/xpub)
   */
  static Result<ExtendedKey> fromString(const std::string& str);

  /**
   * Derive child key at index
   *
   * @param index Child index (use harden() for hardened derivation)
   * @return Result containing child key
   */
  Result<ExtendedKey> deriveChild(uint32_t index) const;

  /**
   * Derive child key at hardened index
   * Convenience method: equivalent to deriveChild(harden(index))
   */
  Result<ExtendedKey> deriveHardened(uint32_t index) const {
    return deriveChild(harden(index));
  }

  /**
   * Derive key at path
   *
   * @param path Derivation path string (e.g., "m/44'/60'/0'/0/0")
   * @return Result containing derived key
   */
  Result<ExtendedKey> derivePath(const std::string& path) const;

  /**
   * Derive key at parsed path
   */
  Result<ExtendedKey> derivePath(const DerivationPath& path) const;

  /**
   * Get neutered (public-only) version of this key
   * Returns a copy with the private key removed.
   */
  ExtendedKey neutered() const;

  // ----- Accessors -----

  /// Check if this is a neutered (public-only) key
  bool isNeutered() const { return !has_private_key_; }

  /// Check if this is a master key (depth 0)
  bool isMaster() const { return depth_ == 0; }

  /// Get the elliptic curve
  Curve curve() const { return curve_; }

  /// Get key depth in the derivation tree
  uint8_t depth() const { return depth_; }

  /// Get parent fingerprint (first 4 bytes of parent's public key hash)
  uint32_t parentFingerprint() const { return parent_fingerprint_; }

  /// Get child index
  uint32_t childIndex() const { return child_index_; }

  /// Get fingerprint of this key
  uint32_t fingerprint() const;

  /// Get private key (if available)
  Result<Bytes32> privateKey() const;

  /// Get public key (compressed)
  Bytes33 publicKey() const { return public_key_; }

  /// Get public key (uncompressed)
  Result<Bytes65> publicKeyUncompressed() const;

  /// Get chain code
  Bytes32 chainCode() const { return chain_code_; }

  // ----- Serialization -----

  /**
   * Serialize as extended private key (xprv)
   * @param version Version bytes (default: mainnet xprv)
   * @return Base58Check-encoded string
   */
  Result<std::string> serializePrivate(uint32_t version = XPRV_VERSION) const;

  /**
   * Serialize as extended public key (xpub)
   * @param version Version bytes (default: mainnet xpub)
   * @return Base58Check-encoded string
   */
  std::string serializePublic(uint32_t version = XPUB_VERSION) const;

  /// Alias for serializePrivate
  Result<std::string> toXprv() const { return serializePrivate(); }

  /// Alias for serializePublic
  std::string toXpub() const { return serializePublic(); }

  // ----- Memory Safety -----

  /// Securely wipe private key from memory
  void wipe();

  /// Clone this key (creates independent copy)
  ExtendedKey clone() const;

  // ----- Constructors -----

  ExtendedKey();
  ~ExtendedKey();

  // Move semantics
  ExtendedKey(ExtendedKey&& other) noexcept;
  ExtendedKey& operator=(ExtendedKey&& other) noexcept;

  // Copy (explicit to prevent accidental copies of private keys)
  ExtendedKey(const ExtendedKey& other);
  ExtendedKey& operator=(const ExtendedKey& other);

private:
  Curve curve_;
  uint8_t depth_;
  uint32_t parent_fingerprint_;
  uint32_t child_index_;
  Bytes32 chain_code_;
  Bytes33 public_key_;
  Bytes32 private_key_;
  bool has_private_key_;

  // Internal constructor
  ExtendedKey(
    Curve curve,
    uint8_t depth,
    uint32_t parent_fp,
    uint32_t child_idx,
    const Bytes32& chain_code,
    const Bytes33& public_key,
    const Bytes32& private_key,
    bool has_private
  );
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Derive public key from private key
 *
 * @param private_key 32-byte private key
 * @param curve Elliptic curve
 * @return Compressed public key
 */
Result<Bytes33> publicKeyFromPrivate(
  const Bytes32& private_key,
  Curve curve = Curve::SECP256K1
);

/**
 * Compress public key
 *
 * @param uncompressed 65-byte uncompressed public key (with 0x04 prefix)
 * @param curve Elliptic curve
 * @return 33-byte compressed public key
 */
Result<Bytes33> compressPublicKey(
  const Bytes65& uncompressed,
  Curve curve = Curve::SECP256K1
);

/**
 * Decompress public key
 *
 * @param compressed 33-byte compressed public key
 * @param curve Elliptic curve
 * @return 65-byte uncompressed public key (with 0x04 prefix)
 */
Result<Bytes65> decompressPublicKey(
  const Bytes33& compressed,
  Curve curve = Curve::SECP256K1
);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

/// Opaque handle for ExtendedKey
typedef struct hd_key_t* hd_key_handle;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_from_seed(
  const uint8_t* seed,
  size_t seed_size,
  int32_t curve
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_from_xprv(const char* xprv);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_from_xpub(const char* xpub);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_derive_path(hd_key_handle key, const char* path);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_derive_child(hd_key_handle key, uint32_t index);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_derive_hardened(hd_key_handle key, uint32_t index);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_get_private(hd_key_handle key, uint8_t* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_get_public(hd_key_handle key, uint8_t* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_get_chain_code(hd_key_handle key, uint8_t* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_key_get_fingerprint(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_key_get_parent_fingerprint(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint8_t hd_key_get_depth(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_key_get_child_index(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_serialize_xprv(hd_key_handle key, char* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_serialize_xpub(hd_key_handle key, char* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_neutered(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_is_neutered(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_wipe(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_handle hd_key_clone(hd_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_destroy(hd_key_handle key);

// Path utilities
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_path_build(
  char* out,
  size_t out_size,
  uint32_t purpose,
  uint32_t coin_type,
  uint32_t account,
  uint32_t change,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_path_parse(
  const char* path,
  uint32_t* purpose,
  uint32_t* coin_type,
  uint32_t* account,
  uint32_t* change,
  uint32_t* index
);

} // namespace bip32
} // namespace hd_wallet

#endif // HD_WALLET_BIP32_H
