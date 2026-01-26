/**
 * @file key_manager.h
 * @brief Key Manager - High-Level Key Derivation and Management
 *
 * The KeyManager class provides a high-level interface for HD key derivation
 * with purpose-based enforcement. It distinguishes between:
 *
 * - Signing keys (external chain, change=0): For transaction/message signing
 * - Encryption keys (internal chain, change=1): For data encryption/decryption
 *
 * This separation follows the convention:
 * - External addresses (change=0): Publicly shareable, for receiving funds
 * - Internal addresses (change=1): Change addresses, used internally
 *
 * We repurpose this for a security boundary:
 * - Signing keys: Used for signatures that are publicly verifiable
 * - Encryption keys: Used for key derivation in encryption schemes
 *
 * Key Features:
 * - Seed storage and management with secure memory handling
 * - Derived key caching for performance
 * - Purpose-based derivation enforcement
 * - Key validation helpers
 * - Support for multiple accounts and coin types
 *
 * @example
 * ```cpp
 * KeyManager km(seed);
 *
 * // Derive a signing key (external chain)
 * auto signingKey = km.deriveSigningKey(CoinType::ETHEREUM, 0, 0);
 *
 * // Derive an encryption key (internal chain)
 * auto encryptionKey = km.deriveEncryptionKey(CoinType::ETHEREUM, 0, 0);
 *
 * // Derive both at once
 * auto keyPair = km.deriveKeyPair(CoinType::ETHEREUM, 0, 0);
 * ```
 */

#ifndef HD_WALLET_KEY_MANAGER_H
#define HD_WALLET_KEY_MANAGER_H

#include "config.h"
#include "types.h"
#include "bip32.h"

#include <cstdint>
#include <memory>
#include <string>
#include <optional>

namespace hd_wallet {

// =============================================================================
// Forward Declarations
// =============================================================================

class KeyManagerImpl;

// =============================================================================
// Derived Key Structure
// =============================================================================

/**
 * A derived key with its metadata
 */
struct DerivedKey {
  /// Private key (32 bytes)
  Bytes32 private_key;

  /// Compressed public key (33 bytes)
  Bytes33 public_key;

  /// Chain code (for further derivation)
  Bytes32 chain_code;

  /// Full derivation path (e.g., "m/44'/60'/0'/0/0")
  std::string path;

  /// Purpose of this key
  KeyPurpose purpose;

  /// Coin type this key is for
  CoinType coin_type;

  /// Account index
  uint32_t account;

  /// Key index within the chain
  uint32_t index;

  /// Fingerprint of the key
  uint32_t fingerprint;

  /**
   * Securely wipe the private key from memory
   */
  void wipe();

  /**
   * Check if the key is valid (has non-zero private key)
   */
  bool isValid() const;

  /**
   * Create an empty/invalid derived key
   */
  static DerivedKey empty();
};

// =============================================================================
// Key Pair Structure
// =============================================================================

/**
 * A pair of derived keys: one for signing, one for encryption
 *
 * This structure represents a matched pair of keys derived at the same
 * account and index, but on different chains:
 * - signing: external chain (change=0)
 * - encryption: internal chain (change=1)
 */
struct KeyPair {
  /// Key for signing operations (external chain)
  DerivedKey signing;

  /// Key for encryption operations (internal chain)
  DerivedKey encryption;

  /**
   * Securely wipe both keys from memory
   */
  void wipe();

  /**
   * Check if both keys are valid
   */
  bool isValid() const;
};

// =============================================================================
// Key Derivation Options
// =============================================================================

/**
 * Options for key derivation
 */
struct DerivationOptions {
  /// BIP purpose (default: 44)
  uint32_t purpose = 44;

  /// Whether to cache the derived key
  bool cache = true;

  /// Elliptic curve to use (default: based on coin type)
  std::optional<Curve> curve;

  /// Custom derivation path (overrides all other options)
  std::optional<std::string> custom_path;
};

// =============================================================================
// Key Manager Class
// =============================================================================

/**
 * KeyManager - High-Level HD Key Derivation and Management
 *
 * The KeyManager provides a secure, purpose-aware interface for HD key
 * derivation. It enforces the convention of using:
 * - External chain (change=0) for signing keys
 * - Internal chain (change=1) for encryption keys
 *
 * Security Features:
 * - Seed is securely wiped on destruction
 * - Derived key caching with secure memory
 * - Private keys never exposed outside controlled methods
 *
 * Thread Safety:
 * - Instance methods are NOT thread-safe
 * - Use external synchronization if sharing across threads
 */
class KeyManager {
public:
  /**
   * Create a KeyManager from a 64-byte seed
   *
   * @param seed 64-byte seed (from BIP-39 mnemonicToSeed)
   */
  explicit KeyManager(const Bytes64& seed);

  /**
   * Create a KeyManager from a seed vector
   */
  explicit KeyManager(const ByteVector& seed);

  /**
   * Create a KeyManager from a mnemonic phrase
   *
   * @param mnemonic BIP-39 mnemonic phrase
   * @param passphrase Optional BIP-39 passphrase
   * @return Result containing KeyManager or error
   */
  static Result<KeyManager> fromMnemonic(
    const std::string& mnemonic,
    const std::string& passphrase = ""
  );

  /**
   * Destructor - securely wipes seed and cached keys
   */
  ~KeyManager();

  // Non-copyable
  KeyManager(const KeyManager&) = delete;
  KeyManager& operator=(const KeyManager&) = delete;

  // Movable
  KeyManager(KeyManager&& other) noexcept;
  KeyManager& operator=(KeyManager&& other) noexcept;

  // ----- Purpose-Based Key Derivation -----

  /**
   * Derive a signing key (external chain, change=0)
   *
   * Derives a key at path: m/purpose'/coin_type'/account'/0/index
   *
   * Use this for:
   * - Transaction signing
   * - Message signing
   * - Public signature verification
   *
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @param index Key index within the account
   * @param options Optional derivation options
   * @return Result containing derived key or error
   */
  Result<DerivedKey> deriveSigningKey(
    CoinType coin_type,
    uint32_t account = 0,
    uint32_t index = 0,
    const DerivationOptions& options = {}
  );

  /**
   * Derive an encryption key (internal chain, change=1)
   *
   * Derives a key at path: m/purpose'/coin_type'/account'/1/index
   *
   * Use this for:
   * - Data encryption/decryption
   * - Key agreement (ECDH/X25519)
   * - Symmetric key derivation
   *
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @param index Key index within the account
   * @param options Optional derivation options
   * @return Result containing derived key or error
   */
  Result<DerivedKey> deriveEncryptionKey(
    CoinType coin_type,
    uint32_t account = 0,
    uint32_t index = 0,
    const DerivationOptions& options = {}
  );

  /**
   * Derive a matched key pair (signing + encryption)
   *
   * Derives two keys at the same account and index:
   * - Signing: m/purpose'/coin_type'/account'/0/index
   * - Encryption: m/purpose'/coin_type'/account'/1/index
   *
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @param index Key index within the account
   * @param options Optional derivation options
   * @return Result containing key pair or error
   */
  Result<KeyPair> deriveKeyPair(
    CoinType coin_type,
    uint32_t account = 0,
    uint32_t index = 0,
    const DerivationOptions& options = {}
  );

  // ----- Generic Key Derivation -----

  /**
   * Derive a key at an arbitrary path
   *
   * @param path Derivation path (e.g., "m/44'/60'/0'/0/0")
   * @param purpose Purpose to assign to the key
   * @return Result containing derived key or error
   */
  Result<DerivedKey> deriveKeyAtPath(
    const std::string& path,
    KeyPurpose purpose = KeyPurpose::SIGNING
  );

  /**
   * Get the extended public key at a path
   *
   * @param path Derivation path
   * @return Result containing xpub string or error
   */
  Result<std::string> getXpub(const std::string& path);

  /**
   * Get the master fingerprint
   */
  uint32_t getMasterFingerprint() const;

  // ----- Key Validation -----

  /**
   * Validate that a private key is valid for a curve
   *
   * @param private_key 32-byte private key
   * @param curve Elliptic curve
   * @return true if valid
   */
  static bool isValidPrivateKey(const Bytes32& private_key, Curve curve);

  /**
   * Validate that a public key is valid for a curve
   *
   * @param public_key Compressed public key
   * @param curve Elliptic curve
   * @return true if valid
   */
  static bool isValidPublicKey(const Bytes33& public_key, Curve curve);

  /**
   * Validate a derivation path
   *
   * @param path Derivation path string
   * @return true if valid
   */
  static bool isValidPath(const std::string& path);

  /**
   * Derive public key from private key
   *
   * @param private_key 32-byte private key
   * @param curve Elliptic curve
   * @return Result containing compressed public key or error
   */
  static Result<Bytes33> publicKeyFromPrivate(
    const Bytes32& private_key,
    Curve curve
  );

  // ----- Cache Management -----

  /**
   * Clear the derived key cache
   */
  void clearCache();

  /**
   * Set maximum cache size (number of keys)
   *
   * @param max_size Maximum number of keys to cache (0 = disable caching)
   */
  void setCacheSize(size_t max_size);

  /**
   * Get current cache size
   */
  size_t getCacheSize() const;

  /**
   * Check if a key at path is cached
   */
  bool isCached(const std::string& path) const;

  // ----- Secure Operations -----

  /**
   * Securely wipe the seed and all cached keys
   */
  void wipe();

  /**
   * Check if the manager has been wiped
   */
  bool isWiped() const;

  // ----- Path Building Helpers -----

  /**
   * Build a BIP-44 compatible path
   *
   * @param purpose BIP purpose (44, 49, 84, etc.)
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @param change Change index (0=external, 1=internal)
   * @param index Address index
   * @return Path string
   */
  static std::string buildPath(
    uint32_t purpose,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
  );

  /**
   * Build a signing key path (change=0)
   */
  static std::string buildSigningPath(
    uint32_t purpose,
    CoinType coin_type,
    uint32_t account,
    uint32_t index
  );

  /**
   * Build an encryption key path (change=1)
   */
  static std::string buildEncryptionPath(
    uint32_t purpose,
    CoinType coin_type,
    uint32_t account,
    uint32_t index
  );

private:
  // Private default constructor for Result::fail
  // Creates an invalid/empty KeyManager
  KeyManager() : impl_(nullptr) {}
  friend struct Result<KeyManager>;

  std::unique_ptr<KeyManagerImpl> impl_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

/// Opaque handle for KeyManager
typedef struct hd_key_manager_t* hd_key_manager_handle;

/// Opaque handle for DerivedKey
typedef struct hd_derived_key_t* hd_derived_key_handle;

/// Opaque handle for KeyPair
typedef struct hd_key_pair_t* hd_key_pair_handle;

// ----- KeyManager Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_manager_handle hd_key_manager_create(
  const uint8_t* seed,
  size_t seed_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_manager_handle hd_key_manager_from_mnemonic(
  const char* mnemonic,
  const char* passphrase
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_destroy(hd_key_manager_handle manager);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_signing_key(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_encryption_key(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_pair_handle hd_key_manager_derive_key_pair(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_at_path(
  hd_key_manager_handle manager,
  const char* path,
  int32_t purpose
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_manager_get_xpub(
  hd_key_manager_handle manager,
  const char* path,
  char* xpub_out,
  size_t xpub_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_key_manager_get_master_fingerprint(hd_key_manager_handle manager);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_clear_cache(hd_key_manager_handle manager);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_wipe(hd_key_manager_handle manager);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_manager_is_wiped(hd_key_manager_handle manager);

// ----- DerivedKey Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_derived_key_destroy(hd_derived_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_private(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_public(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_chain_code(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_path(
  hd_derived_key_handle key,
  char* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_purpose(hd_derived_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_coin_type(hd_derived_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_derived_key_get_fingerprint(hd_derived_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_derived_key_wipe(hd_derived_key_handle key);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_is_valid(hd_derived_key_handle key);

// ----- KeyPair Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_pair_destroy(hd_key_pair_handle pair);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_pair_get_signing(hd_key_pair_handle pair);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_pair_get_encryption(hd_key_pair_handle pair);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_pair_wipe(hd_key_pair_handle pair);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_pair_is_valid(hd_key_pair_handle pair);

// ----- Validation Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_private_key(
  const uint8_t* key,
  size_t key_size,
  int32_t curve
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_public_key(
  const uint8_t* key,
  size_t key_size,
  int32_t curve
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_path(const char* path);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_public_key_from_private(
  const uint8_t* private_key,
  size_t private_key_size,
  int32_t curve,
  uint8_t* public_key_out,
  size_t public_key_size
);

// ----- Path Building Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_build_path(
  char* out,
  size_t out_size,
  uint32_t purpose,
  uint32_t coin_type,
  uint32_t account,
  uint32_t change,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_build_signing_path(
  char* out,
  size_t out_size,
  uint32_t purpose,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_build_encryption_path(
  char* out,
  size_t out_size,
  uint32_t purpose,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
);

} // namespace hd_wallet

#endif // HD_WALLET_KEY_MANAGER_H
