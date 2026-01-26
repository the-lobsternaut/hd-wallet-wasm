/**
 * @file keyring.h
 * @brief Keyring - Multi-Wallet Management
 *
 * The Keyring class provides secure management of multiple HD wallets,
 * enabling:
 * - Multiple wallet storage and management
 * - Account derivation for different coin types
 * - Transaction signing through the keyring
 * - Message signing through the keyring
 * - Secure memory handling (automatic wiping on destruction)
 *
 * Security Features:
 * - Seeds are securely wiped from memory on destruction
 * - Private keys are never exposed outside the keyring
 * - All signing operations are performed internally
 *
 * @example
 * ```cpp
 * Keyring keyring;
 *
 * // Add wallets
 * auto id1 = keyring.addWallet(seed1);
 * auto id2 = keyring.addWallet(seed2);
 *
 * // Derive account and sign
 * auto account = keyring.deriveAccount(id1.value, CoinType::ETHEREUM, 0);
 * auto sig = keyring.signMessage(id1.value, "m/44'/60'/0'/0/0", message);
 * ```
 */

#ifndef HD_WALLET_KEYRING_H
#define HD_WALLET_KEYRING_H

#include "config.h"
#include "types.h"
#include "bip32.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

namespace hd_wallet {

// =============================================================================
// Forward Declarations
// =============================================================================

class KeyringImpl;

// =============================================================================
// Wallet Info
// =============================================================================

/**
 * Information about a wallet stored in the keyring
 */
struct WalletInfo {
  /// Unique identifier for the wallet
  uint32_t id;

  /// Optional label/name for the wallet
  std::string label;

  /// Creation timestamp (Unix epoch)
  int64_t created_at;

  /// Fingerprint of the master key
  uint32_t fingerprint;

  /// Whether the wallet is locked (requires unlock before signing)
  bool locked;
};

// =============================================================================
// Account Info
// =============================================================================

/**
 * Information about a derived account
 */
struct AccountInfo {
  /// Wallet ID this account belongs to
  uint32_t wallet_id;

  /// Coin type (SLIP-44)
  CoinType coin_type;

  /// Account index
  uint32_t account_index;

  /// Full derivation path (e.g., "m/44'/60'/0'")
  std::string path;

  /// Extended public key (xpub)
  std::string xpub;

  /// Fingerprint of the account key
  uint32_t fingerprint;
};

// =============================================================================
// Signature Result
// =============================================================================

/**
 * Result of a signing operation
 */
struct SignatureResult {
  /// DER-encoded signature (for ECDSA) or raw signature (for EdDSA)
  ByteVector signature;

  /// Recovery ID for ECDSA signatures (for Ethereum, etc.)
  int32_t recovery_id;

  /// Public key that signed (compressed)
  Bytes33 public_key;
};

// =============================================================================
// Keyring Class
// =============================================================================

/**
 * Keyring - Secure Multi-Wallet Manager
 *
 * The Keyring class provides a secure container for managing multiple HD
 * wallets. It handles:
 * - Seed storage with secure memory handling
 * - Key derivation with caching
 * - Transaction and message signing
 * - Wallet locking/unlocking
 *
 * Thread Safety:
 * - All public methods are thread-safe
 * - Internal mutex protects wallet operations
 */
class Keyring {
public:
  /**
   * Create a new empty keyring
   */
  Keyring();

  /**
   * Destructor - securely wipes all seeds and keys
   */
  ~Keyring();

  // Non-copyable
  Keyring(const Keyring&) = delete;
  Keyring& operator=(const Keyring&) = delete;

  // Movable
  Keyring(Keyring&& other) noexcept;
  Keyring& operator=(Keyring&& other) noexcept;

  // ----- Wallet Management -----

  /**
   * Add a wallet from seed
   *
   * @param seed 64-byte seed (from BIP-39 mnemonicToSeed)
   * @param label Optional label for the wallet
   * @return Result containing wallet ID or error
   */
  Result<uint32_t> addWallet(const Bytes64& seed, const std::string& label = "");

  /**
   * Add a wallet from seed vector
   */
  Result<uint32_t> addWallet(const ByteVector& seed, const std::string& label = "");

  /**
   * Add a wallet from mnemonic phrase
   *
   * @param mnemonic BIP-39 mnemonic phrase
   * @param passphrase Optional BIP-39 passphrase
   * @param label Optional label for the wallet
   * @return Result containing wallet ID or error
   */
  Result<uint32_t> addWalletFromMnemonic(
    const std::string& mnemonic,
    const std::string& passphrase = "",
    const std::string& label = ""
  );

  /**
   * Remove a wallet from the keyring
   *
   * @param wallet_id Wallet ID to remove
   * @return Result indicating success or error
   */
  VoidResult removeWallet(uint32_t wallet_id);

  /**
   * Get information about a wallet
   *
   * @param wallet_id Wallet ID
   * @return Result containing wallet info or error
   */
  Result<WalletInfo> getWalletInfo(uint32_t wallet_id) const;

  /**
   * List all wallets in the keyring
   *
   * @return Vector of wallet information
   */
  std::vector<WalletInfo> listWallets() const;

  /**
   * Get number of wallets in the keyring
   */
  size_t walletCount() const;

  /**
   * Check if a wallet exists
   */
  bool hasWallet(uint32_t wallet_id) const;

  /**
   * Set wallet label
   */
  VoidResult setWalletLabel(uint32_t wallet_id, const std::string& label);

  // ----- Account Derivation -----

  /**
   * Derive an account for a specific coin type
   *
   * Creates a BIP-44 compatible account at path:
   * m/purpose'/coin_type'/account'
   *
   * @param wallet_id Wallet ID
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @return Result containing account info or error
   */
  Result<AccountInfo> deriveAccount(
    uint32_t wallet_id,
    CoinType coin_type,
    uint32_t account = 0
  );

  /**
   * Derive an account using custom BIP standard
   *
   * @param wallet_id Wallet ID
   * @param purpose BIP purpose (44, 49, 84, etc.)
   * @param coin_type SLIP-44 coin type
   * @param account Account index
   * @return Result containing account info or error
   */
  Result<AccountInfo> deriveAccountWithPurpose(
    uint32_t wallet_id,
    uint32_t purpose,
    CoinType coin_type,
    uint32_t account = 0
  );

  /**
   * Get the extended public key at a specific path
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path
   * @return Result containing xpub string or error
   */
  Result<std::string> getXpub(uint32_t wallet_id, const std::string& path) const;

  /**
   * Get a public key at a specific path
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path
   * @return Result containing compressed public key or error
   */
  Result<Bytes33> getPublicKey(uint32_t wallet_id, const std::string& path) const;

  // ----- Transaction Signing -----

  /**
   * Sign a transaction hash
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path to signing key
   * @param hash 32-byte hash to sign
   * @return Result containing signature or error
   */
  Result<SignatureResult> signTransaction(
    uint32_t wallet_id,
    const std::string& path,
    const Bytes32& hash
  );

  /**
   * Sign a transaction hash (vector version)
   */
  Result<SignatureResult> signTransaction(
    uint32_t wallet_id,
    const std::string& path,
    const ByteVector& hash
  );

  // ----- Message Signing -----

  /**
   * Sign a message using Ethereum-style personal sign
   *
   * Prepends "\x19Ethereum Signed Message:\n" + length prefix
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path to signing key
   * @param message Message to sign
   * @return Result containing signature or error
   */
  Result<SignatureResult> signPersonalMessage(
    uint32_t wallet_id,
    const std::string& path,
    const std::string& message
  );

  /**
   * Sign arbitrary data
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path to signing key
   * @param data Data to sign (will be hashed)
   * @return Result containing signature or error
   */
  Result<SignatureResult> signMessage(
    uint32_t wallet_id,
    const std::string& path,
    const ByteVector& data
  );

  /**
   * Sign a pre-computed hash directly (use with caution)
   *
   * @param wallet_id Wallet ID
   * @param path Derivation path to signing key
   * @param hash 32-byte hash to sign directly
   * @return Result containing signature or error
   */
  Result<SignatureResult> signHash(
    uint32_t wallet_id,
    const std::string& path,
    const Bytes32& hash
  );

  // ----- Wallet Locking -----

  /**
   * Lock a wallet (requires unlock before signing)
   *
   * @param wallet_id Wallet ID
   * @return Result indicating success or error
   */
  VoidResult lockWallet(uint32_t wallet_id);

  /**
   * Unlock a wallet with passphrase
   *
   * @param wallet_id Wallet ID
   * @param passphrase Unlock passphrase
   * @return Result indicating success or error
   */
  VoidResult unlockWallet(uint32_t wallet_id, const std::string& passphrase);

  /**
   * Check if a wallet is locked
   */
  bool isWalletLocked(uint32_t wallet_id) const;

  // ----- Secure Operations -----

  /**
   * Securely wipe all wallets and keys from memory
   */
  void wipeAll();

  /**
   * Wipe derived key cache for a specific wallet
   */
  void wipeCacheForWallet(uint32_t wallet_id);

  /**
   * Wipe all derived key caches
   */
  void wipeAllCaches();

  // ----- Serialization -----

  /**
   * Export a wallet's encrypted seed for backup
   *
   * @param wallet_id Wallet ID
   * @param encryption_key 32-byte encryption key
   * @return Result containing encrypted seed or error
   */
  Result<ByteVector> exportWalletEncrypted(
    uint32_t wallet_id,
    const Bytes32& encryption_key
  ) const;

  /**
   * Import an encrypted wallet backup
   *
   * @param encrypted_data Encrypted wallet data
   * @param encryption_key 32-byte decryption key
   * @param label Optional label
   * @return Result containing new wallet ID or error
   */
  Result<uint32_t> importWalletEncrypted(
    const ByteVector& encrypted_data,
    const Bytes32& encryption_key,
    const std::string& label = ""
  );

private:
  std::unique_ptr<KeyringImpl> impl_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

/// Opaque handle for Keyring
typedef struct hd_keyring_t* hd_keyring_handle;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_keyring_handle hd_keyring_create();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_destroy(hd_keyring_handle keyring);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_add_wallet(
  hd_keyring_handle keyring,
  const uint8_t* seed,
  size_t seed_size,
  const char* label
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_add_wallet_from_mnemonic(
  hd_keyring_handle keyring,
  const char* mnemonic,
  const char* passphrase,
  const char* label
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_remove_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_wallet_count(hd_keyring_handle keyring);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_has_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_get_xpub(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  char* xpub_out,
  size_t xpub_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_get_public_key(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_sign_hash(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  const uint8_t* hash,
  size_t hash_size,
  uint8_t* sig_out,
  size_t sig_size,
  int32_t* recovery_id_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_sign_message(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  const uint8_t* message,
  size_t message_size,
  uint8_t* sig_out,
  size_t sig_size,
  int32_t* recovery_id_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_lock_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_unlock_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* passphrase
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_is_wallet_locked(
  hd_keyring_handle keyring,
  uint32_t wallet_id
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_wipe_all(hd_keyring_handle keyring);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_wipe_cache(
  hd_keyring_handle keyring,
  uint32_t wallet_id
);

} // namespace hd_wallet

#endif // HD_WALLET_KEYRING_H
