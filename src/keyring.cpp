/**
 * @file keyring.cpp
 * @brief Keyring Implementation - Multi-Wallet Management
 *
 * Implementation of the Keyring class for secure multi-wallet management.
 */

#include "hd_wallet/keyring.h"
#include "hd_wallet/bip39.h"
#include "hd_wallet/bip32.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace hd_wallet {

// =============================================================================
// Secure Memory Utilities
// =============================================================================

namespace {

/**
 * Secure memory wipe that prevents compiler optimization
 */
void secureWipe(void* ptr, size_t size) {
  if (ptr && size > 0) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
      *p++ = 0;
    }
    // Memory barrier to prevent reordering
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
}

/**
 * Secure wipe for Bytes32
 */
void secureWipe(Bytes32& data) {
  secureWipe(data.data(), data.size());
}

/**
 * Secure wipe for Bytes64
 */
void secureWipe(Bytes64& data) {
  secureWipe(data.data(), data.size());
}

/**
 * Secure wipe for ByteVector
 */
void secureWipe(ByteVector& data) {
  secureWipe(data.data(), data.size());
  data.clear();
}

/**
 * Get current Unix timestamp in seconds
 */
int64_t getCurrentTimestamp() {
  // In WASI, we may need to use the bridge for time
  // For now, return 0 if time is not available
#if HD_WALLET_IS_WASI
  return 0;
#else
  return static_cast<int64_t>(std::time(nullptr));
#endif
}

} // anonymous namespace

// =============================================================================
// Wallet Entry (Internal)
// =============================================================================

/**
 * Internal wallet entry storing seed and derived keys
 */
struct WalletEntry {
  uint32_t id;
  std::string label;
  int64_t created_at;
  Bytes64 seed;
  bip32::ExtendedKey master_key;
  bool locked;
  std::string lock_passphrase_hash;  // For unlock verification

  // Derived key cache (path -> ExtendedKey)
  std::unordered_map<std::string, bip32::ExtendedKey> key_cache;

  WalletEntry() : id(0), created_at(0), locked(false) {}

  ~WalletEntry() {
    wipe();
  }

  void wipe() {
    secureWipe(seed);
    master_key.wipe();
    for (auto& [path, key] : key_cache) {
      key.wipe();
    }
    key_cache.clear();
    lock_passphrase_hash.clear();
  }

  WalletEntry(WalletEntry&& other) noexcept
    : id(other.id),
      label(std::move(other.label)),
      created_at(other.created_at),
      seed(other.seed),
      master_key(std::move(other.master_key)),
      locked(other.locked),
      lock_passphrase_hash(std::move(other.lock_passphrase_hash)),
      key_cache(std::move(other.key_cache)) {
    secureWipe(other.seed);
    other.id = 0;
  }

  WalletEntry& operator=(WalletEntry&& other) noexcept {
    if (this != &other) {
      wipe();
      id = other.id;
      label = std::move(other.label);
      created_at = other.created_at;
      seed = other.seed;
      master_key = std::move(other.master_key);
      locked = other.locked;
      lock_passphrase_hash = std::move(other.lock_passphrase_hash);
      key_cache = std::move(other.key_cache);
      secureWipe(other.seed);
      other.id = 0;
    }
    return *this;
  }

  // Non-copyable
  WalletEntry(const WalletEntry&) = delete;
  WalletEntry& operator=(const WalletEntry&) = delete;
};

// =============================================================================
// KeyringImpl - Private Implementation
// =============================================================================

class KeyringImpl {
public:
  KeyringImpl() : next_id_(1) {}

  ~KeyringImpl() {
    wipeAll();
  }

  // ----- Wallet Management -----

  Result<uint32_t> addWallet(const Bytes64& seed, const std::string& label) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Create master key from seed
    auto result = bip32::ExtendedKey::fromSeed(seed);
    if (!result.ok()) {
      return Result<uint32_t>::fail(result.error);
    }

    // Create wallet entry
    WalletEntry entry;
    entry.id = next_id_++;
    entry.label = label;
    entry.created_at = getCurrentTimestamp();
    entry.seed = seed;
    entry.master_key = std::move(result.value);
    entry.locked = false;

    uint32_t id = entry.id;
    wallets_[id] = std::move(entry);

    return Result<uint32_t>::success(std::move(id));
  }

  Result<uint32_t> addWallet(const ByteVector& seed, const std::string& label) {
    if (seed.size() != 64) {
      return Result<uint32_t>::fail(Error::INVALID_SEED);
    }
    Bytes64 seed64;
    std::copy(seed.begin(), seed.end(), seed64.begin());
    auto result = addWallet(seed64, label);
    secureWipe(seed64);
    return result;
  }

  VoidResult removeWallet(uint32_t wallet_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return VoidResult::fail(Error::INVALID_ARGUMENT);
    }

    // Securely wipe before removing
    it->second.wipe();
    wallets_.erase(it);

    return VoidResult::success();
  }

  Result<WalletInfo> getWalletInfo(uint32_t wallet_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<WalletInfo>::fail(Error::INVALID_ARGUMENT);
    }

    const auto& entry = it->second;
    WalletInfo info;
    info.id = entry.id;
    info.label = entry.label;
    info.created_at = entry.created_at;
    info.fingerprint = entry.master_key.fingerprint();
    info.locked = entry.locked;

    return Result<WalletInfo>::success(std::move(info));
  }

  std::vector<WalletInfo> listWallets() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<WalletInfo> result;
    result.reserve(wallets_.size());

    for (const auto& [id, entry] : wallets_) {
      WalletInfo info;
      info.id = entry.id;
      info.label = entry.label;
      info.created_at = entry.created_at;
      info.fingerprint = entry.master_key.fingerprint();
      info.locked = entry.locked;
      result.push_back(std::move(info));
    }

    return result;
  }

  size_t walletCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return wallets_.size();
  }

  bool hasWallet(uint32_t wallet_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return wallets_.find(wallet_id) != wallets_.end();
  }

  VoidResult setWalletLabel(uint32_t wallet_id, const std::string& label) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return VoidResult::fail(Error::INVALID_ARGUMENT);
    }

    it->second.label = label;
    return VoidResult::success();
  }

  // ----- Account Derivation -----

  Result<AccountInfo> deriveAccount(
    uint32_t wallet_id,
    uint32_t purpose,
    CoinType coin_type,
    uint32_t account
  ) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<AccountInfo>::fail(Error::INVALID_ARGUMENT);
    }

    auto& entry = it->second;

    // Build account path: m/purpose'/coin'/account'
    std::string path = "m/" + std::to_string(purpose) + "'/" +
                       std::to_string(static_cast<uint32_t>(coin_type)) + "'/" +
                       std::to_string(account) + "'";

    // Derive account key
    auto key_result = deriveKeyInternal(entry, path);
    if (!key_result.ok()) {
      return Result<AccountInfo>::fail(key_result.error);
    }

    AccountInfo info;
    info.wallet_id = wallet_id;
    info.coin_type = coin_type;
    info.account_index = account;
    info.path = path;
    info.xpub = key_result.value.toXpub();
    info.fingerprint = key_result.value.fingerprint();

    return Result<AccountInfo>::success(std::move(info));
  }

  Result<std::string> getXpub(uint32_t wallet_id, const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<std::string>::fail(Error::INVALID_ARGUMENT);
    }

    // Note: const_cast because we may cache, but cache is mutable
    auto& entry = const_cast<WalletEntry&>(it->second);
    auto key_result = deriveKeyInternal(entry, path);
    if (!key_result.ok()) {
      return Result<std::string>::fail(key_result.error);
    }

    return Result<std::string>::success(key_result.value.toXpub());
  }

  Result<Bytes33> getPublicKey(uint32_t wallet_id, const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<Bytes33>::fail(Error::INVALID_ARGUMENT);
    }

    auto& entry = const_cast<WalletEntry&>(it->second);
    auto key_result = deriveKeyInternal(entry, path);
    if (!key_result.ok()) {
      return Result<Bytes33>::fail(key_result.error);
    }

    return Result<Bytes33>::success(key_result.value.publicKey());
  }

  // ----- Signing -----

  Result<SignatureResult> signHash(
    uint32_t wallet_id,
    const std::string& path,
    const Bytes32& hash
  ) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<SignatureResult>::fail(Error::INVALID_ARGUMENT);
    }

    auto& entry = it->second;

    // Check if wallet is locked
    if (entry.locked) {
      return Result<SignatureResult>::fail(Error::USER_CANCELLED);
    }

    // Derive signing key
    auto key_result = deriveKeyInternal(entry, path);
    if (!key_result.ok()) {
      return Result<SignatureResult>::fail(key_result.error);
    }

    // Get private key
    auto privkey_result = key_result.value.privateKey();
    if (!privkey_result.ok()) {
      return Result<SignatureResult>::fail(privkey_result.error);
    }

    // Sign the hash (ECDSA secp256k1)
    // This is a placeholder - actual implementation would use crypto library
    SignatureResult sig_result;
    sig_result.public_key = key_result.value.publicKey();
    sig_result.recovery_id = 0;

    // Placeholder signature (65 bytes: r[32] + s[32] + v[1])
    sig_result.signature.resize(65);
    // In real implementation: sign with private key

    // Securely wipe the private key copy
    Bytes32 privkey_copy = privkey_result.value;
    secureWipe(privkey_copy);

    return Result<SignatureResult>::success(std::move(sig_result));
  }

  // ----- Locking -----

  VoidResult lockWallet(uint32_t wallet_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return VoidResult::fail(Error::INVALID_ARGUMENT);
    }

    it->second.locked = true;
    return VoidResult::success();
  }

  VoidResult unlockWallet(uint32_t wallet_id, const std::string& /*passphrase*/) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return VoidResult::fail(Error::INVALID_ARGUMENT);
    }

    // In a real implementation, verify passphrase hash
    it->second.locked = false;
    return VoidResult::success();
  }

  bool isWalletLocked(uint32_t wallet_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return true;  // Non-existent wallets are considered locked
    }

    return it->second.locked;
  }

  // ----- Secure Operations -----

  void wipeAll() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [id, entry] : wallets_) {
      entry.wipe();
    }
    wallets_.clear();
  }

  void wipeCacheForWallet(uint32_t wallet_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it != wallets_.end()) {
      for (auto& [path, key] : it->second.key_cache) {
        key.wipe();
      }
      it->second.key_cache.clear();
    }
  }

  void wipeAllCaches() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [id, entry] : wallets_) {
      for (auto& [path, key] : entry.key_cache) {
        key.wipe();
      }
      entry.key_cache.clear();
    }
  }

  // ----- Export/Import -----

  Result<ByteVector> exportWalletEncrypted(
    uint32_t wallet_id,
    const Bytes32& /*encryption_key*/
  ) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = wallets_.find(wallet_id);
    if (it == wallets_.end()) {
      return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }

    // Placeholder - real implementation would encrypt the seed
    // using AES-256-GCM with the encryption key
    ByteVector encrypted;
    encrypted.reserve(it->second.seed.size() + 16 + 12);  // seed + tag + nonce

    // For now, just return a placeholder
    return Result<ByteVector>::success(std::move(encrypted));
  }

  Result<uint32_t> importWalletEncrypted(
    const ByteVector& /*encrypted_data*/,
    const Bytes32& /*encryption_key*/,
    const std::string& /*label*/
  ) {
    // Placeholder - real implementation would decrypt and add wallet
    return Result<uint32_t>::fail(Error::NOT_SUPPORTED);
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<uint32_t, WalletEntry> wallets_;
  uint32_t next_id_;

  /**
   * Internal key derivation with caching
   */
  Result<bip32::ExtendedKey> deriveKeyInternal(
    WalletEntry& entry,
    const std::string& path
  ) const {
    // Check cache first
    auto cache_it = entry.key_cache.find(path);
    if (cache_it != entry.key_cache.end()) {
      return Result<bip32::ExtendedKey>::success(cache_it->second.clone());
    }

    // Derive from master key
    auto result = entry.master_key.derivePath(path);
    if (!result.ok()) {
      return result;
    }

    // Cache the result
    entry.key_cache[path] = result.value.clone();

    return result;
  }
};

// =============================================================================
// Keyring Public Implementation
// =============================================================================

Keyring::Keyring() : impl_(std::make_unique<KeyringImpl>()) {}

Keyring::~Keyring() = default;

Keyring::Keyring(Keyring&& other) noexcept = default;
Keyring& Keyring::operator=(Keyring&& other) noexcept = default;

// ----- Wallet Management -----

Result<uint32_t> Keyring::addWallet(const Bytes64& seed, const std::string& label) {
  return impl_->addWallet(seed, label);
}

Result<uint32_t> Keyring::addWallet(const ByteVector& seed, const std::string& label) {
  return impl_->addWallet(seed, label);
}

Result<uint32_t> Keyring::addWalletFromMnemonic(
  const std::string& mnemonic,
  const std::string& passphrase,
  const std::string& label
) {
  // Validate mnemonic first
  Error err = bip39::validateMnemonic(mnemonic);
  if (err != Error::OK) {
    return Result<uint32_t>::fail(err);
  }

  // Convert to seed
  auto seed_result = bip39::mnemonicToSeed(mnemonic, passphrase);
  if (!seed_result.ok()) {
    return Result<uint32_t>::fail(seed_result.error);
  }

  // Add wallet
  auto result = impl_->addWallet(seed_result.value, label);

  // Securely wipe the seed
  secureWipe(seed_result.value);

  return result;
}

VoidResult Keyring::removeWallet(uint32_t wallet_id) {
  return impl_->removeWallet(wallet_id);
}

Result<WalletInfo> Keyring::getWalletInfo(uint32_t wallet_id) const {
  return impl_->getWalletInfo(wallet_id);
}

std::vector<WalletInfo> Keyring::listWallets() const {
  return impl_->listWallets();
}

size_t Keyring::walletCount() const {
  return impl_->walletCount();
}

bool Keyring::hasWallet(uint32_t wallet_id) const {
  return impl_->hasWallet(wallet_id);
}

VoidResult Keyring::setWalletLabel(uint32_t wallet_id, const std::string& label) {
  return impl_->setWalletLabel(wallet_id, label);
}

// ----- Account Derivation -----

Result<AccountInfo> Keyring::deriveAccount(
  uint32_t wallet_id,
  CoinType coin_type,
  uint32_t account
) {
  return impl_->deriveAccount(wallet_id, 44, coin_type, account);
}

Result<AccountInfo> Keyring::deriveAccountWithPurpose(
  uint32_t wallet_id,
  uint32_t purpose,
  CoinType coin_type,
  uint32_t account
) {
  return impl_->deriveAccount(wallet_id, purpose, coin_type, account);
}

Result<std::string> Keyring::getXpub(uint32_t wallet_id, const std::string& path) const {
  return impl_->getXpub(wallet_id, path);
}

Result<Bytes33> Keyring::getPublicKey(uint32_t wallet_id, const std::string& path) const {
  return impl_->getPublicKey(wallet_id, path);
}

// ----- Transaction Signing -----

Result<SignatureResult> Keyring::signTransaction(
  uint32_t wallet_id,
  const std::string& path,
  const Bytes32& hash
) {
  return impl_->signHash(wallet_id, path, hash);
}

Result<SignatureResult> Keyring::signTransaction(
  uint32_t wallet_id,
  const std::string& path,
  const ByteVector& hash
) {
  if (hash.size() != 32) {
    return Result<SignatureResult>::fail(Error::INVALID_ARGUMENT);
  }
  Bytes32 hash32;
  std::copy(hash.begin(), hash.end(), hash32.begin());
  return signTransaction(wallet_id, path, hash32);
}

// ----- Message Signing -----

Result<SignatureResult> Keyring::signPersonalMessage(
  uint32_t wallet_id,
  const std::string& path,
  const std::string& message
) {
  // Ethereum personal_sign prefix
  std::string prefix = "\x19" "Ethereum Signed Message:\n" +
                       std::to_string(message.size());

  // Create message to hash
  ByteVector to_hash;
  to_hash.reserve(prefix.size() + message.size());
  to_hash.insert(to_hash.end(), prefix.begin(), prefix.end());
  to_hash.insert(to_hash.end(), message.begin(), message.end());

  return signMessage(wallet_id, path, to_hash);
}

Result<SignatureResult> Keyring::signMessage(
  uint32_t wallet_id,
  const std::string& path,
  const ByteVector& data
) {
  // Hash the data (keccak256 for Ethereum, sha256 for others)
  // Placeholder: in real implementation, hash based on coin type
  Bytes32 hash{};

  // For now, use first 32 bytes or pad with zeros
  size_t copy_len = std::min(data.size(), size_t(32));
  std::copy(data.begin(), data.begin() + copy_len, hash.begin());

  return signHash(wallet_id, path, hash);
}

Result<SignatureResult> Keyring::signHash(
  uint32_t wallet_id,
  const std::string& path,
  const Bytes32& hash
) {
  return impl_->signHash(wallet_id, path, hash);
}

// ----- Wallet Locking -----

VoidResult Keyring::lockWallet(uint32_t wallet_id) {
  return impl_->lockWallet(wallet_id);
}

VoidResult Keyring::unlockWallet(uint32_t wallet_id, const std::string& passphrase) {
  return impl_->unlockWallet(wallet_id, passphrase);
}

bool Keyring::isWalletLocked(uint32_t wallet_id) const {
  return impl_->isWalletLocked(wallet_id);
}

// ----- Secure Operations -----

void Keyring::wipeAll() {
  impl_->wipeAll();
}

void Keyring::wipeCacheForWallet(uint32_t wallet_id) {
  impl_->wipeCacheForWallet(wallet_id);
}

void Keyring::wipeAllCaches() {
  impl_->wipeAllCaches();
}

// ----- Serialization -----

Result<ByteVector> Keyring::exportWalletEncrypted(
  uint32_t wallet_id,
  const Bytes32& encryption_key
) const {
  return impl_->exportWalletEncrypted(wallet_id, encryption_key);
}

Result<uint32_t> Keyring::importWalletEncrypted(
  const ByteVector& encrypted_data,
  const Bytes32& encryption_key,
  const std::string& label
) {
  return impl_->importWalletEncrypted(encrypted_data, encryption_key, label);
}

// =============================================================================
// C API Implementation
// =============================================================================

struct hd_keyring_t {
  Keyring keyring;
};

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_keyring_handle hd_keyring_create() {
  try {
    return new hd_keyring_t();
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_destroy(hd_keyring_handle keyring) {
  if (keyring) {
    keyring->keyring.wipeAll();
    delete keyring;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_add_wallet(
  hd_keyring_handle keyring,
  const uint8_t* seed,
  size_t seed_size,
  const char* label
) {
  if (!keyring || !seed || seed_size != 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes64 seed64;
  std::copy(seed, seed + 64, seed64.begin());

  auto result = keyring->keyring.addWallet(
    seed64,
    label ? std::string(label) : ""
  );

  secureWipe(seed64);

  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
  return static_cast<int32_t>(result.value);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_add_wallet_from_mnemonic(
  hd_keyring_handle keyring,
  const char* mnemonic,
  const char* passphrase,
  const char* label
) {
  if (!keyring || !mnemonic) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = keyring->keyring.addWalletFromMnemonic(
    std::string(mnemonic),
    passphrase ? std::string(passphrase) : "",
    label ? std::string(label) : ""
  );

  if (!result.ok()) {
    return -static_cast<int32_t>(result.error);
  }
  return static_cast<int32_t>(result.value);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_remove_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
) {
  if (!keyring) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = keyring->keyring.removeWallet(wallet_id);
  return static_cast<int32_t>(result.error);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_wallet_count(hd_keyring_handle keyring) {
  if (!keyring) {
    return 0;
  }
  return static_cast<int32_t>(keyring->keyring.walletCount());
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_has_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
) {
  if (!keyring) {
    return 0;
  }
  return keyring->keyring.hasWallet(wallet_id) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_get_xpub(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  char* xpub_out,
  size_t xpub_size
) {
  if (!keyring || !path || !xpub_out || xpub_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = keyring->keyring.getXpub(wallet_id, std::string(path));
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.size() >= xpub_size) {
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(result.value.begin(), result.value.end(), xpub_out);
  xpub_out[result.value.size()] = '\0';

  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_get_public_key(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* path,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!keyring || !path || !pubkey_out || pubkey_size < 33) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = keyring->keyring.getPublicKey(wallet_id, std::string(path));
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

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
) {
  if (!keyring || !path || !hash || hash_size != 32 || !sig_out || sig_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 hash32;
  std::copy(hash, hash + 32, hash32.begin());

  auto result = keyring->keyring.signHash(wallet_id, std::string(path), hash32);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  size_t copy_len = std::min(result.value.signature.size(), sig_size);
  std::copy(result.value.signature.begin(),
            result.value.signature.begin() + copy_len,
            sig_out);

  if (recovery_id_out) {
    *recovery_id_out = result.value.recovery_id;
  }

  return static_cast<int32_t>(copy_len);
}

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
) {
  if (!keyring || !path || !message || !sig_out || sig_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector msg(message, message + message_size);
  auto result = keyring->keyring.signMessage(wallet_id, std::string(path), msg);

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  size_t copy_len = std::min(result.value.signature.size(), sig_size);
  std::copy(result.value.signature.begin(),
            result.value.signature.begin() + copy_len,
            sig_out);

  if (recovery_id_out) {
    *recovery_id_out = result.value.recovery_id;
  }

  return static_cast<int32_t>(copy_len);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_lock_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id
) {
  if (!keyring) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  auto result = keyring->keyring.lockWallet(wallet_id);
  return static_cast<int32_t>(result.error);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_unlock_wallet(
  hd_keyring_handle keyring,
  uint32_t wallet_id,
  const char* passphrase
) {
  if (!keyring) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  auto result = keyring->keyring.unlockWallet(
    wallet_id,
    passphrase ? std::string(passphrase) : ""
  );
  return static_cast<int32_t>(result.error);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_keyring_is_wallet_locked(
  hd_keyring_handle keyring,
  uint32_t wallet_id
) {
  if (!keyring) {
    return 1;  // Non-existent keyring means locked
  }
  return keyring->keyring.isWalletLocked(wallet_id) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_wipe_all(hd_keyring_handle keyring) {
  if (keyring) {
    keyring->keyring.wipeAll();
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_keyring_wipe_cache(
  hd_keyring_handle keyring,
  uint32_t wallet_id
) {
  if (keyring) {
    keyring->keyring.wipeCacheForWallet(wallet_id);
  }
}

} // namespace hd_wallet
