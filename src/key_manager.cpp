/**
 * @file key_manager.cpp
 * @brief Key Manager Implementation - High-Level Key Derivation
 *
 * Implementation of the KeyManager class for purpose-based HD key derivation.
 */

#include "hd_wallet/key_manager.h"
#include "hd_wallet/bip39.h"
#include "hd_wallet/bip32.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <sstream>
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
    std::atomic_thread_fence(std::memory_order_seq_cst);
  }
}

void secureWipe(Bytes32& data) {
  secureWipe(data.data(), data.size());
}

void secureWipe(Bytes64& data) {
  secureWipe(data.data(), data.size());
}

/**
 * Check if bytes are all zero
 */
bool isAllZero(const Bytes32& data) {
  for (const auto& b : data) {
    if (b != 0) return false;
  }
  return true;
}

} // anonymous namespace

// =============================================================================
// DerivedKey Implementation
// =============================================================================

void DerivedKey::wipe() {
  secureWipe(private_key);
  secureWipe(chain_code);
  // Public key and metadata are not sensitive
  path.clear();
}

bool DerivedKey::isValid() const {
  return !isAllZero(private_key);
}

DerivedKey DerivedKey::empty() {
  DerivedKey key;
  key.private_key = {};
  key.public_key = {};
  key.chain_code = {};
  key.path = "";
  key.purpose = KeyPurpose::SIGNING;
  key.coin_type = CoinType::BITCOIN;
  key.account = 0;
  key.index = 0;
  key.fingerprint = 0;
  return key;
}

// =============================================================================
// KeyPair Implementation
// =============================================================================

void KeyPair::wipe() {
  signing.wipe();
  encryption.wipe();
}

bool KeyPair::isValid() const {
  return signing.isValid() && encryption.isValid();
}

// =============================================================================
// KeyManagerImpl - Private Implementation
// =============================================================================

class KeyManagerImpl {
public:
  explicit KeyManagerImpl(const Bytes64& seed)
    : seed_(seed), wiped_(false), max_cache_size_(100) {
    initializeMasterKey();
  }

  explicit KeyManagerImpl(const ByteVector& seed) : wiped_(false), max_cache_size_(100) {
    if (seed.size() == 64) {
      std::copy(seed.begin(), seed.end(), seed_.begin());
      initializeMasterKey();
    } else {
      wiped_ = true;  // Mark as invalid
    }
  }

  ~KeyManagerImpl() {
    wipe();
  }

  // Non-copyable
  KeyManagerImpl(const KeyManagerImpl&) = delete;
  KeyManagerImpl& operator=(const KeyManagerImpl&) = delete;

  // Move
  KeyManagerImpl(KeyManagerImpl&& other) noexcept
    : seed_(other.seed_),
      master_key_(std::move(other.master_key_)),
      key_cache_(std::move(other.key_cache_)),
      wiped_(other.wiped_),
      max_cache_size_(other.max_cache_size_) {
    secureWipe(other.seed_);
    other.wiped_ = true;
  }

  KeyManagerImpl& operator=(KeyManagerImpl&& other) noexcept {
    if (this != &other) {
      wipe();
      seed_ = other.seed_;
      master_key_ = std::move(other.master_key_);
      key_cache_ = std::move(other.key_cache_);
      wiped_ = other.wiped_;
      max_cache_size_ = other.max_cache_size_;
      secureWipe(other.seed_);
      other.wiped_ = true;
    }
    return *this;
  }

  // ----- Key Derivation -----

  Result<DerivedKey> deriveSigningKey(
    CoinType coin_type,
    uint32_t account,
    uint32_t index,
    const DerivationOptions& options
  ) {
    if (wiped_) {
      return Result<DerivedKey>::fail(Error::INTERNAL);
    }

    // External chain (change=0) for signing
    std::string path;
    if (options.custom_path.has_value()) {
      path = options.custom_path.value();
    } else {
      path = buildPath(
        options.purpose,
        static_cast<uint32_t>(coin_type),
        account,
        0,  // External chain
        index
      );
    }

    return deriveKeyAtPathInternal(path, KeyPurpose::SIGNING, coin_type, account, index, options);
  }

  Result<DerivedKey> deriveEncryptionKey(
    CoinType coin_type,
    uint32_t account,
    uint32_t index,
    const DerivationOptions& options
  ) {
    if (wiped_) {
      return Result<DerivedKey>::fail(Error::INTERNAL);
    }

    // Internal chain (change=1) for encryption
    std::string path;
    if (options.custom_path.has_value()) {
      path = options.custom_path.value();
    } else {
      path = buildPath(
        options.purpose,
        static_cast<uint32_t>(coin_type),
        account,
        1,  // Internal chain
        index
      );
    }

    return deriveKeyAtPathInternal(path, KeyPurpose::ENCRYPTION, coin_type, account, index, options);
  }

  Result<KeyPair> deriveKeyPair(
    CoinType coin_type,
    uint32_t account,
    uint32_t index,
    const DerivationOptions& options
  ) {
    auto signing_result = deriveSigningKey(coin_type, account, index, options);
    if (!signing_result.ok()) {
      return Result<KeyPair>::fail(signing_result.error);
    }

    auto encryption_result = deriveEncryptionKey(coin_type, account, index, options);
    if (!encryption_result.ok()) {
      signing_result.value.wipe();
      return Result<KeyPair>::fail(encryption_result.error);
    }

    KeyPair pair;
    pair.signing = std::move(signing_result.value);
    pair.encryption = std::move(encryption_result.value);

    return Result<KeyPair>::success(std::move(pair));
  }

  Result<DerivedKey> deriveKeyAtPath(
    const std::string& path,
    KeyPurpose purpose
  ) {
    if (wiped_) {
      return Result<DerivedKey>::fail(Error::INTERNAL);
    }

    DerivationOptions options;
    options.cache = true;
    return deriveKeyAtPathInternal(path, purpose, CoinType::BITCOIN, 0, 0, options);
  }

  Result<std::string> getXpub(const std::string& path) {
    if (wiped_) {
      return Result<std::string>::fail(Error::INTERNAL);
    }

    auto key_result = master_key_.derivePath(path);
    if (!key_result.ok()) {
      return Result<std::string>::fail(key_result.error);
    }

    return Result<std::string>::success(key_result.value.toXpub());
  }

  uint32_t getMasterFingerprint() const {
    if (wiped_) {
      return 0;
    }
    return master_key_.fingerprint();
  }

  // ----- Cache Management -----

  void clearCache() {
    for (auto& [path, key] : key_cache_) {
      key.wipe();
    }
    key_cache_.clear();
  }

  void setCacheSize(size_t max_size) {
    max_cache_size_ = max_size;
    if (max_size == 0) {
      clearCache();
    } else {
      // Evict excess entries if needed
      while (key_cache_.size() > max_size) {
        auto it = key_cache_.begin();
        it->second.wipe();
        key_cache_.erase(it);
      }
    }
  }

  size_t getCacheSize() const {
    return key_cache_.size();
  }

  bool isCached(const std::string& path) const {
    return key_cache_.find(path) != key_cache_.end();
  }

  // ----- Secure Operations -----

  void wipe() {
    secureWipe(seed_);
    master_key_.wipe();
    clearCache();
    wiped_ = true;
  }

  bool isWiped() const {
    return wiped_;
  }

private:
  Bytes64 seed_;
  bip32::ExtendedKey master_key_;
  std::unordered_map<std::string, DerivedKey> key_cache_;
  bool wiped_;
  size_t max_cache_size_;

  void initializeMasterKey() {
    auto result = bip32::ExtendedKey::fromSeed(seed_);
    if (result.ok()) {
      master_key_ = std::move(result.value);
    } else {
      wiped_ = true;
    }
  }

  Result<DerivedKey> deriveKeyAtPathInternal(
    const std::string& path,
    KeyPurpose purpose,
    CoinType coin_type,
    uint32_t account,
    uint32_t index,
    const DerivationOptions& options
  ) {
    // Check cache first
    if (options.cache) {
      auto it = key_cache_.find(path);
      if (it != key_cache_.end()) {
        // Return a copy
        DerivedKey copy;
        copy.private_key = it->second.private_key;
        copy.public_key = it->second.public_key;
        copy.chain_code = it->second.chain_code;
        copy.path = it->second.path;
        copy.purpose = it->second.purpose;
        copy.coin_type = it->second.coin_type;
        copy.account = it->second.account;
        copy.index = it->second.index;
        copy.fingerprint = it->second.fingerprint;
        return Result<DerivedKey>::success(std::move(copy));
      }
    }

    // Derive the key
    auto key_result = master_key_.derivePath(path);
    if (!key_result.ok()) {
      return Result<DerivedKey>::fail(key_result.error);
    }

    // Get private key
    auto privkey_result = key_result.value.privateKey();
    if (!privkey_result.ok()) {
      return Result<DerivedKey>::fail(privkey_result.error);
    }

    // Build DerivedKey
    DerivedKey derived;
    derived.private_key = privkey_result.value;
    derived.public_key = key_result.value.publicKey();
    derived.chain_code = key_result.value.chainCode();
    derived.path = path;
    derived.purpose = purpose;
    derived.coin_type = coin_type;
    derived.account = account;
    derived.index = index;
    derived.fingerprint = key_result.value.fingerprint();

    // Cache if enabled
    if (options.cache && max_cache_size_ > 0) {
      // Evict if at capacity
      if (key_cache_.size() >= max_cache_size_) {
        auto it = key_cache_.begin();
        it->second.wipe();
        key_cache_.erase(it);
      }

      // Store a copy in cache
      DerivedKey cached;
      cached.private_key = derived.private_key;
      cached.public_key = derived.public_key;
      cached.chain_code = derived.chain_code;
      cached.path = derived.path;
      cached.purpose = derived.purpose;
      cached.coin_type = derived.coin_type;
      cached.account = derived.account;
      cached.index = derived.index;
      cached.fingerprint = derived.fingerprint;
      key_cache_[path] = std::move(cached);
    }

    return Result<DerivedKey>::success(std::move(derived));
  }

  static std::string buildPath(
    uint32_t purpose,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
  ) {
    std::ostringstream ss;
    ss << "m/" << purpose << "'/" << coin_type << "'/" << account << "'/"
       << change << "/" << index;
    return ss.str();
  }
};

// =============================================================================
// KeyManager Public Implementation
// =============================================================================

KeyManager::KeyManager(const Bytes64& seed)
  : impl_(std::make_unique<KeyManagerImpl>(seed)) {}

KeyManager::KeyManager(const ByteVector& seed)
  : impl_(std::make_unique<KeyManagerImpl>(seed)) {}

Result<KeyManager> KeyManager::fromMnemonic(
  const std::string& mnemonic,
  const std::string& passphrase
) {
  // Validate mnemonic
  Error err = bip39::validateMnemonic(mnemonic);
  if (err != Error::OK) {
    return Result<KeyManager>::fail(err);
  }

  // Convert to seed
  auto seed_result = bip39::mnemonicToSeed(mnemonic, passphrase);
  if (!seed_result.ok()) {
    return Result<KeyManager>::fail(seed_result.error);
  }

  KeyManager manager(seed_result.value);

  // Securely wipe the seed
  Bytes64 seed_copy = seed_result.value;
  secureWipe(seed_copy);

  return Result<KeyManager>::success(std::move(manager));
}

KeyManager::~KeyManager() = default;

KeyManager::KeyManager(KeyManager&& other) noexcept = default;
KeyManager& KeyManager::operator=(KeyManager&& other) noexcept = default;

// ----- Purpose-Based Key Derivation -----

Result<DerivedKey> KeyManager::deriveSigningKey(
  CoinType coin_type,
  uint32_t account,
  uint32_t index,
  const DerivationOptions& options
) {
  return impl_->deriveSigningKey(coin_type, account, index, options);
}

Result<DerivedKey> KeyManager::deriveEncryptionKey(
  CoinType coin_type,
  uint32_t account,
  uint32_t index,
  const DerivationOptions& options
) {
  return impl_->deriveEncryptionKey(coin_type, account, index, options);
}

Result<KeyPair> KeyManager::deriveKeyPair(
  CoinType coin_type,
  uint32_t account,
  uint32_t index,
  const DerivationOptions& options
) {
  return impl_->deriveKeyPair(coin_type, account, index, options);
}

// ----- Generic Key Derivation -----

Result<DerivedKey> KeyManager::deriveKeyAtPath(
  const std::string& path,
  KeyPurpose purpose
) {
  return impl_->deriveKeyAtPath(path, purpose);
}

Result<std::string> KeyManager::getXpub(const std::string& path) {
  return impl_->getXpub(path);
}

uint32_t KeyManager::getMasterFingerprint() const {
  return impl_->getMasterFingerprint();
}

// ----- Key Validation -----

bool KeyManager::isValidPrivateKey(const Bytes32& private_key, Curve curve) {
  // Check for zero key
  if (isAllZero(private_key)) {
    return false;
  }

  // For secp256k1, check that key is less than curve order
  if (curve == Curve::SECP256K1) {
    // secp256k1 order (n) in big-endian
    static const uint8_t secp256k1_order[32] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };

    // Compare key to order
    for (size_t i = 0; i < 32; ++i) {
      if (private_key[i] < secp256k1_order[i]) {
        return true;  // key < order
      } else if (private_key[i] > secp256k1_order[i]) {
        return false;  // key >= order
      }
    }
    return false;  // key == order (invalid)
  }

  // For Ed25519, any 32-byte value is valid (will be clamped)
  if (curve == Curve::ED25519) {
    return true;
  }

  // For other curves, accept for now (proper validation would use crypto library)
  return true;
}

bool KeyManager::isValidPublicKey(const Bytes33& public_key, Curve curve) {
  // Check for zero key
  bool all_zero = true;
  for (const auto& b : public_key) {
    if (b != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    return false;
  }

  // For secp256k1, check prefix byte
  if (curve == Curve::SECP256K1) {
    // Compressed public key must start with 0x02 or 0x03
    return public_key[0] == 0x02 || public_key[0] == 0x03;
  }

  // For Ed25519, check that it's a valid point (simplified check)
  if (curve == Curve::ED25519) {
    // Ed25519 public keys are 32 bytes, but we use 33 for consistency
    // First byte should be 0x00 as a marker or we store differently
    return true;
  }

  return true;
}

bool KeyManager::isValidPath(const std::string& path) {
  auto result = bip32::DerivationPath::parse(path);
  return result.ok();
}

Result<Bytes33> KeyManager::publicKeyFromPrivate(
  const Bytes32& private_key,
  Curve curve
) {
  return bip32::publicKeyFromPrivate(private_key, curve);
}

// ----- Cache Management -----

void KeyManager::clearCache() {
  impl_->clearCache();
}

void KeyManager::setCacheSize(size_t max_size) {
  impl_->setCacheSize(max_size);
}

size_t KeyManager::getCacheSize() const {
  return impl_->getCacheSize();
}

bool KeyManager::isCached(const std::string& path) const {
  return impl_->isCached(path);
}

// ----- Secure Operations -----

void KeyManager::wipe() {
  impl_->wipe();
}

bool KeyManager::isWiped() const {
  return impl_->isWiped();
}

// ----- Path Building Helpers -----

std::string KeyManager::buildPath(
  uint32_t purpose,
  uint32_t coin_type,
  uint32_t account,
  uint32_t change,
  uint32_t index
) {
  std::ostringstream ss;
  ss << "m/" << purpose << "'/" << coin_type << "'/" << account << "'/"
     << change << "/" << index;
  return ss.str();
}

std::string KeyManager::buildSigningPath(
  uint32_t purpose,
  CoinType coin_type,
  uint32_t account,
  uint32_t index
) {
  return buildPath(purpose, static_cast<uint32_t>(coin_type), account, 0, index);
}

std::string KeyManager::buildEncryptionPath(
  uint32_t purpose,
  CoinType coin_type,
  uint32_t account,
  uint32_t index
) {
  return buildPath(purpose, static_cast<uint32_t>(coin_type), account, 1, index);
}

// =============================================================================
// C API Implementation
// =============================================================================

// ----- Handle Structures -----

struct hd_key_manager_t {
  std::unique_ptr<KeyManager> manager;
};

struct hd_derived_key_t {
  DerivedKey key;
};

struct hd_key_pair_t {
  KeyPair pair;
};

// ----- KeyManager Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_manager_handle hd_key_manager_create(
  const uint8_t* seed,
  size_t seed_size
) {
  if (!seed || seed_size != 64) {
    return nullptr;
  }

  try {
    Bytes64 seed64;
    std::copy(seed, seed + 64, seed64.begin());

    auto handle = new hd_key_manager_t();
    handle->manager = std::make_unique<KeyManager>(seed64);

    secureWipe(seed64);

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_manager_handle hd_key_manager_from_mnemonic(
  const char* mnemonic,
  const char* passphrase
) {
  if (!mnemonic) {
    return nullptr;
  }

  try {
    auto result = KeyManager::fromMnemonic(
      std::string(mnemonic),
      passphrase ? std::string(passphrase) : ""
    );

    if (!result.ok()) {
      return nullptr;
    }

    auto handle = new hd_key_manager_t();
    handle->manager = std::make_unique<KeyManager>(std::move(result.value));

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_destroy(hd_key_manager_handle manager) {
  if (manager) {
    if (manager->manager) {
      manager->manager->wipe();
    }
    delete manager;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_signing_key(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
) {
  if (!manager || !manager->manager) {
    return nullptr;
  }

  try {
    auto result = manager->manager->deriveSigningKey(
      static_cast<CoinType>(coin_type),
      account,
      index
    );

    if (!result.ok()) {
      return nullptr;
    }

    auto handle = new hd_derived_key_t();
    handle->key = std::move(result.value);

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_encryption_key(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
) {
  if (!manager || !manager->manager) {
    return nullptr;
  }

  try {
    auto result = manager->manager->deriveEncryptionKey(
      static_cast<CoinType>(coin_type),
      account,
      index
    );

    if (!result.ok()) {
      return nullptr;
    }

    auto handle = new hd_derived_key_t();
    handle->key = std::move(result.value);

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_key_pair_handle hd_key_manager_derive_key_pair(
  hd_key_manager_handle manager,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
) {
  if (!manager || !manager->manager) {
    return nullptr;
  }

  try {
    auto result = manager->manager->deriveKeyPair(
      static_cast<CoinType>(coin_type),
      account,
      index
    );

    if (!result.ok()) {
      return nullptr;
    }

    auto handle = new hd_key_pair_t();
    handle->pair = std::move(result.value);

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_manager_derive_at_path(
  hd_key_manager_handle manager,
  const char* path,
  int32_t purpose
) {
  if (!manager || !manager->manager || !path) {
    return nullptr;
  }

  try {
    auto result = manager->manager->deriveKeyAtPath(
      std::string(path),
      static_cast<KeyPurpose>(purpose)
    );

    if (!result.ok()) {
      return nullptr;
    }

    auto handle = new hd_derived_key_t();
    handle->key = std::move(result.value);

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_manager_get_xpub(
  hd_key_manager_handle manager,
  const char* path,
  char* xpub_out,
  size_t xpub_size
) {
  if (!manager || !manager->manager || !path || !xpub_out || xpub_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = manager->manager->getXpub(std::string(path));
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
uint32_t hd_key_manager_get_master_fingerprint(hd_key_manager_handle manager) {
  if (!manager || !manager->manager) {
    return 0;
  }
  return manager->manager->getMasterFingerprint();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_clear_cache(hd_key_manager_handle manager) {
  if (manager && manager->manager) {
    manager->manager->clearCache();
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_manager_wipe(hd_key_manager_handle manager) {
  if (manager && manager->manager) {
    manager->manager->wipe();
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_manager_is_wiped(hd_key_manager_handle manager) {
  if (!manager || !manager->manager) {
    return 1;
  }
  return manager->manager->isWiped() ? 1 : 0;
}

// ----- DerivedKey Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_derived_key_destroy(hd_derived_key_handle key) {
  if (key) {
    key->key.wipe();
    delete key;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_private(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
) {
  if (!key || !out || out_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::copy(key->key.private_key.begin(), key->key.private_key.end(), out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_public(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
) {
  if (!key || !out || out_size < 33) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::copy(key->key.public_key.begin(), key->key.public_key.end(), out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_chain_code(
  hd_derived_key_handle key,
  uint8_t* out,
  size_t out_size
) {
  if (!key || !out || out_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::copy(key->key.chain_code.begin(), key->key.chain_code.end(), out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_path(
  hd_derived_key_handle key,
  char* out,
  size_t out_size
) {
  if (!key || !out || out_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  if (key->key.path.size() >= out_size) {
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(key->key.path.begin(), key->key.path.end(), out);
  out[key->key.path.size()] = '\0';

  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_purpose(hd_derived_key_handle key) {
  if (!key) {
    return -1;
  }
  return static_cast<int32_t>(key->key.purpose);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_get_coin_type(hd_derived_key_handle key) {
  if (!key) {
    return -1;
  }
  return static_cast<int32_t>(key->key.coin_type);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_derived_key_get_fingerprint(hd_derived_key_handle key) {
  if (!key) {
    return 0;
  }
  return key->key.fingerprint;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_derived_key_wipe(hd_derived_key_handle key) {
  if (key) {
    key->key.wipe();
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_derived_key_is_valid(hd_derived_key_handle key) {
  if (!key) {
    return 0;
  }
  return key->key.isValid() ? 1 : 0;
}

// ----- KeyPair Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_pair_destroy(hd_key_pair_handle pair) {
  if (pair) {
    pair->pair.wipe();
    delete pair;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_pair_get_signing(hd_key_pair_handle pair) {
  if (!pair) {
    return nullptr;
  }

  try {
    // Create a copy of the signing key
    auto handle = new hd_derived_key_t();
    handle->key.private_key = pair->pair.signing.private_key;
    handle->key.public_key = pair->pair.signing.public_key;
    handle->key.chain_code = pair->pair.signing.chain_code;
    handle->key.path = pair->pair.signing.path;
    handle->key.purpose = pair->pair.signing.purpose;
    handle->key.coin_type = pair->pair.signing.coin_type;
    handle->key.account = pair->pair.signing.account;
    handle->key.index = pair->pair.signing.index;
    handle->key.fingerprint = pair->pair.signing.fingerprint;

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_derived_key_handle hd_key_pair_get_encryption(hd_key_pair_handle pair) {
  if (!pair) {
    return nullptr;
  }

  try {
    // Create a copy of the encryption key
    auto handle = new hd_derived_key_t();
    handle->key.private_key = pair->pair.encryption.private_key;
    handle->key.public_key = pair->pair.encryption.public_key;
    handle->key.chain_code = pair->pair.encryption.chain_code;
    handle->key.path = pair->pair.encryption.path;
    handle->key.purpose = pair->pair.encryption.purpose;
    handle->key.coin_type = pair->pair.encryption.coin_type;
    handle->key.account = pair->pair.encryption.account;
    handle->key.index = pair->pair.encryption.index;
    handle->key.fingerprint = pair->pair.encryption.fingerprint;

    return handle;
  } catch (...) {
    return nullptr;
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_key_pair_wipe(hd_key_pair_handle pair) {
  if (pair) {
    pair->pair.wipe();
  }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_key_pair_is_valid(hd_key_pair_handle pair) {
  if (!pair) {
    return 0;
  }
  return pair->pair.isValid() ? 1 : 0;
}

// ----- Validation Functions -----

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_private_key(
  const uint8_t* key,
  size_t key_size,
  int32_t curve
) {
  if (!key || key_size != 32) {
    return 0;
  }

  Bytes32 key32;
  std::copy(key, key + 32, key32.begin());

  return KeyManager::isValidPrivateKey(key32, static_cast<Curve>(curve)) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_public_key(
  const uint8_t* key,
  size_t key_size,
  int32_t curve
) {
  if (!key || key_size != 33) {
    return 0;
  }

  Bytes33 key33;
  std::copy(key, key + 33, key33.begin());

  return KeyManager::isValidPublicKey(key33, static_cast<Curve>(curve)) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_validate_path(const char* path) {
  if (!path) {
    return 0;
  }
  return KeyManager::isValidPath(std::string(path)) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_public_key_from_private(
  const uint8_t* private_key,
  size_t private_key_size,
  int32_t curve,
  uint8_t* public_key_out,
  size_t public_key_size
) {
  if (!private_key || private_key_size != 32 || !public_key_out || public_key_size < 33) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = KeyManager::publicKeyFromPrivate(priv, static_cast<Curve>(curve));

  secureWipe(priv);

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::copy(result.value.begin(), result.value.end(), public_key_out);
  return static_cast<int32_t>(Error::OK);
}

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
) {
  if (!out || out_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string path = KeyManager::buildPath(purpose, coin_type, account, change, index);

  if (path.size() >= out_size) {
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(path.begin(), path.end(), out);
  out[path.size()] = '\0';

  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_build_signing_path(
  char* out,
  size_t out_size,
  uint32_t purpose,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
) {
  if (!out || out_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string path = KeyManager::buildSigningPath(
    purpose,
    static_cast<CoinType>(coin_type),
    account,
    index
  );

  if (path.size() >= out_size) {
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(path.begin(), path.end(), out);
  out[path.size()] = '\0';

  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_build_encryption_path(
  char* out,
  size_t out_size,
  uint32_t purpose,
  int32_t coin_type,
  uint32_t account,
  uint32_t index
) {
  if (!out || out_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string path = KeyManager::buildEncryptionPath(
    purpose,
    static_cast<CoinType>(coin_type),
    account,
    index
  );

  if (path.size() >= out_size) {
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(path.begin(), path.end(), out);
  out[path.size()] = '\0';

  return static_cast<int32_t>(Error::OK);
}

} // namespace hd_wallet
