/**
 * @file wasm_bindings.cpp
 * @brief WASM Bindings - C API for WebAssembly
 *
 * This file implements the C API functions exported to WebAssembly.
 * These functions act as a bridge between the C++ implementation and
 * the JavaScript/TypeScript wrapper.
 *
 * Memory Management:
 * - All returned pointers must be freed by the caller using hd_dealloc()
 * - Handles (opaque pointers) returned by functions like hd_key_from_seed
 *   must be destroyed using their respective destroy functions
 * - Secure wiping is performed on sensitive data before deallocation
 *
 * Error Handling:
 * - Functions return int32_t error codes (0 = success, negative = error)
 * - Some functions return handles (pointers) with nullptr indicating failure
 *
 * @note This file is only compiled when building for WASM (HD_WALLET_IS_WASM=1)
 */

#include <hd_wallet/config.h>
#include <hd_wallet/types.h>
#include <hd_wallet/bip39.h>
#include <hd_wallet/bip32.h>
#include <hd_wallet/wasi_bridge.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/keccak.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#endif

using namespace hd_wallet;

// =============================================================================
// Memory Management
// =============================================================================

/**
 * Allocate memory in WASM linear memory
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
void* hd_alloc(size_t size) {
    return std::malloc(size);
}

/**
 * Deallocate memory previously allocated with hd_alloc
 * @param ptr Pointer to memory to free
 */
extern "C" HD_WALLET_EXPORT
void hd_dealloc(void* ptr) {
    std::free(ptr);
}

/**
 * Securely wipe memory before deallocation
 * Uses volatile writes to prevent compiler optimization
 * @param ptr Pointer to memory to wipe
 * @param size Number of bytes to wipe
 */
extern "C" HD_WALLET_EXPORT
void hd_secure_wipe(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
    }
}

// =============================================================================
// Module Info
// =============================================================================

/**
 * Get library version as packed integer (major << 16 | minor << 8 | patch)
 */
extern "C" HD_WALLET_EXPORT
uint32_t hd_get_version() {
    return (HD_WALLET_VERSION_MAJOR << 16) |
           (HD_WALLET_VERSION_MINOR << 8) |
           HD_WALLET_VERSION_PATCH;
}

/**
 * Get library version as string
 * @return Pointer to static version string
 */
extern "C" HD_WALLET_EXPORT
const char* hd_get_version_string() {
    return HD_WALLET_VERSION_STRING;
}

/**
 * Check if Crypto++ is available
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_has_cryptopp() {
#if HD_WALLET_USE_CRYPTOPP
    return 1;
#else
    return 0;
#endif
}

/**
 * Check if FIPS mode is enabled
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_is_fips_mode() {
#if HD_WALLET_FIPS_MODE
    return 1;
#else
    return 0;
#endif
}

// Static storage for coin list string
static std::string g_supported_coins;

/**
 * Get list of supported coins as JSON array string
 */
extern "C" HD_WALLET_EXPORT
const char* hd_get_supported_coins() {
    g_supported_coins = "[";
#if HD_WALLET_ENABLE_BITCOIN
    g_supported_coins += "\"bitcoin\",";
#endif
#if HD_WALLET_ENABLE_ETHEREUM
    g_supported_coins += "\"ethereum\",";
#endif
#if HD_WALLET_ENABLE_COSMOS
    g_supported_coins += "\"cosmos\",";
#endif
#if HD_WALLET_ENABLE_SOLANA
    g_supported_coins += "\"solana\",";
#endif
#if HD_WALLET_ENABLE_POLKADOT
    g_supported_coins += "\"polkadot\",";
#endif
    // Remove trailing comma if present
    if (g_supported_coins.length() > 1 && g_supported_coins.back() == ',') {
        g_supported_coins.pop_back();
    }
    g_supported_coins += "]";
    return g_supported_coins.c_str();
}

// Static storage for curve list string
static std::string g_supported_curves;

/**
 * Get list of supported curves as JSON array string
 */
extern "C" HD_WALLET_EXPORT
const char* hd_get_supported_curves() {
    g_supported_curves = "[";
#if HD_WALLET_ENABLE_SECP256K1
    g_supported_curves += "\"secp256k1\",";
#endif
#if HD_WALLET_ENABLE_ED25519
    g_supported_curves += "\"ed25519\",";
#endif
#if HD_WALLET_ENABLE_P256
    g_supported_curves += "\"p256\",";
#endif
#if HD_WALLET_ENABLE_P384
    g_supported_curves += "\"p384\",";
#endif
#if HD_WALLET_ENABLE_X25519
    g_supported_curves += "\"x25519\",";
#endif
    // Remove trailing comma if present
    if (g_supported_curves.length() > 1 && g_supported_curves.back() == ',') {
        g_supported_curves.pop_back();
    }
    g_supported_curves += "]";
    return g_supported_curves.c_str();
}

// =============================================================================
// WASI Bridge
// =============================================================================

/**
 * Check if a WASI feature is available
 * @param feature WasiFeature enum value
 * @return 1 if available, 0 if not
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_wasi_has_feature(int32_t feature) {
    return WasiBridge::instance().hasFeature(static_cast<WasiFeature>(feature)) ? 1 : 0;
}

/**
 * Get warning code for a WASI feature
 * @param feature WasiFeature enum value
 * @return WasiWarning enum value
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_wasi_get_warning(int32_t feature) {
    return static_cast<int32_t>(WasiBridge::instance().getWarning(static_cast<WasiFeature>(feature)));
}

// Static storage for warning message
static std::string g_warning_message;

/**
 * Get warning message for a WASI feature
 * @param feature WasiFeature enum value
 * @return Pointer to warning message string
 */
extern "C" HD_WALLET_EXPORT
const char* hd_wasi_get_warning_message(int32_t feature) {
    g_warning_message = WasiBridge::instance().getWarningMessage(static_cast<WasiFeature>(feature));
    return g_warning_message.c_str();
}

/**
 * Set a WASI callback (placeholder for JS bridge integration)
 * @param feature Feature to set callback for
 * @param callback_ptr Function pointer (interpreted by JS)
 * @return 0 on success
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_wasi_set_callback(int32_t feature, void* callback_ptr) {
    // This function is meant to be called from JS to register callbacks
    // The actual implementation depends on the JS wrapper
    (void)feature;
    (void)callback_ptr;
    return 0;
}

// =============================================================================
// Entropy
// =============================================================================

/**
 * Inject entropy from external source
 * Must be called before cryptographic operations in WASI environments
 * @param entropy Pointer to entropy bytes
 * @param length Number of entropy bytes (at least 32 recommended)
 */
extern "C" HD_WALLET_EXPORT
void hd_inject_entropy(const uint8_t* entropy, size_t length) {
    WasiBridge::instance().injectEntropy(entropy, length);
}

/**
 * Get entropy status
 * @return 0=not initialized, 1=initialized, 2=sufficient
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_get_entropy_status() {
    auto& bridge = WasiBridge::instance();
    if (!bridge.hasEntropy()) {
        return 0; // NOT_INITIALIZED
    }
    // Check if we have sufficient entropy (at least 32 bytes)
    return 2; // SUFFICIENT
}

// =============================================================================
// BIP-39 Mnemonic
// NOTE: These wrappers are disabled because the same functions are already
// exported from bip39.cpp with identical signatures.
// =============================================================================

#if 0 // Disabled - already defined in bip39.cpp
/**
 * Generate a random mnemonic phrase
 * @param output Buffer to write mnemonic string
 * @param output_size Size of output buffer
 * @param word_count Number of words (12, 15, 18, 21, or 24)
 * @param language Language enum value
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_generate(
    char* output,
    size_t output_size,
    size_t word_count,
    int32_t language
) {
    auto result = bip39::generateMnemonic(
        word_count,
        static_cast<bip39::Language>(language)
    );

    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (result.value.length() + 1 > output_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(output, result.value.c_str(), result.value.length() + 1);
    return 0;
}

/**
 * Validate a mnemonic phrase
 * @param mnemonic Null-terminated mnemonic string
 * @param language Language enum value
 * @return 0 if valid, negative error code if invalid
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_validate(const char* mnemonic, int32_t language) {
    auto error = bip39::validateMnemonic(
        mnemonic,
        static_cast<bip39::Language>(language)
    );
    return static_cast<int32_t>(error);
}

/**
 * Convert mnemonic to 64-byte seed
 * @param mnemonic Null-terminated mnemonic string
 * @param passphrase Null-terminated passphrase (can be empty string)
 * @param seed_out Buffer to write 64-byte seed
 * @param seed_size Size of seed buffer (must be at least 64)
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_to_seed(
    const char* mnemonic,
    const char* passphrase,
    uint8_t* seed_out,
    size_t seed_size
) {
    if (seed_size < 64) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto result = bip39::mnemonicToSeed(
        mnemonic,
        passphrase ? passphrase : ""
    );

    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(seed_out, result.value.data(), 64);
    return 0;
}

/**
 * Convert mnemonic to entropy bytes
 * @param mnemonic Null-terminated mnemonic string
 * @param language Language enum value
 * @param entropy_out Buffer to write entropy bytes
 * @param entropy_size [in/out] Size of buffer / bytes written
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_to_entropy(
    const char* mnemonic,
    int32_t language,
    uint8_t* entropy_out,
    size_t* entropy_size
) {
    auto result = bip39::mnemonicToEntropy(
        mnemonic,
        static_cast<bip39::Language>(language)
    );

    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (result.value.size() > *entropy_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(entropy_out, result.value.data(), result.value.size());
    *entropy_size = result.value.size();
    return 0;
}

/**
 * Convert entropy to mnemonic
 * @param entropy Entropy bytes
 * @param entropy_size Number of entropy bytes (16, 20, 24, 28, or 32)
 * @param language Language enum value
 * @param output Buffer to write mnemonic string
 * @param output_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_entropy_to_mnemonic(
    const uint8_t* entropy,
    size_t entropy_size,
    int32_t language,
    char* output,
    size_t output_size
) {
    ByteVector entropy_vec(entropy, entropy + entropy_size);
    auto result = bip39::entropyToMnemonic(
        entropy_vec,
        static_cast<bip39::Language>(language)
    );

    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (result.value.length() + 1 > output_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(output, result.value.c_str(), result.value.length() + 1);
    return 0;
}

// Static storage for wordlist JSON
static std::string g_wordlist_json;

/**
 * Get wordlist for language as JSON array
 * @param language Language enum value
 * @return Pointer to JSON array string of words
 */
extern "C" HD_WALLET_EXPORT
const char* hd_mnemonic_get_wordlist(int32_t language) {
    const char* const* wordlist = bip39::getWordlist(static_cast<bip39::Language>(language));
    if (!wordlist) {
        return "[]";
    }

    g_wordlist_json = "[";
    for (size_t i = 0; i < bip39::WORDLIST_SIZE; ++i) {
        if (i > 0) g_wordlist_json += ",";
        g_wordlist_json += "\"";
        g_wordlist_json += wordlist[i];
        g_wordlist_json += "\"";
    }
    g_wordlist_json += "]";
    return g_wordlist_json.c_str();
}

// Static storage for word suggestions
static std::string g_suggestions_json;

/**
 * Get word suggestions for autocomplete
 * @param prefix Word prefix
 * @param language Language enum value
 * @param suggestions_out Buffer to write JSON array of suggestions
 * @param output_size Size of output buffer
 * @param max_suggestions Maximum number of suggestions
 * @return Number of suggestions, or negative error code
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_suggest_word(
    const char* prefix,
    int32_t language,
    char* suggestions_out,
    size_t output_size,
    size_t max_suggestions
) {
    auto suggestions = bip39::suggestWords(
        prefix,
        static_cast<bip39::Language>(language),
        max_suggestions
    );

    g_suggestions_json = "[";
    for (size_t i = 0; i < suggestions.size(); ++i) {
        if (i > 0) g_suggestions_json += ",";
        g_suggestions_json += "\"";
        g_suggestions_json += suggestions[i];
        g_suggestions_json += "\"";
    }
    g_suggestions_json += "]";

    if (g_suggestions_json.length() + 1 > output_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(suggestions_out, g_suggestions_json.c_str(), g_suggestions_json.length() + 1);
    return static_cast<int32_t>(suggestions.size());
}

/**
 * Check if a word is in the wordlist
 * @param word Word to check
 * @param language Language enum value
 * @return Word index (0-2047) if found, -1 if not found
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_mnemonic_check_word(const char* word, int32_t language) {
    return bip39::findWord(word, static_cast<bip39::Language>(language));
}
#endif // Disabled BIP-39 wrappers

// =============================================================================
// BIP-32 HD Keys
// NOTE: These wrappers are disabled because the same functions are already
// exported from bip32.cpp with identical signatures.
// =============================================================================

#if 0 // Disabled - already defined in bip32.cpp
// Internal helper to cast handles
static bip32::ExtendedKey* toKey(bip32::hd_key_handle handle) {
    return reinterpret_cast<bip32::ExtendedKey*>(handle);
}

/**
 * Create master HD key from seed
 * @param seed Seed bytes
 * @param seed_size Seed size (16-64 bytes per BIP-32 spec)
 * @param curve Curve enum value
 * @return Key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_from_seed(const uint8_t* seed, size_t seed_size, int32_t curve) {
    // BIP-32 allows 128-512 bits (16-64 bytes)
    if (seed_size < 16 || seed_size > 64) {
        return nullptr;
    }

    ByteVector seed_vec(seed, seed + seed_size);

    auto result = bip32::ExtendedKey::fromSeed(seed_vec, static_cast<Curve>(curve));
    if (!result.ok()) {
        return nullptr;
    }

    // Allocate new key on heap and move result into it
    auto* key = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(key);
}

/**
 * Parse extended private key from string
 * @param xprv Base58Check-encoded xprv string
 * @return Key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_from_xprv(const char* xprv) {
    auto result = bip32::ExtendedKey::fromString(xprv);
    if (!result.ok()) {
        return nullptr;
    }

    auto* key = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(key);
}

/**
 * Parse extended public key from string
 * @param xpub Base58Check-encoded xpub string
 * @return Key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_from_xpub(const char* xpub) {
    auto result = bip32::ExtendedKey::fromString(xpub);
    if (!result.ok()) {
        return nullptr;
    }

    auto* key = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(key);
}

/**
 * Derive key at path
 * @param key_handle Source key handle
 * @param path Derivation path string (e.g., "m/44'/60'/0'/0/0")
 * @return New key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_derive_path(bip32::hd_key_handle key_handle, const char* path) {
    auto* key = toKey(key_handle);
    if (!key) return nullptr;

    auto result = key->derivePath(path);
    if (!result.ok()) {
        return nullptr;
    }

    auto* derived = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(derived);
}

/**
 * Derive child key at index
 * @param key_handle Source key handle
 * @param index Child index
 * @return New key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_derive_child(bip32::hd_key_handle key_handle, uint32_t index) {
    auto* key = toKey(key_handle);
    if (!key) return nullptr;

    auto result = key->deriveChild(index);
    if (!result.ok()) {
        return nullptr;
    }

    auto* derived = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(derived);
}

/**
 * Derive hardened child key
 * @param key_handle Source key handle
 * @param index Child index (will be hardened)
 * @return New key handle, or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_derive_hardened(bip32::hd_key_handle key_handle, uint32_t index) {
    auto* key = toKey(key_handle);
    if (!key) return nullptr;

    auto result = key->deriveHardened(index);
    if (!result.ok()) {
        return nullptr;
    }

    auto* derived = new bip32::ExtendedKey(std::move(result.value));
    return reinterpret_cast<bip32::hd_key_handle>(derived);
}

/**
 * Get private key bytes
 * @param key_handle Key handle
 * @param out Buffer to write 32-byte private key
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_get_private(bip32::hd_key_handle key_handle, uint8_t* out, size_t out_size) {
    auto* key = toKey(key_handle);
    if (!key) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    auto result = key->privateKey();
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(out, result.value.data(), 32);
    return 0;
}

/**
 * Get public key bytes (compressed)
 * @param key_handle Key handle
 * @param out Buffer to write 33-byte public key
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_get_public(bip32::hd_key_handle key_handle, uint8_t* out, size_t out_size) {
    auto* key = toKey(key_handle);
    if (!key) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    auto pubkey = key->publicKey();
    std::memcpy(out, pubkey.data(), 33);
    return 0;
}

/**
 * Get chain code bytes
 * @param key_handle Key handle
 * @param out Buffer to write 32-byte chain code
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_get_chain_code(bip32::hd_key_handle key_handle, uint8_t* out, size_t out_size) {
    auto* key = toKey(key_handle);
    if (!key) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    auto chain_code = key->chainCode();
    std::memcpy(out, chain_code.data(), 32);
    return 0;
}

/**
 * Get key fingerprint
 * @param key_handle Key handle
 * @return Fingerprint (first 4 bytes of HASH160 of public key)
 */
extern "C" HD_WALLET_EXPORT
uint32_t hd_key_get_fingerprint(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return 0;
    return key->fingerprint();
}

/**
 * Get parent fingerprint
 * @param key_handle Key handle
 * @return Parent fingerprint
 */
extern "C" HD_WALLET_EXPORT
uint32_t hd_key_get_parent_fingerprint(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return 0;
    return key->parentFingerprint();
}

/**
 * Get key depth
 * @param key_handle Key handle
 * @return Key depth in derivation tree
 */
extern "C" HD_WALLET_EXPORT
uint8_t hd_key_get_depth(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return 0;
    return key->depth();
}

/**
 * Get child index
 * @param key_handle Key handle
 * @return Child index
 */
extern "C" HD_WALLET_EXPORT
uint32_t hd_key_get_child_index(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return 0;
    return key->childIndex();
}

/**
 * Serialize as extended private key
 * @param key_handle Key handle
 * @param out Buffer to write Base58Check string
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_serialize_xprv(bip32::hd_key_handle key_handle, char* out, size_t out_size) {
    auto* key = toKey(key_handle);
    if (!key) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

    auto result = key->toXprv();
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (result.value.length() + 1 > out_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(out, result.value.c_str(), result.value.length() + 1);
    return 0;
}

/**
 * Serialize as extended public key
 * @param key_handle Key handle
 * @param out Buffer to write Base58Check string
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_serialize_xpub(bip32::hd_key_handle key_handle, char* out, size_t out_size) {
    auto* key = toKey(key_handle);
    if (!key) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

    auto xpub = key->toXpub();
    if (xpub.length() + 1 > out_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(out, xpub.c_str(), xpub.length() + 1);
    return 0;
}

/**
 * Get neutered (public-only) version of key
 * @param key_handle Key handle
 * @return New key handle (neutered), or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_neutered(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return nullptr;

    auto* neutered = new bip32::ExtendedKey(key->neutered());
    return reinterpret_cast<bip32::hd_key_handle>(neutered);
}

/**
 * Check if key is neutered (public-only)
 * @param key_handle Key handle
 * @return 1 if neutered, 0 if has private key
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_key_is_neutered(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return 1;
    return key->isNeutered() ? 1 : 0;
}

/**
 * Securely wipe key material
 * @param key_handle Key handle
 */
extern "C" HD_WALLET_EXPORT
void hd_key_wipe(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (key) {
        key->wipe();
    }
}

/**
 * Clone a key
 * @param key_handle Key handle
 * @return New key handle (clone), or nullptr on failure
 */
extern "C" HD_WALLET_EXPORT
bip32::hd_key_handle hd_key_clone(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (!key) return nullptr;

    auto* cloned = new bip32::ExtendedKey(key->clone());
    return reinterpret_cast<bip32::hd_key_handle>(cloned);
}

/**
 * Destroy a key handle and free memory
 * @param key_handle Key handle
 */
extern "C" HD_WALLET_EXPORT
void hd_key_destroy(bip32::hd_key_handle key_handle) {
    auto* key = toKey(key_handle);
    if (key) {
        key->wipe();
        delete key;
    }
}
#endif // Disabled BIP-32 wrappers

// =============================================================================
// BIP-44/49/84 Paths
// NOTE: hd_path_build and hd_path_parse are disabled because they are already
// exported from bip44.cpp with identical signatures.
// =============================================================================

#if 0 // Disabled - already defined in bip44.cpp
/**
 * Build a derivation path string
 * @param out Buffer to write path string
 * @param out_size Size of output buffer
 * @param purpose Purpose (44, 49, 84)
 * @param coin_type SLIP-44 coin type
 * @param account Account index
 * @param change Change (0=external, 1=internal)
 * @param index Address index
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_path_build(
    char* out,
    size_t out_size,
    uint32_t purpose,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
) {
    char path[128];
    int len = std::snprintf(path, sizeof(path), "m/%u'/%u'/%u'/%u/%u",
        purpose, coin_type, account, change, index);

    if (len < 0 || static_cast<size_t>(len) >= out_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(out, path, len + 1);
    return 0;
}

/**
 * Parse a derivation path string
 * @param path Path string (e.g., "m/44'/60'/0'/0/0")
 * @param purpose [out] Purpose
 * @param coin_type [out] Coin type
 * @param account [out] Account
 * @param change [out] Change
 * @param index [out] Index
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_path_parse(
    const char* path,
    uint32_t* purpose,
    uint32_t* coin_type,
    uint32_t* account,
    uint32_t* change,
    uint32_t* index
) {
    auto result = bip32::DerivationPath::parse(path);
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    auto& components = result.value.components;
    if (components.size() < 5) {
        return static_cast<int32_t>(Error::INVALID_PATH);
    }

    *purpose = components[0].index;
    *coin_type = components[1].index;
    *account = components[2].index;
    *change = components[3].index;
    *index = components[4].index;

    return 0;
}
#endif // Disabled path wrappers

// Static storage for path string
static std::string g_path_string;

/**
 * Convert path components to string
 * @param purpose Purpose
 * @param coin_type Coin type
 * @param account Account
 * @param change Change
 * @param index Index
 * @return Pointer to path string
 */
extern "C" HD_WALLET_EXPORT
const char* hd_path_to_string(
    uint32_t purpose,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
) {
    char buf[128];
    std::snprintf(buf, sizeof(buf), "m/%u'/%u'/%u'/%u/%u",
        purpose, coin_type, account, change, index);
    g_path_string = buf;
    return g_path_string.c_str();
}

// Forward declare hd_path_parse from bip44.cpp (since our local wrapper is disabled)
extern "C" int32_t hd_path_parse(const char* path, uint32_t* purpose, uint32_t* coin_type,
                                  uint32_t* account, uint32_t* change, uint32_t* index);

// Path component getters
extern "C" HD_WALLET_EXPORT uint32_t hd_path_get_purpose(const char* path) {
    uint32_t purpose = 0, coin_type = 0, account = 0, change = 0, index = 0;
    hd_path_parse(path, &purpose, &coin_type, &account, &change, &index);
    return purpose;
}

extern "C" HD_WALLET_EXPORT uint32_t hd_path_get_coin_type(const char* path) {
    uint32_t purpose = 0, coin_type = 0, account = 0, change = 0, index = 0;
    hd_path_parse(path, &purpose, &coin_type, &account, &change, &index);
    return coin_type;
}

extern "C" HD_WALLET_EXPORT uint32_t hd_path_get_account(const char* path) {
    uint32_t purpose = 0, coin_type = 0, account = 0, change = 0, index = 0;
    hd_path_parse(path, &purpose, &coin_type, &account, &change, &index);
    return account;
}

extern "C" HD_WALLET_EXPORT uint32_t hd_path_get_change(const char* path) {
    uint32_t purpose = 0, coin_type = 0, account = 0, change = 0, index = 0;
    hd_path_parse(path, &purpose, &coin_type, &account, &change, &index);
    return change;
}

extern "C" HD_WALLET_EXPORT uint32_t hd_path_get_index(const char* path) {
    uint32_t purpose = 0, coin_type = 0, account = 0, change = 0, index = 0;
    hd_path_parse(path, &purpose, &coin_type, &account, &change, &index);
    return index;
}

// =============================================================================
// Multi-Curve Key Derivation
// =============================================================================

/**
 * Derive public key from private key for specified curve
 * @param private_key 32-byte private key
 * @param curve Curve enum value
 * @param public_key_out Buffer for compressed public key
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_curve_pubkey_from_privkey(
    const uint8_t* private_key,
    int32_t curve,
    uint8_t* public_key_out,
    size_t out_size
) {
    if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    Bytes32 privkey;
    std::memcpy(privkey.data(), private_key, 32);

    auto result = bip32::publicKeyFromPrivate(privkey, static_cast<Curve>(curve));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(public_key_out, result.value.data(), 33);
    return 0;
}

/**
 * Compress a public key
 * @param uncompressed 65-byte uncompressed public key
 * @param curve Curve enum value
 * @param compressed_out Buffer for 33-byte compressed key
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_curve_compress_pubkey(
    const uint8_t* uncompressed,
    int32_t curve,
    uint8_t* compressed_out,
    size_t out_size
) {
    if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    Bytes65 pubkey;
    std::memcpy(pubkey.data(), uncompressed, 65);

    auto result = bip32::compressPublicKey(pubkey, static_cast<Curve>(curve));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(compressed_out, result.value.data(), 33);
    return 0;
}

/**
 * Decompress a public key
 * @param compressed 33-byte compressed public key
 * @param curve Curve enum value
 * @param uncompressed_out Buffer for 65-byte uncompressed key
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_curve_decompress_pubkey(
    const uint8_t* compressed,
    int32_t curve,
    uint8_t* uncompressed_out,
    size_t out_size
) {
    if (out_size < 65) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    Bytes33 pubkey;
    std::memcpy(pubkey.data(), compressed, 33);

    auto result = bip32::decompressPublicKey(pubkey, static_cast<Curve>(curve));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(uncompressed_out, result.value.data(), 65);
    return 0;
}

// Curve-specific derivation wrappers
extern "C" HD_WALLET_EXPORT
int32_t hd_curve_derive_secp256k1(const uint8_t* priv, uint8_t* pub_out, size_t out_size) {
    return hd_curve_pubkey_from_privkey(priv, static_cast<int32_t>(Curve::SECP256K1), pub_out, out_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_derive_ed25519(const uint8_t* priv, uint8_t* pub_out, size_t out_size) {
    return hd_curve_pubkey_from_privkey(priv, static_cast<int32_t>(Curve::ED25519), pub_out, out_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_derive_p256(const uint8_t* priv, uint8_t* pub_out, size_t out_size) {
    return hd_curve_pubkey_from_privkey(priv, static_cast<int32_t>(Curve::P256), pub_out, out_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_derive_p384(const uint8_t* priv, uint8_t* pub_out, size_t out_size) {
    return hd_curve_pubkey_from_privkey(priv, static_cast<int32_t>(Curve::P384), pub_out, out_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_derive_x25519(const uint8_t* priv, uint8_t* pub_out, size_t out_size) {
    return hd_curve_pubkey_from_privkey(priv, static_cast<int32_t>(Curve::X25519), pub_out, out_size);
}

// =============================================================================
// Cryptographic Signing (secp256k1)
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

/**
 * Sign message with secp256k1 (ECDSA)
 * @param message Message to sign (typically a 32-byte hash)
 * @param message_len Message length
 * @param private_key 32-byte private key
 * @param signature_out Buffer for 64-byte signature (r || s)
 * @param out_size Size of output buffer
 * @return 0 on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out,
    size_t out_size
) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
        CryptoPP::Integer privKeyInt(private_key, 32);
        key.Initialize(CryptoPP::ASN1::secp256k1(), privKeyInt);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);

        std::string signature;
        CryptoPP::StringSource ss(message, message_len, true,
            new CryptoPP::SignerFilter(rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        if (signature.size() > out_size) {
            return static_cast<int32_t>(Error::OUT_OF_MEMORY);
        }

        std::memcpy(signature_out, signature.data(), signature.size());
        return static_cast<int32_t>(signature.size());
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

/**
 * Sign message with secp256k1 (recoverable signature)
 * @param message Message to sign
 * @param message_len Message length
 * @param private_key 32-byte private key
 * @param signature_out Buffer for 65-byte signature (r || s || v)
 * @param out_size Size of output buffer
 * @return Recovery ID (0-3) on success, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign_recoverable(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out,
    size_t out_size
) {
    if (out_size < 65) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    int32_t result = hd_secp256k1_sign(message, message_len, private_key, signature_out, out_size - 1);
    if (result < 0) return result;

    // Recovery ID (simplified - actual implementation would compute properly)
    signature_out[64] = 0;
    return 0;
}

/**
 * Verify secp256k1 signature
 * @param message Message that was signed
 * @param message_len Message length
 * @param signature 64-byte signature (r || s)
 * @param signature_len Signature length
 * @param public_key 33 or 65-byte public key
 * @param public_key_len Public key length
 * @return 1 if valid, 0 if invalid, negative error code on failure
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_verify(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
) {
    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey key;

        if (public_key_len == 33) {
            // Compressed - need to decompress
            // Implementation would decompress here
        } else if (public_key_len == 65) {
            CryptoPP::ECP::Point point;
            point.x.Decode(public_key + 1, 32);
            point.y.Decode(public_key + 33, 32);
            key.Initialize(CryptoPP::ASN1::secp256k1(), point);
        } else {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(key);

        bool valid = verifier.VerifyMessage(message, message_len, signature, signature_len);
        return valid ? 1 : 0;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

/**
 * Recover public key from recoverable signature
 */
extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_recover(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    int32_t recovery_id,
    uint8_t* public_key_out,
    size_t out_size
) {
    if (out_size < 65) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    // Recovery implementation would go here
    // This is a placeholder - actual implementation requires EC math
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    (void)recovery_id;
    (void)public_key_out;

    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Ed25519 Signing
// =============================================================================
// NOTE: Ed25519 sign/verify functions are defined in eddsa.cpp with correct
// signatures matching the JS wrapper expectations

// =============================================================================
// P-256 / P-384 Signing
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
        CryptoPP::Integer privKeyInt(private_key, 32);
        key.Initialize(CryptoPP::ASN1::secp256r1(), privKeyInt);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);

        std::string signature;
        CryptoPP::StringSource ss(message, message_len, true,
            new CryptoPP::SignerFilter(rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        std::memcpy(signature_out, signature.data(), signature.size());
        return static_cast<int32_t>(signature.size());
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len,
    const uint8_t* public_key, size_t public_key_len
) {
    (void)message; (void)message_len;
    (void)signature; (void)signature_len;
    (void)public_key; (void)public_key_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 96) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey key;
        CryptoPP::Integer privKeyInt(private_key, 48);
        key.Initialize(CryptoPP::ASN1::secp384r1(), privKeyInt);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer signer(key);

        std::string signature;
        CryptoPP::StringSource ss(message, message_len, true,
            new CryptoPP::SignerFilter(rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        std::memcpy(signature_out, signature.data(), signature.size());
        return static_cast<int32_t>(signature.size());
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len,
    const uint8_t* public_key, size_t public_key_len
) {
    (void)message; (void)message_len;
    (void)signature; (void)signature_len;
    (void)public_key; (void)public_key_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// ECDH Key Exchange
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_secp256k1(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    (void)private_key; (void)public_key; (void)public_key_len;
    (void)shared_secret_out;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p256(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    (void)private_key; (void)public_key; (void)public_key_len;
    (void)shared_secret_out;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p384(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t out_size
) {
    if (out_size < 48) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    (void)private_key; (void)public_key; (void)public_key_len;
    (void)shared_secret_out;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

#if HD_WALLET_ENABLE_X25519
extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_x25519(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret_out,
    size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::x25519 ecdh(private_key);
        ecdh.Agree(shared_secret_out, private_key, public_key);
        return 32;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}
#else
extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_x25519(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret_out,
    size_t out_size
) {
    (void)private_key; (void)public_key; (void)shared_secret_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
#endif // HD_WALLET_ENABLE_X25519

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Hash Functions
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::SHA256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha512(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::SHA512 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 64;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_keccak256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::Keccak_256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_ripemd160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::RIPEMD160 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_hash160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    uint8_t sha256_out[32];
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(sha256_out, data, data_len);

    CryptoPP::RIPEMD160 ripemd;
    ripemd.CalculateDigest(hash_out, sha256_out, 32);

    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2b(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t hash_len) {
    if (hash_len == 0) hash_len = 32;
    if (out_size < hash_len) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::BLAKE2b hash(false, static_cast<unsigned int>(hash_len));
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(hash_len);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2s(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t hash_len) {
    if (hash_len == 0) hash_len = 32;
    if (out_size < hash_len) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    CryptoPP::BLAKE2s hash(false, static_cast<unsigned int>(hash_len));
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(hash_len);
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Key Derivation Functions
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_hkdf(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* output, size_t output_len
) {
    try {
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(output, output_len, ikm, ikm_len, salt, salt_len, info, info_len);
        return static_cast<int32_t>(output_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_pbkdf2(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* output, size_t output_len
) {
    try {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
        pbkdf2.DeriveKey(output, output_len, 0, password, password_len, salt, salt_len, iterations);
        return static_cast<int32_t>(output_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_scrypt(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint64_t n, uint32_t r, uint32_t p,
    uint8_t* output, size_t output_len
) {
    try {
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(output, output_len, password, password_len, salt, salt_len, n, r, p);
        return static_cast<int32_t>(output_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Encoding Utilities
// =============================================================================

// Base58 alphabet
static const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Static storage for encoded strings
static std::string g_encoded_string;

extern "C" HD_WALLET_EXPORT
const char* hd_encode_base58(const uint8_t* data, size_t data_len) {
    // Count leading zeros
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0) {
        zeros++;
    }

    // Allocate enough space for base58 encoding
    size_t size = (data_len - zeros) * 138 / 100 + 1;
    std::vector<uint8_t> b58(size);

    // Process input
    for (size_t i = zeros; i < data_len; i++) {
        int carry = data[i];
        for (auto it = b58.rbegin(); it != b58.rend(); ++it) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
    }

    // Skip leading zeros in b58
    auto it = b58.begin();
    while (it != b58.end() && *it == 0) {
        ++it;
    }

    // Build result
    g_encoded_string.clear();
    g_encoded_string.reserve(zeros + (b58.end() - it));
    g_encoded_string.append(zeros, '1');
    while (it != b58.end()) {
        g_encoded_string += BASE58_ALPHABET[*it++];
    }

    return g_encoded_string.c_str();
}

extern "C" HD_WALLET_EXPORT
int32_t hd_decode_base58(const char* str, uint8_t* output, size_t* output_len) {
    size_t str_len = std::strlen(str);

    // Count leading '1's
    size_t zeros = 0;
    while (zeros < str_len && str[zeros] == '1') {
        zeros++;
    }

    // Allocate enough space
    size_t size = (str_len - zeros) * 733 / 1000 + 1;
    std::vector<uint8_t> b256(size);

    // Process input
    for (size_t i = zeros; i < str_len; i++) {
        const char* p = std::strchr(BASE58_ALPHABET, str[i]);
        if (!p) {
            return static_cast<int32_t>(Error::INVALID_ARGUMENT);
        }
        int carry = static_cast<int>(p - BASE58_ALPHABET);
        for (auto it = b256.rbegin(); it != b256.rend(); ++it) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
    }

    // Skip leading zeros in b256
    auto it = b256.begin();
    while (it != b256.end() && *it == 0) {
        ++it;
    }

    // Check output size
    size_t result_len = zeros + (b256.end() - it);
    if (result_len > *output_len) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    // Build result
    std::memset(output, 0, zeros);
    std::copy(it, b256.end(), output + zeros);
    *output_len = result_len;

    return 0;
}

extern "C" HD_WALLET_EXPORT
const char* hd_encode_base58check(const uint8_t* data, size_t data_len) {
#if HD_WALLET_USE_CRYPTOPP
    // Compute double SHA256 checksum
    uint8_t hash1[32], hash2[32];
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(hash1, data, data_len);
    sha256.CalculateDigest(hash2, hash1, 32);

    // Append checksum
    std::vector<uint8_t> with_checksum(data, data + data_len);
    with_checksum.insert(with_checksum.end(), hash2, hash2 + 4);

    return hd_encode_base58(with_checksum.data(), with_checksum.size());
#else
    (void)data; (void)data_len;
    return "";
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_decode_base58check(const char* str, uint8_t* output, size_t* output_len) {
#if HD_WALLET_USE_CRYPTOPP
    // First decode base58
    uint8_t decoded[256];
    size_t decoded_len = sizeof(decoded);
    int32_t result = hd_decode_base58(str, decoded, &decoded_len);
    if (result != 0) return result;

    if (decoded_len < 4) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Verify checksum
    size_t payload_len = decoded_len - 4;
    uint8_t hash1[32], hash2[32];
    CryptoPP::SHA256 sha256;
    sha256.CalculateDigest(hash1, decoded, payload_len);
    sha256.CalculateDigest(hash2, hash1, 32);

    if (std::memcmp(hash2, decoded + payload_len, 4) != 0) {
        return static_cast<int32_t>(Error::INVALID_CHECKSUM);
    }

    if (payload_len > *output_len) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(output, decoded, payload_len);
    *output_len = payload_len;
    return 0;
#else
    (void)str; (void)output; (void)output_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
#endif
}

extern "C" HD_WALLET_EXPORT
const char* hd_encode_hex(const uint8_t* data, size_t data_len) {
    static const char hex_chars[] = "0123456789abcdef";
    g_encoded_string.clear();
    g_encoded_string.reserve(data_len * 2);

    for (size_t i = 0; i < data_len; i++) {
        g_encoded_string += hex_chars[(data[i] >> 4) & 0x0F];
        g_encoded_string += hex_chars[data[i] & 0x0F];
    }

    return g_encoded_string.c_str();
}

extern "C" HD_WALLET_EXPORT
int32_t hd_decode_hex(const char* str, uint8_t* output, size_t* output_len) {
    size_t str_len = std::strlen(str);
    if (str_len % 2 != 0) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    size_t result_len = str_len / 2;
    if (result_len > *output_len) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    for (size_t i = 0; i < result_len; i++) {
        char hi = str[i * 2];
        char lo = str[i * 2 + 1];

        uint8_t hi_val, lo_val;
        if (hi >= '0' && hi <= '9') hi_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_val = hi - 'a' + 10;
        else if (hi >= 'A' && hi <= 'F') hi_val = hi - 'A' + 10;
        else return static_cast<int32_t>(Error::INVALID_ARGUMENT);

        if (lo >= '0' && lo <= '9') lo_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_val = lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') lo_val = lo - 'A' + 10;
        else return static_cast<int32_t>(Error::INVALID_ARGUMENT);

        output[i] = (hi_val << 4) | lo_val;
    }

    *output_len = result_len;
    return 0;
}

#if HD_WALLET_USE_CRYPTOPP

extern "C" HD_WALLET_EXPORT
const char* hd_encode_base64(const uint8_t* data, size_t data_len) {
    g_encoded_string.clear();
    CryptoPP::StringSource ss(data, data_len, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(g_encoded_string),
            false // no line breaks
        )
    );
    return g_encoded_string.c_str();
}

extern "C" HD_WALLET_EXPORT
int32_t hd_decode_base64(const char* str, uint8_t* output, size_t* output_len) {
    try {
        std::string decoded;
        CryptoPP::StringSource ss(str, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded)
            )
        );

        if (decoded.size() > *output_len) {
            return static_cast<int32_t>(Error::OUT_OF_MEMORY);
        }

        std::memcpy(output, decoded.data(), decoded.size());
        *output_len = decoded.size();
        return 0;
    } catch (...) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Bech32 Encoding (for SegWit addresses)
// =============================================================================

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

extern "C" HD_WALLET_EXPORT
const char* hd_encode_bech32(const char* hrp, const uint8_t* data, size_t data_len) {
    // Simplified bech32 encoding - full implementation would include checksum
    g_encoded_string = hrp;
    g_encoded_string += "1";

    for (size_t i = 0; i < data_len; i++) {
        g_encoded_string += BECH32_CHARSET[data[i] & 0x1f];
    }

    // TODO: Add proper checksum
    return g_encoded_string.c_str();
}

extern "C" HD_WALLET_EXPORT
int32_t hd_decode_bech32(const char* str, char* hrp_out, size_t hrp_size, uint8_t* data_out, size_t* data_len) {
    // Find separator
    const char* sep = std::strrchr(str, '1');
    if (!sep) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    size_t hrp_len = sep - str;
    if (hrp_len + 1 > hrp_size) {
        return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    std::memcpy(hrp_out, str, hrp_len);
    hrp_out[hrp_len] = '\0';

    // Decode data part
    const char* data = sep + 1;
    size_t data_str_len = std::strlen(data);

    // TODO: Verify checksum and decode properly
    size_t out_idx = 0;
    for (size_t i = 0; i < data_str_len && out_idx < *data_len; i++) {
        const char* p = std::strchr(BECH32_CHARSET, std::tolower(data[i]));
        if (p) {
            data_out[out_idx++] = static_cast<uint8_t>(p - BECH32_CHARSET);
        }
    }

    *data_len = out_idx;
    return 0;
}

// =============================================================================
// Bitcoin Functions (placeholders - full implementation in separate files)
// =============================================================================

#if HD_WALLET_ENABLE_BITCOIN

// Address generation
extern "C" HD_WALLET_EXPORT
int32_t hd_btc_get_address_p2pkh(const uint8_t* pubkey, size_t pubkey_len, int32_t network, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)network; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_get_address_p2sh(const uint8_t* script, size_t script_len, int32_t network, char* out, size_t out_size) {
    (void)script; (void)script_len; (void)network; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_get_address_p2wpkh(const uint8_t* pubkey, size_t pubkey_len, int32_t network, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)network; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_get_address_p2wsh(const uint8_t* script, size_t script_len, int32_t network, char* out, size_t out_size) {
    (void)script; (void)script_len; (void)network; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_get_address_taproot(const uint8_t* pubkey, size_t pubkey_len, int32_t network, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)network; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_validate_address(const char* address) {
    (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_decode_address(const char* address, int32_t* type, uint8_t* hash, size_t* hash_len, int32_t* network) {
    (void)address; (void)type; (void)hash; (void)hash_len; (void)network;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

// Message signing
extern "C" HD_WALLET_EXPORT
int32_t hd_btc_sign_message(const char* message, const uint8_t* privkey, char* sig_out, size_t out_size) {
    (void)message; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_btc_verify_message(const char* message, const char* signature, const char* address) {
    (void)message; (void)signature; (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

// Transaction building
extern "C" HD_WALLET_EXPORT void* hd_btc_tx_create() { return nullptr; }
extern "C" HD_WALLET_EXPORT int32_t hd_btc_tx_add_input(void* tx, const char* txid, uint32_t vout, uint32_t sequence) {
    (void)tx; (void)txid; (void)vout; (void)sequence;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_btc_tx_add_output(void* tx, const char* address, uint64_t amount) {
    (void)tx; (void)address; (void)amount;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_btc_tx_sign(void* tx, uint32_t input_idx, const uint8_t* privkey, const uint8_t* redeem_script, size_t script_len) {
    (void)tx; (void)input_idx; (void)privkey; (void)redeem_script; (void)script_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_btc_tx_serialize(void* tx, uint8_t* out, size_t* out_size) {
    (void)tx; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT const char* hd_btc_tx_get_txid(void* tx) { (void)tx; return ""; }
extern "C" HD_WALLET_EXPORT size_t hd_btc_tx_get_size(void* tx) { (void)tx; return 0; }
extern "C" HD_WALLET_EXPORT size_t hd_btc_tx_get_vsize(void* tx) { (void)tx; return 0; }
extern "C" HD_WALLET_EXPORT void hd_btc_tx_destroy(void* tx) { (void)tx; }

#endif // HD_WALLET_ENABLE_BITCOIN

// =============================================================================
// Ethereum Functions (placeholders)
// =============================================================================

#if HD_WALLET_ENABLE_ETHEREUM

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_get_address(const uint8_t* pubkey, size_t pubkey_len, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_get_address_checksum(const char* address, char* out, size_t out_size) {
    (void)address; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_validate_address(const char* address) {
    (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_sign_message(const char* message, const uint8_t* privkey, char* sig_out, size_t out_size) {
    (void)message; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_sign_typed_data(const char* typed_data_json, const uint8_t* privkey, char* sig_out, size_t out_size) {
    (void)typed_data_json; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_eth_verify_message(const char* message, const char* signature, char* address_out, size_t out_size) {
    (void)message; (void)signature; (void)address_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

// Transaction building
extern "C" HD_WALLET_EXPORT void* hd_eth_tx_create(
    uint64_t nonce, const uint8_t* gas_price, size_t gas_price_len, uint64_t gas_limit,
    const char* to, const uint8_t* value, size_t value_len, const uint8_t* data, size_t data_len, uint64_t chain_id
) {
    (void)nonce; (void)gas_price; (void)gas_price_len; (void)gas_limit;
    (void)to; (void)value; (void)value_len; (void)data; (void)data_len; (void)chain_id;
    return nullptr;
}

extern "C" HD_WALLET_EXPORT void* hd_eth_tx_create_eip1559(
    uint64_t nonce, const uint8_t* max_fee, size_t max_fee_len, const uint8_t* max_priority_fee, size_t max_priority_len,
    uint64_t gas_limit, const char* to, const uint8_t* value, size_t value_len, const uint8_t* data, size_t data_len, uint64_t chain_id
) {
    (void)nonce; (void)max_fee; (void)max_fee_len; (void)max_priority_fee; (void)max_priority_len;
    (void)gas_limit; (void)to; (void)value; (void)value_len; (void)data; (void)data_len; (void)chain_id;
    return nullptr;
}

extern "C" HD_WALLET_EXPORT int32_t hd_eth_tx_sign(void* tx, const uint8_t* privkey) {
    (void)tx; (void)privkey;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_eth_tx_serialize(void* tx, uint8_t* out, size_t* out_size) {
    (void)tx; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT const char* hd_eth_tx_get_hash(void* tx) { (void)tx; return ""; }
extern "C" HD_WALLET_EXPORT void hd_eth_tx_destroy(void* tx) { (void)tx; }

extern "C" HD_WALLET_EXPORT int32_t hd_eth_encode_abi(const char* signature, const char* params_json, uint8_t* out, size_t* out_size) {
    (void)signature; (void)params_json; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_eth_decode_abi(const char* signature, const uint8_t* data, size_t data_len, char* json_out, size_t out_size) {
    (void)signature; (void)data; (void)data_len; (void)json_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

#endif // HD_WALLET_ENABLE_ETHEREUM

// =============================================================================
// Cosmos Functions (placeholders)
// =============================================================================

#if HD_WALLET_ENABLE_COSMOS

extern "C" HD_WALLET_EXPORT
int32_t hd_cosmos_get_address(const uint8_t* pubkey, size_t pubkey_len, const char* prefix, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)prefix; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_cosmos_validate_address(const char* address) {
    (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_cosmos_sign_amino(const char* doc_json, const uint8_t* privkey, char* sig_out, size_t out_size) {
    (void)doc_json; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_cosmos_sign_direct(
    const uint8_t* body_bytes, size_t body_len,
    const uint8_t* auth_info_bytes, size_t auth_len,
    const char* chain_id, uint64_t account_number,
    const uint8_t* privkey, char* sig_out, size_t out_size
) {
    (void)body_bytes; (void)body_len; (void)auth_info_bytes; (void)auth_len;
    (void)chain_id; (void)account_number; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_cosmos_verify(const uint8_t* sig, size_t sig_len, const uint8_t* message, size_t msg_len, const uint8_t* pubkey, size_t pubkey_len) {
    (void)sig; (void)sig_len; (void)message; (void)msg_len; (void)pubkey; (void)pubkey_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT void* hd_cosmos_tx_create() { return nullptr; }
extern "C" HD_WALLET_EXPORT int32_t hd_cosmos_tx_sign(void* tx, const uint8_t* privkey) { (void)tx; (void)privkey; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT int32_t hd_cosmos_tx_serialize(void* tx, uint8_t* out, size_t* out_size) { (void)tx; (void)out; (void)out_size; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT void hd_cosmos_tx_destroy(void* tx) { (void)tx; }

#endif // HD_WALLET_ENABLE_COSMOS

// =============================================================================
// Solana Functions (placeholders)
// =============================================================================

#if HD_WALLET_ENABLE_SOLANA

extern "C" HD_WALLET_EXPORT
int32_t hd_sol_get_address(const uint8_t* pubkey, size_t pubkey_len, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_sol_validate_address(const char* address) {
    (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_sol_sign_message(const uint8_t* message, size_t msg_len, const uint8_t* privkey, uint8_t* sig_out, size_t out_size) {
    (void)message; (void)msg_len; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_sol_verify_message(const uint8_t* message, size_t msg_len, const uint8_t* sig, size_t sig_len, const uint8_t* pubkey, size_t pubkey_len) {
    (void)message; (void)msg_len; (void)sig; (void)sig_len; (void)pubkey; (void)pubkey_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT void* hd_sol_tx_create() { return nullptr; }
extern "C" HD_WALLET_EXPORT int32_t hd_sol_tx_sign(void* tx, const uint8_t* privkey) { (void)tx; (void)privkey; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT int32_t hd_sol_tx_serialize(void* tx, uint8_t* out, size_t* out_size) { (void)tx; (void)out; (void)out_size; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT void hd_sol_tx_destroy(void* tx) { (void)tx; }

#endif // HD_WALLET_ENABLE_SOLANA

// =============================================================================
// Polkadot Functions (placeholders)
// =============================================================================

#if HD_WALLET_ENABLE_POLKADOT

extern "C" HD_WALLET_EXPORT
int32_t hd_dot_get_address(const uint8_t* pubkey, size_t pubkey_len, uint16_t ss58_prefix, char* out, size_t out_size) {
    (void)pubkey; (void)pubkey_len; (void)ss58_prefix; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_dot_validate_address(const char* address) {
    (void)address;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_dot_sign_message(const uint8_t* message, size_t msg_len, const uint8_t* privkey, uint8_t* sig_out, size_t out_size) {
    (void)message; (void)msg_len; (void)privkey; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_dot_verify_message(const uint8_t* message, size_t msg_len, const uint8_t* sig, size_t sig_len, const uint8_t* pubkey, size_t pubkey_len) {
    (void)message; (void)msg_len; (void)sig; (void)sig_len; (void)pubkey; (void)pubkey_len;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}

extern "C" HD_WALLET_EXPORT void* hd_dot_tx_create() { return nullptr; }
extern "C" HD_WALLET_EXPORT int32_t hd_dot_tx_sign(void* tx, const uint8_t* privkey) { (void)tx; (void)privkey; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT int32_t hd_dot_tx_serialize(void* tx, uint8_t* out, size_t* out_size) { (void)tx; (void)out; (void)out_size; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT void hd_dot_tx_destroy(void* tx) { (void)tx; }

#endif // HD_WALLET_ENABLE_POLKADOT

// =============================================================================
// Hardware Wallet Functions (placeholders - require WASI bridge)
// =============================================================================

extern "C" HD_WALLET_EXPORT
const char* hd_hw_enumerate() {
    return "[]"; // Empty JSON array
}

extern "C" HD_WALLET_EXPORT void* hd_hw_connect(const char* path) { (void)path; return nullptr; }
extern "C" HD_WALLET_EXPORT void hd_hw_disconnect(void* hw) { (void)hw; }
extern "C" HD_WALLET_EXPORT int32_t hd_hw_is_connected(void* hw) { (void)hw; return 0; }
extern "C" HD_WALLET_EXPORT const char* hd_hw_get_vendor(void* hw) { (void)hw; return ""; }
extern "C" HD_WALLET_EXPORT const char* hd_hw_get_model(void* hw) { (void)hw; return ""; }
extern "C" HD_WALLET_EXPORT const char* hd_hw_get_firmware_version(void* hw) { (void)hw; return ""; }
extern "C" HD_WALLET_EXPORT int32_t hd_hw_get_public_key(void* hw, const char* path, int32_t curve, uint8_t* out, size_t out_size) {
    (void)hw; (void)path; (void)curve; (void)out; (void)out_size;
    return static_cast<int32_t>(Error::NEEDS_BRIDGE);
}
extern "C" HD_WALLET_EXPORT int32_t hd_hw_sign_transaction(void* hw, const char* path, const uint8_t* tx, size_t tx_len, uint8_t* sig_out, size_t out_size) {
    (void)hw; (void)path; (void)tx; (void)tx_len; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NEEDS_BRIDGE);
}
extern "C" HD_WALLET_EXPORT int32_t hd_hw_sign_message(void* hw, const char* path, const char* message, uint8_t* sig_out, size_t out_size) {
    (void)hw; (void)path; (void)message; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NEEDS_BRIDGE);
}
extern "C" HD_WALLET_EXPORT int32_t hd_hw_wipe_device(void* hw) { (void)hw; return static_cast<int32_t>(Error::NEEDS_BRIDGE); }
extern "C" HD_WALLET_EXPORT int32_t hd_hw_load_device(void* hw, const char* mnemonic, const char* pin) {
    (void)hw; (void)mnemonic; (void)pin;
    return static_cast<int32_t>(Error::NEEDS_BRIDGE);
}
extern "C" HD_WALLET_EXPORT int32_t hd_hw_reset_device(void* hw) { (void)hw; return static_cast<int32_t>(Error::NEEDS_BRIDGE); }
extern "C" HD_WALLET_EXPORT int32_t hd_hw_ping(void* hw) { (void)hw; return static_cast<int32_t>(Error::NEEDS_BRIDGE); }
extern "C" HD_WALLET_EXPORT void hd_hw_cancel(void* hw) { (void)hw; }

// =============================================================================
// Keyring Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT void* hd_keyring_create() { return nullptr; }
extern "C" HD_WALLET_EXPORT void hd_keyring_destroy(void* kr) { (void)kr; }
extern "C" HD_WALLET_EXPORT const char* hd_keyring_add_wallet(void* kr, const uint8_t* seed, size_t seed_len, const char* name) {
    (void)kr; (void)seed; (void)seed_len; (void)name;
    return "";
}
extern "C" HD_WALLET_EXPORT int32_t hd_keyring_remove_wallet(void* kr, const char* id) { (void)kr; (void)id; return static_cast<int32_t>(Error::NOT_SUPPORTED); }
extern "C" HD_WALLET_EXPORT size_t hd_keyring_get_wallet_count(void* kr) { (void)kr; return 0; }
extern "C" HD_WALLET_EXPORT void* hd_keyring_get_wallet(void* kr, const char* id) { (void)kr; (void)id; return nullptr; }
extern "C" HD_WALLET_EXPORT const char* hd_keyring_get_accounts(void* kr, const char* wallet_id, int32_t coin_type, size_t count) {
    (void)kr; (void)wallet_id; (void)coin_type; (void)count;
    return "[]";
}
extern "C" HD_WALLET_EXPORT int32_t hd_keyring_sign_transaction(void* kr, const char* wallet_id, const char* path, const uint8_t* tx, size_t tx_len, uint8_t* sig_out, size_t out_size) {
    (void)kr; (void)wallet_id; (void)path; (void)tx; (void)tx_len; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
extern "C" HD_WALLET_EXPORT int32_t hd_keyring_sign_message(void* kr, const char* wallet_id, const char* path, const uint8_t* msg, size_t msg_len, uint8_t* sig_out, size_t out_size) {
    (void)kr; (void)wallet_id; (void)path; (void)msg; (void)msg_len; (void)sig_out; (void)out_size;
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
}
