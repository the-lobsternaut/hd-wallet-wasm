/**
 * @file wasi_bridge.cpp
 * @brief WASI Bridge Implementation
 *
 * Implements the WASI bridge system for providing host functionality
 * to WASM/WASI environments. This module manages:
 *
 * - Entropy pool for cryptographic operations
 * - USB/HID callbacks for hardware wallet support
 * - Network callbacks for RPC operations
 * - Filesystem callbacks for key storage
 * - Clock callbacks for timestamps
 *
 * In pure WASI environments, many system features are not directly available.
 * The bridge pattern allows host applications to provide these features
 * through registered callbacks.
 */

#include "hd_wallet/wasi_bridge.h"
#include "hd_wallet/config.h"
#include "hd_wallet/types.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>

#if HD_WALLET_IS_WASI
// WASI random_get syscall
extern "C" {
    __attribute__((import_module("wasi_snapshot_preview1")))
    __attribute__((import_name("random_get")))
    int32_t __wasi_random_get(uint8_t* buf, size_t buf_len);
}
#elif defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <Security/SecRandom.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fstream>
#endif

#if !HD_WALLET_IS_WASI
#include <chrono>
#endif

namespace hd_wallet {

// =============================================================================
// Entropy Pool Implementation
// =============================================================================

namespace {

/**
 * Thread-safe entropy pool
 *
 * Collects injected entropy and provides it to cryptographic operations.
 * Uses a simple mixing function to combine entropy sources.
 */
class EntropyPool {
public:
    static constexpr size_t POOL_SIZE = 256;
    static constexpr size_t MIN_ENTROPY = 32;

    EntropyPool() : pool_(POOL_SIZE, 0), index_(0), total_injected_(0) {}

    /**
     * Inject entropy into the pool
     */
    void inject(const uint8_t* data, size_t length) {
        std::lock_guard<std::mutex> lock(mutex_);

        for (size_t i = 0; i < length; ++i) {
            // XOR with existing pool data and mix
            pool_[index_] ^= data[i];

            // Simple mixing: rotate and XOR neighboring bytes
            size_t prev = (index_ + POOL_SIZE - 1) % POOL_SIZE;
            size_t next = (index_ + 1) % POOL_SIZE;
            pool_[index_] ^= static_cast<uint8_t>((pool_[prev] >> 3) | (pool_[next] << 5));

            index_ = (index_ + 1) % POOL_SIZE;
        }

        total_injected_ += length;
    }

    /**
     * Extract entropy from the pool
     *
     * Uses a deterministic extraction that updates the pool state.
     * Returns actual bytes extracted.
     */
    size_t extract(uint8_t* output, size_t length) {
        std::lock_guard<std::mutex> lock(mutex_);

        if (total_injected_ < MIN_ENTROPY) {
            return 0;
        }

        for (size_t i = 0; i < length; ++i) {
            // Extract from current position
            output[i] = pool_[index_];

            // Update pool state (feedback)
            pool_[index_] ^= static_cast<uint8_t>(i + 1);
            size_t prev = (index_ + POOL_SIZE - 1) % POOL_SIZE;
            pool_[prev] ^= output[i];

            index_ = (index_ + 1) % POOL_SIZE;
        }

        return length;
    }

    /**
     * Check if sufficient entropy is available
     */
    bool hasEntropy() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_injected_ >= MIN_ENTROPY;
    }

    /**
     * Get total bytes of entropy injected
     */
    size_t totalInjected() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_injected_;
    }

    /**
     * Clear the entropy pool
     */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);

        // Secure wipe
        volatile uint8_t* volatile_ptr = pool_.data();
        for (size_t i = 0; i < pool_.size(); ++i) {
            volatile_ptr[i] = 0;
        }

        index_ = 0;
        total_injected_ = 0;
    }

private:
    mutable std::mutex mutex_;
    std::vector<uint8_t> pool_;
    size_t index_;
    size_t total_injected_;
};

// Global entropy pool instance
EntropyPool& getEntropyPool() {
    static EntropyPool pool;
    return pool;
}

} // anonymous namespace

// =============================================================================
// WasiBridge Implementation
// =============================================================================

WasiBridge::WasiBridge()
    : entropy_initialized_(false) {}

WasiBridge& WasiBridge::instance() {
    static WasiBridge instance;
    return instance;
}

// ----- Feature Availability -----

bool WasiBridge::hasFeature(WasiFeature feature) const {
    switch (feature) {
        case WasiFeature::RANDOM:
#if HD_WALLET_IS_WASI
            // In WASI, need either entropy callback or injected entropy
            return entropy_callback_ || getEntropyPool().hasEntropy();
#else
            // Native has system RNG
            return true;
#endif

        case WasiFeature::FILESYSTEM:
#if HD_WALLET_IS_WASI
            return file_read_ || file_write_;
#else
            return true;
#endif

        case WasiFeature::NETWORK:
#if HD_WALLET_IS_WASI
            return static_cast<bool>(http_request_);
#else
            return true;
#endif

        case WasiFeature::USB_HID:
            // Always requires bridge - no native USB in WASM
            return hid_enumerate_ && hid_open_ && hid_close_ &&
                   hid_write_ && hid_read_;

        case WasiFeature::CLOCK:
#if HD_WALLET_IS_WASI
            return static_cast<bool>(get_time_);
#else
            return true;
#endif

        case WasiFeature::ENVIRONMENT:
#if HD_WALLET_IS_WASI
            // WASI provides env access by default
            return true;
#else
            return true;
#endif

        default:
            return false;
    }
}

WasiWarning WasiBridge::getWarning(WasiFeature feature) const {
    if (hasFeature(feature)) {
        return WasiWarning::NONE;
    }

    switch (feature) {
        case WasiFeature::RANDOM:
            return WasiWarning::NEEDS_ENTROPY;

        case WasiFeature::USB_HID:
            return WasiWarning::NEEDS_BRIDGE;

        case WasiFeature::NETWORK:
        case WasiFeature::FILESYSTEM:
#if HD_WALLET_IS_WASI
            return WasiWarning::NEEDS_BRIDGE;
#else
            return WasiWarning::NONE;
#endif

        case WasiFeature::CLOCK:
#if HD_WALLET_IS_WASI
            return WasiWarning::NEEDS_CAPABILITY;
#else
            return WasiWarning::NONE;
#endif

        default:
            return WasiWarning::NOT_AVAILABLE_WASI;
    }
}

std::string WasiBridge::getWarningMessage(WasiFeature feature) const {
    WasiWarning warning = getWarning(feature);

    switch (warning) {
        case WasiWarning::NONE:
            return "";

        case WasiWarning::NEEDS_ENTROPY:
            return "Random number generation requires entropy injection. "
                   "Call hd_inject_entropy() before cryptographic operations.";

        case WasiWarning::NEEDS_BRIDGE:
            switch (feature) {
                case WasiFeature::USB_HID:
                    return "USB/HID access requires host bridge callbacks. "
                           "Register HID callbacks via setHidEnumerateCallback(), etc.";
                case WasiFeature::NETWORK:
                    return "Network access requires host bridge callback. "
                           "Register HTTP callback via setHttpRequestCallback().";
                case WasiFeature::FILESYSTEM:
                    return "Filesystem access requires host bridge callbacks. "
                           "Register file callbacks via setFileReadCallback(), etc.";
                default:
                    return "Feature requires host bridge callback.";
            }

        case WasiWarning::NOT_AVAILABLE_WASI:
            return "Feature not available in WASI environment.";

        case WasiWarning::DISABLED_FIPS:
            return "Feature disabled in FIPS compliance mode.";

        case WasiWarning::NEEDS_CAPABILITY:
            return "Feature requires specific WASI capability from runtime.";

        default:
            return "Unknown warning.";
    }
}

// ----- Entropy -----

void WasiBridge::setEntropyCallback(callbacks::EntropyCallback callback) {
    entropy_callback_ = std::move(callback);
}

int32_t WasiBridge::getEntropy(uint8_t* buffer, size_t length) {
    if (buffer == nullptr || length == 0) {
        return -1;
    }

    // Try callback first (allows host to override)
    if (entropy_callback_) {
        return entropy_callback_(buffer, length);
    }

    // Try entropy pool (for manually injected entropy)
    if (getEntropyPool().hasEntropy()) {
        size_t extracted = getEntropyPool().extract(buffer, length);
        return static_cast<int32_t>(extracted);
    }

#if HD_WALLET_IS_WASI
    // WASI: Use the random_get syscall for cryptographically secure entropy
    int32_t result = __wasi_random_get(buffer, length);
    if (result == 0) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(__linux__)
    // Linux: Use getrandom() for cryptographically secure entropy
    ssize_t result = getrandom(buffer, length, 0);
    if (result >= 0 && static_cast<size_t>(result) == length) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(__APPLE__)
    // macOS/iOS: Use SecRandomCopyBytes for cryptographically secure entropy
    int result = SecRandomCopyBytes(kSecRandomDefault, length, buffer);
    if (result == errSecSuccess) {
        return static_cast<int32_t>(length);
    }
    return -1;
#elif defined(_WIN32)
    // Windows: Use BCryptGenRandom for cryptographically secure entropy
    NTSTATUS status = BCryptGenRandom(NULL, buffer, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (BCRYPT_SUCCESS(status)) {
        return static_cast<int32_t>(length);
    }
    return -1;
#else
    // Fallback: Read from /dev/urandom
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    if (urandom.good()) {
        urandom.read(reinterpret_cast<char*>(buffer), length);
        if (urandom.gcount() == static_cast<std::streamsize>(length)) {
            return static_cast<int32_t>(length);
        }
    }
    return -1;
#endif
}

void WasiBridge::injectEntropy(const uint8_t* entropy, size_t length) {
    if (entropy == nullptr || length == 0) {
        return;
    }
    getEntropyPool().inject(entropy, length);
    entropy_initialized_ = true;
}

bool WasiBridge::hasEntropy() const {
    return entropy_callback_ || getEntropyPool().hasEntropy();
}

// ----- USB/HID -----

void WasiBridge::setHidEnumerateCallback(callbacks::HidEnumerateCallback callback) {
    hid_enumerate_ = std::move(callback);
}

void WasiBridge::setHidOpenCallback(callbacks::HidOpenCallback callback) {
    hid_open_ = std::move(callback);
}

void WasiBridge::setHidCloseCallback(callbacks::HidCloseCallback callback) {
    hid_close_ = std::move(callback);
}

void WasiBridge::setHidWriteCallback(callbacks::HidWriteCallback callback) {
    hid_write_ = std::move(callback);
}

void WasiBridge::setHidReadCallback(callbacks::HidReadCallback callback) {
    hid_read_ = std::move(callback);
}

std::vector<HidDeviceInfo> WasiBridge::hidEnumerate() {
    if (!hid_enumerate_) {
        return {};
    }
    return hid_enumerate_();
}

int32_t WasiBridge::hidOpen(const std::string& path) {
    if (!hid_open_) {
        return -1;
    }
    return hid_open_(path);
}

void WasiBridge::hidClose(int32_t handle) {
    if (hid_close_) {
        hid_close_(handle);
    }
}

int32_t WasiBridge::hidWrite(int32_t handle, const std::vector<uint8_t>& data) {
    if (!hid_write_) {
        return -1;
    }
    return hid_write_(handle, data);
}

int32_t WasiBridge::hidRead(int32_t handle, uint8_t* buffer,
                            size_t max_length, uint32_t timeout_ms) {
    if (!hid_read_) {
        return -1;
    }
    return hid_read_(handle, buffer, max_length, timeout_ms);
}

// ----- Network -----

void WasiBridge::setHttpRequestCallback(callbacks::HttpRequestCallback callback) {
    http_request_ = std::move(callback);
}

callbacks::HttpResponse WasiBridge::httpRequest(
    const std::string& method,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const std::string& body) {
    if (!http_request_) {
        return {-1, "No HTTP callback registered", {}};
    }
    return http_request_(method, url, headers, body);
}

// ----- Filesystem -----

void WasiBridge::setFileReadCallback(callbacks::FileReadCallback callback) {
    file_read_ = std::move(callback);
}

void WasiBridge::setFileWriteCallback(callbacks::FileWriteCallback callback) {
    file_write_ = std::move(callback);
}

void WasiBridge::setFileExistsCallback(callbacks::FileExistsCallback callback) {
    file_exists_ = std::move(callback);
}

void WasiBridge::setFileDeleteCallback(callbacks::FileDeleteCallback callback) {
    file_delete_ = std::move(callback);
}

std::vector<uint8_t> WasiBridge::fileRead(const std::string& path) {
    if (!file_read_) {
        return {};
    }
    return file_read_(path);
}

bool WasiBridge::fileWrite(const std::string& path, const std::vector<uint8_t>& data) {
    if (!file_write_) {
        return false;
    }
    return file_write_(path, data);
}

bool WasiBridge::fileExists(const std::string& path) {
    if (!file_exists_) {
        return false;
    }
    return file_exists_(path);
}

bool WasiBridge::fileDelete(const std::string& path) {
    if (!file_delete_) {
        return false;
    }
    return file_delete_(path);
}

// ----- Clock -----

void WasiBridge::setGetTimeCallback(callbacks::GetTimeCallback callback) {
    get_time_ = std::move(callback);
}

int64_t WasiBridge::getTime() {
    if (get_time_) {
        return get_time_();
    }

#if !HD_WALLET_IS_WASI
    // Native: use system time
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
#else
    // WASI without callback
    return -1;
#endif
}

// ----- Reset -----

void WasiBridge::reset() {
    entropy_callback_ = nullptr;
    hid_enumerate_ = nullptr;
    hid_open_ = nullptr;
    hid_close_ = nullptr;
    hid_write_ = nullptr;
    hid_read_ = nullptr;
    http_request_ = nullptr;
    file_read_ = nullptr;
    file_write_ = nullptr;
    file_exists_ = nullptr;
    file_delete_ = nullptr;
    get_time_ = nullptr;

    // Clear entropy pool
    getEntropyPool().clear();
    entropy_initialized_ = false;
}

// =============================================================================
// C API Implementation
// =============================================================================

namespace {

// Thread-local storage for warning messages
thread_local std::string warning_message_buffer;

} // anonymous namespace

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_has_feature(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return 0;
    }
    return WasiBridge::instance().hasFeature(static_cast<WasiFeature>(feature)) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_get_warning(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return static_cast<int32_t>(WasiWarning::NOT_AVAILABLE_WASI);
    }
    return static_cast<int32_t>(
        WasiBridge::instance().getWarning(static_cast<WasiFeature>(feature))
    );
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_wasi_get_warning_message(int32_t feature) {
    if (feature < 0 || feature >= static_cast<int32_t>(WasiFeature::COUNT)) {
        return "Invalid feature code";
    }
    warning_message_buffer = WasiBridge::instance().getWarningMessage(
        static_cast<WasiFeature>(feature)
    );
    return warning_message_buffer.c_str();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_inject_entropy(const uint8_t* entropy, size_t length) {
    WasiBridge::instance().injectEntropy(entropy, length);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_entropy_status() {
    // Returns:
    //  0 = No entropy available
    //  1 = Entropy callback set
    //  2 = Entropy pool has sufficient entropy
    //  3 = Both callback and pool available

    int32_t status = 0;
    auto& bridge = WasiBridge::instance();

    if (bridge.hasEntropy()) {
        status |= 2;
    }

    return status;
}

// =============================================================================
// Additional C API Functions
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_random(uint8_t* buffer, size_t length) {
    return WasiBridge::instance().getEntropy(buffer, length);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_wasi_reset() {
    WasiBridge::instance().reset();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_version() {
    return HD_WALLET_VERSION_STRING;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_major() {
    return HD_WALLET_VERSION_MAJOR;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_minor() {
    return HD_WALLET_VERSION_MINOR;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version_patch() {
    return HD_WALLET_VERSION_PATCH;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_wasm() {
#if HD_WALLET_IS_WASM
    return 1;
#else
    return 0;
#endif
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_wasi() {
#if HD_WALLET_IS_WASI
    return 1;
#else
    return 0;
#endif
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_fips_mode() {
#if HD_WALLET_FIPS_MODE
    return 1;
#else
    return 0;
#endif
}

// Alias for hd_get_version (which already returns the version string)
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_version_string() {
    return HD_WALLET_VERSION_STRING;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_has_cryptopp() {
#if HD_WALLET_USE_CRYPTOPP
    return 1;
#else
    return 0;
#endif
}

// Static storage for coin list string
static std::string g_supported_coins;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
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
    if (g_supported_coins.size() > 1) {
        g_supported_coins.pop_back();
    }
    g_supported_coins += "]";
    return g_supported_coins.c_str();
}

// Static storage for curves list string
static std::string g_supported_curves;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_supported_curves() {
    g_supported_curves = "[\"secp256k1\",\"ed25519\",\"p256\",\"p384\",\"x25519\"]";
    return g_supported_curves.c_str();
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_curve_supported(int32_t curve) {
    switch (static_cast<Curve>(curve)) {
        case Curve::SECP256K1:
#if HD_WALLET_ENABLE_SECP256K1
            return 1;
#else
            return 0;
#endif
        case Curve::ED25519:
#if HD_WALLET_ENABLE_ED25519
            return 1;
#else
            return 0;
#endif
        case Curve::P256:
#if HD_WALLET_ENABLE_P256
            return 1;
#else
            return 0;
#endif
        case Curve::P384:
#if HD_WALLET_ENABLE_P384
            return 1;
#else
            return 0;
#endif
        case Curve::X25519:
#if HD_WALLET_ENABLE_X25519
            return 1;
#else
            return 0;
#endif
        default:
            return 0;
    }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_error_string(int32_t error_code) {
    return errorToString(static_cast<Error>(error_code));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_curve_string(int32_t curve) {
    return curveToString(static_cast<Curve>(curve));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_coin_type_string(int32_t coin_type) {
    return coinTypeToString(static_cast<CoinType>(coin_type));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_type_curve(int32_t coin_type) {
    return static_cast<int32_t>(coinTypeToCurve(static_cast<CoinType>(coin_type)));
}

} // namespace hd_wallet
