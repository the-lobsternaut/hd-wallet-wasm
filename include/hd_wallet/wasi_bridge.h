/**
 * @file wasi_bridge.h
 * @brief WASI Bridge - Host Callback System for WASM/WASI
 *
 * This module provides a callback-based bridge system for features that cannot
 * be implemented natively in WASM/WASI environments. It allows host applications
 * (in Go, Rust, Python, JavaScript, etc.) to provide implementations for:
 *
 * - USB/HID device communication (hardware wallets)
 * - Network operations (RPC calls, node communication)
 * - Filesystem access (key storage)
 * - Random number generation (entropy source)
 *
 * When a feature is not available, the library returns appropriate warnings
 * and error codes rather than silently failing.
 *
 * @example JavaScript Bridge Setup
 * ```javascript
 * const wasm = await HDWalletWasm();
 *
 * // Register USB/HID bridge for hardware wallet support
 * wasm.setBridge('usb_hid', {
 *   enumerate: async () => navigator.hid.getDevices(),
 *   connect: async (deviceId) => { ... },
 *   write: async (deviceId, data) => { ... },
 *   read: async (deviceId) => { ... }
 * });
 *
 * // Register network bridge for RPC calls
 * wasm.setBridge('network', {
 *   fetch: async (url, options) => fetch(url, options)
 * });
 * ```
 *
 * @example Go Bridge Setup (with wazero)
 * ```go
 * func main() {
 *     ctx := context.Background()
 *     runtime := wazero.NewRuntime(ctx)
 *
 *     // Register host functions
 *     _, err := runtime.NewHostModuleBuilder("hd_wallet_bridge").
 *         NewFunctionBuilder().WithFunc(usbEnumerate).Export("usb_enumerate").
 *         NewFunctionBuilder().WithFunc(usbConnect).Export("usb_connect").
 *         Instantiate(ctx)
 * }
 * ```
 */

#ifndef HD_WALLET_WASI_BRIDGE_H
#define HD_WALLET_WASI_BRIDGE_H

#include "config.h"
#include "types.h"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace hd_wallet {

// =============================================================================
// Callback Types
// =============================================================================

/**
 * USB/HID device descriptor returned by enumeration
 */
struct HidDeviceInfo {
  uint16_t vendor_id;
  uint16_t product_id;
  std::string serial_number;
  std::string manufacturer;
  std::string product;
  std::string path;
  int interface_number;
};

/**
 * Callback signatures for bridge functions.
 * These are the function types that host applications must implement.
 */
namespace callbacks {

// ----- Entropy -----

/// Callback to get random bytes from host
/// @param buffer Output buffer for random bytes
/// @param length Number of bytes requested
/// @return Number of bytes actually written, or negative on error
using EntropyCallback = std::function<int32_t(uint8_t* buffer, size_t length)>;

// ----- USB/HID (Hardware Wallets) -----

/// Enumerate available HID devices
/// @return List of device descriptors
using HidEnumerateCallback = std::function<std::vector<HidDeviceInfo>()>;

/// Open a connection to a HID device
/// @param path Device path from enumeration
/// @return Device handle (>0 on success, <=0 on error)
using HidOpenCallback = std::function<int32_t(const std::string& path)>;

/// Close a HID device connection
/// @param handle Device handle from open
using HidCloseCallback = std::function<void(int32_t handle)>;

/// Write data to HID device
/// @param handle Device handle
/// @param data Data to write
/// @return Bytes written, or negative on error
using HidWriteCallback = std::function<int32_t(int32_t handle, const std::vector<uint8_t>& data)>;

/// Read data from HID device
/// @param handle Device handle
/// @param buffer Output buffer
/// @param max_length Maximum bytes to read
/// @param timeout_ms Timeout in milliseconds (0 = no timeout)
/// @return Bytes read, or negative on error/timeout
using HidReadCallback = std::function<int32_t(int32_t handle, uint8_t* buffer, size_t max_length, uint32_t timeout_ms)>;

// ----- Network -----

/// HTTP response structure
struct HttpResponse {
  int32_t status_code;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;
};

/// Perform an HTTP request
/// @param method HTTP method (GET, POST, etc.)
/// @param url Request URL
/// @param headers Request headers
/// @param body Request body (for POST, PUT, etc.)
/// @return HTTP response
using HttpRequestCallback = std::function<HttpResponse(
  const std::string& method,
  const std::string& url,
  const std::vector<std::pair<std::string, std::string>>& headers,
  const std::string& body
)>;

// ----- Filesystem -----

/// Read a file
/// @param path File path
/// @return File contents, or empty on error
using FileReadCallback = std::function<std::vector<uint8_t>(const std::string& path)>;

/// Write a file
/// @param path File path
/// @param data Data to write
/// @return true on success
using FileWriteCallback = std::function<bool(const std::string& path, const std::vector<uint8_t>& data)>;

/// Check if file exists
/// @param path File path
/// @return true if file exists
using FileExistsCallback = std::function<bool(const std::string& path)>;

/// Delete a file
/// @param path File path
/// @return true on success
using FileDeleteCallback = std::function<bool(const std::string& path)>;

// ----- Clock -----

/// Get current Unix timestamp in milliseconds
using GetTimeCallback = std::function<int64_t()>;

} // namespace callbacks

// =============================================================================
// WASI Bridge Class
// =============================================================================

/**
 * WASI Bridge - Manages host callbacks for WASM/WASI features
 *
 * This singleton class manages the bridge between WASM code and host
 * functionality. Features check the bridge before attempting operations
 * and return appropriate warnings when bridges are not configured.
 */
class WasiBridge {
public:
  /**
   * Get the singleton instance
   */
  static WasiBridge& instance();

  // ----- Feature Availability -----

  /**
   * Check if a feature is available
   * @param feature Feature to check
   * @return true if feature is available (native or via bridge)
   */
  bool hasFeature(WasiFeature feature) const;

  /**
   * Get warning for unavailable feature
   * @param feature Feature to check
   * @return Warning code explaining why feature is unavailable
   */
  WasiWarning getWarning(WasiFeature feature) const;

  /**
   * Get human-readable warning message
   * @param feature Feature to check
   * @return Warning message string
   */
  std::string getWarningMessage(WasiFeature feature) const;

  // ----- Entropy -----

  /**
   * Set entropy callback (required for WASI)
   */
  void setEntropyCallback(callbacks::EntropyCallback callback);

  /**
   * Get random bytes
   * @param buffer Output buffer
   * @param length Number of bytes
   * @return Bytes written, or negative on error
   */
  int32_t getEntropy(uint8_t* buffer, size_t length);

  /**
   * Inject entropy from external source
   * This must be called before any cryptographic operations in WASI
   * @param entropy Entropy bytes (at least 32 bytes recommended)
   * @param length Entropy length
   */
  void injectEntropy(const uint8_t* entropy, size_t length);

  /**
   * Check if sufficient entropy is available
   */
  bool hasEntropy() const;

  // ----- USB/HID -----

  void setHidEnumerateCallback(callbacks::HidEnumerateCallback callback);
  void setHidOpenCallback(callbacks::HidOpenCallback callback);
  void setHidCloseCallback(callbacks::HidCloseCallback callback);
  void setHidWriteCallback(callbacks::HidWriteCallback callback);
  void setHidReadCallback(callbacks::HidReadCallback callback);

  std::vector<HidDeviceInfo> hidEnumerate();
  int32_t hidOpen(const std::string& path);
  void hidClose(int32_t handle);
  int32_t hidWrite(int32_t handle, const std::vector<uint8_t>& data);
  int32_t hidRead(int32_t handle, uint8_t* buffer, size_t max_length, uint32_t timeout_ms);

  // ----- Network -----

  void setHttpRequestCallback(callbacks::HttpRequestCallback callback);

  callbacks::HttpResponse httpRequest(
    const std::string& method,
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& headers = {},
    const std::string& body = ""
  );

  // ----- Filesystem -----

  void setFileReadCallback(callbacks::FileReadCallback callback);
  void setFileWriteCallback(callbacks::FileWriteCallback callback);
  void setFileExistsCallback(callbacks::FileExistsCallback callback);
  void setFileDeleteCallback(callbacks::FileDeleteCallback callback);

  std::vector<uint8_t> fileRead(const std::string& path);
  bool fileWrite(const std::string& path, const std::vector<uint8_t>& data);
  bool fileExists(const std::string& path);
  bool fileDelete(const std::string& path);

  // ----- Clock -----

  void setGetTimeCallback(callbacks::GetTimeCallback callback);
  int64_t getTime();

  // ----- Reset -----

  /**
   * Clear all callbacks (useful for testing)
   */
  void reset();

private:
  WasiBridge();
  ~WasiBridge() = default;
  WasiBridge(const WasiBridge&) = delete;
  WasiBridge& operator=(const WasiBridge&) = delete;

  // Thread safety for callback registration
  mutable std::mutex callback_mutex_;

  // Entropy state
  callbacks::EntropyCallback entropy_callback_;
  std::vector<uint8_t> entropy_pool_;
  size_t entropy_pool_index_ = 0;
  bool entropy_initialized_ = false;

  // HID callbacks
  callbacks::HidEnumerateCallback hid_enumerate_;
  callbacks::HidOpenCallback hid_open_;
  callbacks::HidCloseCallback hid_close_;
  callbacks::HidWriteCallback hid_write_;
  callbacks::HidReadCallback hid_read_;

  // Network callbacks
  callbacks::HttpRequestCallback http_request_;

  // Filesystem callbacks
  callbacks::FileReadCallback file_read_;
  callbacks::FileWriteCallback file_write_;
  callbacks::FileExistsCallback file_exists_;
  callbacks::FileDeleteCallback file_delete_;

  // Clock callback
  callbacks::GetTimeCallback get_time_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_has_feature(int32_t feature);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_wasi_get_warning(int32_t feature);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_wasi_get_warning_message(int32_t feature);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_inject_entropy(const uint8_t* entropy, size_t length);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_entropy_status();

} // namespace hd_wallet

#endif // HD_WALLET_WASI_BRIDGE_H
