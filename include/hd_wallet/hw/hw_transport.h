/**
 * @file hw_transport.h
 * @brief Hardware Wallet Transport Layer Abstraction
 *
 * This module provides the transport layer abstraction for hardware wallet
 * communication. It handles the low-level communication protocol including:
 *
 * - HID message framing (64-byte packets)
 * - Timeout handling with configurable thresholds
 * - Connection state management
 * - Error recovery and retry logic
 *
 * The transport layer uses WASI bridge callbacks for actual USB/HID I/O,
 * allowing the library to work in WASM environments with host-provided
 * USB access.
 */

#ifndef HD_WALLET_HW_TRANSPORT_H
#define HD_WALLET_HW_TRANSPORT_H

#include "../config.h"
#include "../types.h"
#include "../wasi_bridge.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Constants
// =============================================================================

/// Standard HID report size for hardware wallets
constexpr size_t HID_REPORT_SIZE = 64;

/// Default timeout for device operations (ms)
constexpr uint32_t DEFAULT_TIMEOUT_MS = 30000;

/// Default timeout for user interaction (ms)
constexpr uint32_t USER_INTERACTION_TIMEOUT_MS = 120000;

/// Maximum message size (256 KB)
constexpr size_t MAX_MESSAGE_SIZE = 256 * 1024;

/// Number of retries on transient errors
constexpr int MAX_RETRY_COUNT = 3;

/// Delay between retries (ms)
constexpr uint32_t RETRY_DELAY_MS = 100;

// =============================================================================
// Transport Error Codes
// =============================================================================

/**
 * Transport-specific error codes
 */
enum class TransportError : int32_t {
  /// Success
  OK = 0,

  /// Device not connected
  NOT_CONNECTED = 1,

  /// Device disconnected during operation
  DISCONNECTED = 2,

  /// Operation timed out
  TIMEOUT = 3,

  /// Write operation failed
  WRITE_FAILED = 4,

  /// Read operation failed
  READ_FAILED = 5,

  /// Invalid response from device
  INVALID_RESPONSE = 6,

  /// Message too large
  MESSAGE_TOO_LARGE = 7,

  /// Transport not initialized
  NOT_INITIALIZED = 8,

  /// Protocol error (framing, checksum, etc.)
  PROTOCOL_ERROR = 9,

  /// Device busy
  DEVICE_BUSY = 10,

  /// User cancelled operation on device
  USER_CANCELLED = 11,

  /// Bridge not available
  BRIDGE_NOT_AVAILABLE = 12
};

/**
 * Convert transport error to string
 */
const char* transportErrorToString(TransportError error);

/**
 * Convert transport error to library Error
 */
Error transportErrorToError(TransportError error);

// =============================================================================
// Transport Configuration
// =============================================================================

/**
 * Transport configuration options
 */
struct TransportConfig {
  /// Timeout for standard operations (ms)
  uint32_t timeout_ms = DEFAULT_TIMEOUT_MS;

  /// Timeout for operations requiring user interaction (ms)
  uint32_t user_interaction_timeout_ms = USER_INTERACTION_TIMEOUT_MS;

  /// Number of retry attempts on transient errors
  int max_retries = MAX_RETRY_COUNT;

  /// Delay between retries (ms)
  uint32_t retry_delay_ms = RETRY_DELAY_MS;

  /// Enable debug logging
  bool debug_logging = false;
};

// =============================================================================
// Message Frame
// =============================================================================

/**
 * Represents a framed message for HID transport
 *
 * Most hardware wallets use a simple framing protocol:
 * - First packet: [channel_id (2)] [command_tag (1)] [sequence (2)] [length (4)] [data...]
 * - Subsequent packets: [channel_id (2)] [command_tag (1)] [sequence (2)] [data...]
 */
struct MessageFrame {
  uint16_t channel_id = 0;
  uint8_t command_tag = 0;
  uint16_t sequence = 0;
  ByteVector data;

  /// Total size of framed message
  size_t totalSize() const;

  /// Number of HID packets needed
  size_t packetCount() const;
};

// =============================================================================
// HID Transport
// =============================================================================

/**
 * HID Transport - Low-level USB HID communication
 *
 * This class handles the framing and transmission of messages over USB HID.
 * It uses the WASI bridge for actual USB I/O operations.
 */
class HidTransport {
public:
  /**
   * Construct HID transport with optional configuration
   */
  explicit HidTransport(const TransportConfig& config = TransportConfig());

  /**
   * Destructor - closes connection if open
   */
  ~HidTransport();

  // Non-copyable
  HidTransport(const HidTransport&) = delete;
  HidTransport& operator=(const HidTransport&) = delete;

  // Movable
  HidTransport(HidTransport&& other) noexcept;
  HidTransport& operator=(HidTransport&& other) noexcept;

  // ----- Connection Management -----

  /**
   * Open connection to device
   * @param path Device path from enumeration
   * @return Error code
   */
  TransportError open(const std::string& path);

  /**
   * Close connection
   */
  void close();

  /**
   * Check if connected
   */
  bool isConnected() const { return handle_ > 0; }

  /**
   * Get device path
   */
  const std::string& devicePath() const { return device_path_; }

  // ----- Raw I/O -----

  /**
   * Write raw data to device
   * @param data Data to write (will be padded to HID_REPORT_SIZE)
   * @return Error code
   */
  TransportError writeRaw(const ByteVector& data);

  /**
   * Read raw data from device
   * @param buffer Output buffer
   * @param timeout_ms Timeout (0 = use default)
   * @return Error code (data in buffer)
   */
  TransportError readRaw(ByteVector& buffer, uint32_t timeout_ms = 0);

  // ----- Framed I/O -----

  /**
   * Send a framed message
   *
   * Automatically handles:
   * - Message fragmentation into HID packets
   * - Sequence numbering
   * - Packet padding
   *
   * @param channel_id Channel identifier
   * @param command_tag Command tag byte
   * @param data Message data
   * @return Error code
   */
  TransportError sendMessage(
    uint16_t channel_id,
    uint8_t command_tag,
    const ByteVector& data
  );

  /**
   * Receive a framed message
   *
   * Automatically handles:
   * - Packet reassembly
   * - Sequence verification
   * - Timeout handling
   *
   * @param channel_id Expected channel identifier
   * @param command_tag Expected command tag
   * @param data Output buffer for message data
   * @param timeout_ms Timeout (0 = use default)
   * @return Error code
   */
  TransportError receiveMessage(
    uint16_t channel_id,
    uint8_t command_tag,
    ByteVector& data,
    uint32_t timeout_ms = 0
  );

  /**
   * Send message and wait for response
   *
   * Convenience method combining sendMessage and receiveMessage.
   *
   * @param channel_id Channel identifier
   * @param command_tag Command tag byte
   * @param request Request data
   * @param response Output buffer for response
   * @param timeout_ms Timeout (0 = use default)
   * @return Error code
   */
  TransportError exchange(
    uint16_t channel_id,
    uint8_t command_tag,
    const ByteVector& request,
    ByteVector& response,
    uint32_t timeout_ms = 0
  );

  // ----- Configuration -----

  /**
   * Get current configuration
   */
  const TransportConfig& config() const { return config_; }

  /**
   * Update configuration
   */
  void setConfig(const TransportConfig& config) { config_ = config; }

  /**
   * Set timeout for current operation
   */
  void setTimeout(uint32_t timeout_ms) { config_.timeout_ms = timeout_ms; }

private:
  TransportConfig config_;
  int32_t handle_ = 0;
  std::string device_path_;

  /// Frame a message into HID packets
  std::vector<ByteVector> frameMessage(
    uint16_t channel_id,
    uint8_t command_tag,
    const ByteVector& data
  );

  /// Unframe HID packets into message
  TransportError unframeMessage(
    const std::vector<ByteVector>& packets,
    uint16_t expected_channel,
    uint8_t expected_tag,
    ByteVector& data
  );
};

// =============================================================================
// Transport Factory
// =============================================================================

/**
 * Create transport instance
 *
 * Factory function that creates the appropriate transport based on
 * available WASI bridge capabilities.
 */
std::unique_ptr<HidTransport> createTransport(
  const TransportConfig& config = TransportConfig()
);

// =============================================================================
// Device Discovery
// =============================================================================

/**
 * Hardware wallet device type
 */
enum class DeviceType {
  UNKNOWN = 0,
  KEEPKEY = 1,
  TREZOR_ONE = 2,
  TREZOR_T = 3,
  LEDGER_NANO_S = 4,
  LEDGER_NANO_X = 5,
  LEDGER_NANO_S_PLUS = 6
};

/**
 * Get device type name
 */
const char* deviceTypeToString(DeviceType type);

/**
 * Discovered hardware wallet device
 */
struct HardwareWalletDevice {
  DeviceType type = DeviceType::UNKNOWN;
  std::string path;
  std::string serial_number;
  std::string manufacturer;
  std::string product;
  uint16_t vendor_id = 0;
  uint16_t product_id = 0;
  int interface_number = 0;
};

/**
 * Known vendor/product IDs for hardware wallets
 */
namespace DeviceIds {
  // KeepKey
  constexpr uint16_t KEEPKEY_VID = 0x2B24;
  constexpr uint16_t KEEPKEY_PID = 0x0001;

  // Trezor
  constexpr uint16_t TREZOR_VID = 0x534C;
  constexpr uint16_t TREZOR_ONE_PID = 0x0001;
  constexpr uint16_t TREZOR_T_PID = 0x0002;

  // Trezor (SatoshiLabs alternative VID)
  constexpr uint16_t SATOSHILABS_VID = 0x1209;
  constexpr uint16_t TREZOR_ONE_PID_ALT = 0x53C0;
  constexpr uint16_t TREZOR_T_PID_ALT = 0x53C1;

  // Ledger
  constexpr uint16_t LEDGER_VID = 0x2C97;
  constexpr uint16_t LEDGER_NANO_S_PID = 0x0001;
  constexpr uint16_t LEDGER_NANO_X_PID = 0x0004;
  constexpr uint16_t LEDGER_NANO_S_PLUS_PID = 0x5011;
}

/**
 * Enumerate connected hardware wallet devices
 *
 * Uses WASI bridge to discover connected devices and filters
 * to known hardware wallet vendor/product IDs.
 *
 * @return List of discovered devices
 */
std::vector<HardwareWalletDevice> enumerateDevices();

/**
 * Enumerate devices of a specific type
 *
 * @param type Device type to filter for
 * @return List of matching devices
 */
std::vector<HardwareWalletDevice> enumerateDevices(DeviceType type);

/**
 * Identify device type from vendor/product IDs
 *
 * @param vendor_id USB vendor ID
 * @param product_id USB product ID
 * @return Device type or UNKNOWN
 */
DeviceType identifyDevice(uint16_t vendor_id, uint16_t product_id);

} // namespace hw
} // namespace hd_wallet

#endif // HD_WALLET_HW_TRANSPORT_H
