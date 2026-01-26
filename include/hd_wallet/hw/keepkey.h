/**
 * @file keepkey.h
 * @brief KeepKey Hardware Wallet Implementation
 *
 * This module provides the KeepKey-specific implementation of the
 * hardware wallet interface. KeepKey uses a protocol similar to
 * Trezor (based on the original Trezor protocol).
 *
 * Protocol Overview:
 * - Message-based communication over HID
 * - Protobuf-encoded messages
 * - Channel ID: 0x4B4B ("KK")
 * - Report size: 64 bytes
 *
 * Supported Operations:
 * - Device initialization and PIN entry
 * - Public key derivation (secp256k1, ed25519)
 * - Bitcoin transaction signing (P2PKH, P2SH, P2WPKH, P2TR)
 * - Ethereum transaction signing
 * - Message signing
 *
 * Note: This implementation focuses on the protocol logic.
 * Actual I/O is handled through the WASI bridge.
 */

#ifndef HD_WALLET_HW_KEEPKEY_H
#define HD_WALLET_HW_KEEPKEY_H

#include "../config.h"
#include "../types.h"
#include "hw_wallet.h"
#include "hw_transport.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace hd_wallet {
namespace hw {

// =============================================================================
// KeepKey Constants
// =============================================================================

namespace keepkey {

/// KeepKey channel ID ("KK")
constexpr uint16_t CHANNEL_ID = 0x4B4B;

/// Message magic byte
constexpr uint8_t MESSAGE_MAGIC = 0x3F;

/// Maximum message size
constexpr size_t MAX_MESSAGE_SIZE = 64 * 1024;

// Message types (subset of supported messages)
enum class MessageType : uint16_t {
  // General
  INITIALIZE = 0,
  PING = 1,
  SUCCESS = 2,
  FAILURE = 3,
  CHANGE_PIN = 4,
  WIPE_DEVICE = 5,
  GET_ENTROPY = 9,
  ENTROPY = 10,
  LOAD_DEVICE = 13,
  RESET_DEVICE = 14,
  FEATURES = 17,
  PIN_MATRIX_REQUEST = 18,
  PIN_MATRIX_ACK = 19,
  CANCEL = 20,
  CLEAR_SESSION = 24,
  APPLY_SETTINGS = 25,
  BUTTON_REQUEST = 26,
  BUTTON_ACK = 27,
  PASSPHRASE_REQUEST = 41,
  PASSPHRASE_ACK = 42,

  // Crypto
  GET_PUBLIC_KEY = 11,
  PUBLIC_KEY = 12,
  SIGN_TX = 15,
  TX_REQUEST = 21,
  TX_ACK = 22,
  SIGN_MESSAGE = 38,
  VERIFY_MESSAGE = 39,
  MESSAGE_SIGNATURE = 40,
  SIGN_IDENTITY = 53,
  SIGNED_IDENTITY = 54,

  // Ethereum
  ETHEREUM_GET_ADDRESS = 56,
  ETHEREUM_ADDRESS = 57,
  ETHEREUM_SIGN_TX = 58,
  ETHEREUM_TX_REQUEST = 59,
  ETHEREUM_TX_ACK = 60,
  ETHEREUM_SIGN_MESSAGE = 64,
  ETHEREUM_MESSAGE_SIGNATURE = 66,
  ETHEREUM_SIGN_TYPED_DATA = 464,
  ETHEREUM_TYPED_DATA_SIGNATURE = 465,

  // Device
  GET_FEATURES = 55,
  FIRMWARE_ERASE = 6,
  FIRMWARE_UPLOAD = 7,
  SELF_TEST = 32
};

/// Button request types
enum class ButtonRequestType : uint8_t {
  OTHER = 1,
  FEE_OVER_THRESHOLD = 2,
  CONFIRM_OUTPUT = 3,
  RESET_DEVICE = 4,
  CONFIRM_WORD = 5,
  WIPE_DEVICE = 6,
  PROTECT_CALL = 7,
  SIGN_TX = 8,
  FIRMWARE_CHECK = 9,
  ADDRESS = 10,
  PUBLIC_KEY = 11,
  MNEMONIC_WORD_COUNT = 12,
  MNEMONIC_INPUT = 13,
  PASSPHRASE_TYPE = 14,
  UNKNOWN = 0xFF
};

/// Failure codes
enum class FailureCode : uint8_t {
  UNEXPECTED_MESSAGE = 1,
  BUTTON_EXPECTED = 2,
  DATA_ERROR = 3,
  ACTION_CANCELLED = 4,
  PIN_EXPECTED = 5,
  PIN_CANCELLED = 6,
  PIN_INVALID = 7,
  INVALID_SIGNATURE = 8,
  PROCESS_ERROR = 9,
  NOT_ENOUGH_FUNDS = 10,
  NOT_INITIALIZED = 11,
  PIN_MISMATCH = 12,
  FIRMWARE_ERROR = 99
};

/// Get failure code description
const char* failureCodeToString(FailureCode code);

} // namespace keepkey

// =============================================================================
// KeepKey Wallet Implementation
// =============================================================================

/**
 * KeepKey hardware wallet implementation
 *
 * Implements the HardwareWallet interface for KeepKey devices.
 */
class KeepKeyWallet : public HardwareWallet {
public:
  /**
   * Construct KeepKey wallet
   */
  KeepKeyWallet();

  /**
   * Destructor - disconnects if connected
   */
  ~KeepKeyWallet() override;

  // Non-copyable
  KeepKeyWallet(const KeepKeyWallet&) = delete;
  KeepKeyWallet& operator=(const KeepKeyWallet&) = delete;

  // Movable
  KeepKeyWallet(KeepKeyWallet&& other) noexcept;
  KeepKeyWallet& operator=(KeepKeyWallet&& other) noexcept;

  // ----- HardwareWallet Interface -----

  Result<void> connect(const HardwareWalletDevice& device) override;
  void disconnect() override;
  bool isConnected() const override;
  ConnectionState connectionState() const override;

  Result<DeviceFeatures> initialize() override;
  const DeviceFeatures& features() const override;
  DeviceType deviceType() const override { return DeviceType::KEEPKEY; }

  Result<void> enterPin(const std::string& pin) override;
  Result<void> enterPassphrase(const std::string& passphrase) override;
  Result<void> cancel() override;

  Result<Bytes33> getPublicKey(
    const std::string& path,
    bool display = false
  ) override;

  Result<std::string> getExtendedPublicKey(
    const std::string& path,
    bool display = false
  ) override;

  Result<std::string> getAddress(
    const std::string& path,
    CoinType coin_type,
    bool display = false
  ) override;

  Result<SignedTransaction> signBitcoinTransaction(
    const BitcoinTransaction& tx
  ) override;

  Result<SignedTransaction> signEthereumTransaction(
    const EthereumTransaction& tx
  ) override;

  Result<SignedMessage> signMessage(
    const std::string& path,
    const std::string& message
  ) override;

  Result<SignedMessage> signEthereumMessage(
    const std::string& path,
    const std::string& message
  ) override;

  Result<SignedMessage> signTypedData(
    const std::string& path,
    const Bytes32& domain_separator,
    const Bytes32& struct_hash
  ) override;

  void setPinCallback(callbacks::PinEntryCallback callback) override;
  void setPassphraseCallback(callbacks::PassphraseCallback callback) override;
  void setConfirmCallback(callbacks::ConfirmCallback callback) override;
  void setButtonCallback(callbacks::ButtonCallback callback) override;
  void setProgressCallback(callbacks::ProgressCallback callback) override;

  // ----- KeepKey-specific Methods -----

  /**
   * Ping the device
   * @param message Message to echo
   * @return Echoed message
   */
  Result<std::string> ping(const std::string& message);

  /**
   * Get device entropy
   * @param size Number of bytes to request
   * @return Random bytes from device
   */
  Result<ByteVector> getEntropy(size_t size);

  /**
   * Clear current session (resets PIN/passphrase state)
   */
  Result<void> clearSession();

  /**
   * Apply device settings
   * @param label New device label (empty to keep current)
   * @param use_passphrase Enable/disable passphrase
   * @param language Display language
   */
  Result<void> applySettings(
    const std::string& label = "",
    std::optional<bool> use_passphrase = std::nullopt,
    const std::string& language = ""
  );

  /**
   * Wipe device (factory reset)
   * Requires user confirmation on device.
   */
  Result<void> wipeDevice();

  /**
   * Change device PIN
   * @param remove If true, remove PIN protection
   */
  Result<void> changePin(bool remove = false);

private:
  std::unique_ptr<HidTransport> transport_;
  DeviceFeatures features_;
  ConnectionState state_ = ConnectionState::DISCONNECTED;

  // Callbacks
  callbacks::PinEntryCallback pin_callback_;
  callbacks::PassphraseCallback passphrase_callback_;
  callbacks::ConfirmCallback confirm_callback_;
  callbacks::ButtonCallback button_callback_;
  callbacks::ProgressCallback progress_callback_;

  // Protocol helpers
  Result<void> sendMessage(keepkey::MessageType type, const ByteVector& data);
  Result<std::pair<keepkey::MessageType, ByteVector>> receiveMessage(uint32_t timeout_ms = 0);
  Result<std::pair<keepkey::MessageType, ByteVector>> exchange(
    keepkey::MessageType type,
    const ByteVector& data,
    uint32_t timeout_ms = 0
  );

  // Handle device requests (PIN, button, passphrase)
  Result<std::pair<keepkey::MessageType, ByteVector>> handleDeviceRequest(
    keepkey::MessageType type,
    const ByteVector& data,
    uint32_t timeout_ms = 0
  );

  // Message encoding/decoding
  ByteVector encodeMessage(keepkey::MessageType type, const ByteVector& data);
  Result<std::pair<keepkey::MessageType, ByteVector>> decodeMessage(const ByteVector& data);

  // Path encoding
  ByteVector encodePath(const std::string& path);

  // Transaction helpers
  ByteVector encodeBitcoinTxInput(const BitcoinTxInput& input, uint32_t index);
  ByteVector encodeBitcoinTxOutput(const BitcoinTxOutput& output, uint32_t index);
  ByteVector encodeEthereumTx(const EthereumTransaction& tx);

  // Feature parsing
  void parseFeatures(const ByteVector& data);
};

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create KeepKey wallet instance
 */
std::unique_ptr<KeepKeyWallet> createKeepKeyWallet();

} // namespace hw
} // namespace hd_wallet

#endif // HD_WALLET_HW_KEEPKEY_H
