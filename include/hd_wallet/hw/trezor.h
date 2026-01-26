/**
 * @file trezor.h
 * @brief Trezor Hardware Wallet Implementation
 *
 * This module provides the Trezor-specific implementation of the
 * hardware wallet interface. Supports both Trezor One and Trezor Model T.
 *
 * Protocol Overview:
 * - Message-based communication over HID (One) or WebUSB (Model T)
 * - Protobuf-encoded messages
 * - Channel ID: 0x0101 (magic "##")
 * - Report size: 64 bytes
 *
 * Model Differences:
 * - Trezor One: PIN entry via host (scrambled matrix)
 * - Trezor Model T: PIN entry on device touchscreen
 * - Model T has additional features (SD card, passphrase on device)
 *
 * Supported Operations:
 * - Device initialization and PIN entry
 * - Public key derivation (secp256k1, ed25519, NIST P-256)
 * - Bitcoin transaction signing (all script types)
 * - Ethereum transaction signing (including EIP-1559)
 * - Message signing (Bitcoin, Ethereum, EIP-712)
 * - Cosmos/Tendermint signing
 *
 * Note: This implementation focuses on the protocol logic.
 * Actual I/O is handled through the WASI bridge.
 */

#ifndef HD_WALLET_HW_TREZOR_H
#define HD_WALLET_HW_TREZOR_H

#include "../config.h"
#include "../types.h"
#include "hw_wallet.h"
#include "hw_transport.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Trezor Constants
// =============================================================================

namespace trezor {

/// Trezor HID channel magic ("##")
constexpr uint16_t CHANNEL_MAGIC = 0x2323;

/// WebUSB channel ID
constexpr uint16_t WEBUSB_CHANNEL = 0x0001;

/// Maximum message size
constexpr size_t MAX_MESSAGE_SIZE = 256 * 1024;

/// Model identifiers
enum class Model : uint8_t {
  UNKNOWN = 0,
  ONE = 1,      // Trezor One (T1)
  T = 2,        // Trezor Model T (T2)
  R = 3         // Trezor Safe 3 (T2B1)
};

/// Get model name
const char* modelToString(Model model);

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
  PASSPHRASE_STATE_REQUEST = 77,
  PASSPHRASE_STATE_ACK = 78,

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
  GET_ADDRESS = 29,
  ADDRESS = 30,
  GET_OWNERSHIP_ID = 43,
  OWNERSHIP_ID = 44,
  GET_OWNERSHIP_PROOF = 49,
  OWNERSHIP_PROOF = 50,

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
  ETHEREUM_SIGN_TX_EIP1559 = 452,
  ETHEREUM_GET_PUBLIC_KEY = 450,
  ETHEREUM_PUBLIC_KEY = 451,

  // Cosmos
  COSMOS_GET_ADDRESS = 800,
  COSMOS_ADDRESS = 801,
  COSMOS_SIGN_TX = 802,
  COSMOS_SIGNED_TX = 803,

  // Cardano
  CARDANO_GET_ADDRESS = 307,
  CARDANO_ADDRESS = 308,
  CARDANO_GET_PUBLIC_KEY = 305,
  CARDANO_PUBLIC_KEY = 306,
  CARDANO_SIGN_TX = 303,
  CARDANO_SIGNED_TX = 310,

  // Device management
  SD_PROTECT = 79,
  GET_NEXT_U2F_COUNTER = 80,
  NEXT_U2F_COUNTER = 81,
  SET_U2F_COUNTER = 63,
  DO_PREAUTHORIZED = 84,
  PREAUTHORIZED_REQUEST = 85,
  CANCEL_AUTHORIZATION = 86,
  REBOOT_TO_BOOTLOADER = 87,
  GET_NONCE = 31,
  NONCE = 33,
  UNLOCK_PATH = 93,
  UNLOCKED_PATH_REQUEST = 94,

  // Debug (Model T)
  DEBUG_LINK_STATE = 101,
  DEBUG_LINK_LOG = 104,
  DEBUG_LINK_MEMORY_READ = 110,
  DEBUG_LINK_MEMORY_WRITE = 111,
  DEBUG_LINK_FLASH_ERASE = 113
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
  PASSPHRASE_ENTRY = 15
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
  WIPE_CODE_MISMATCH = 13,
  INVALID_SESSION = 14,
  FIRMWARE_ERROR = 99
};

/// Get failure code description
const char* failureCodeToString(FailureCode code);

/// Input script types
enum class InputScriptType : uint8_t {
  SPENDADDRESS = 0,       // P2PKH
  SPENDMULTISIG = 1,      // P2SH multisig
  EXTERNAL = 2,           // External inputs
  SPENDWITNESS = 3,       // P2WPKH
  SPENDP2SHWITNESS = 4,   // P2SH-P2WPKH
  SPENDTAPROOT = 5        // P2TR
};

/// Output script types
enum class OutputScriptType : uint8_t {
  PAYTOADDRESS = 0,       // P2PKH
  PAYTOSCRIPTHASH = 1,    // P2SH
  PAYTOMULTISIG = 2,      // Multisig
  PAYTOOPRETURN = 3,      // OP_RETURN
  PAYTOWITNESS = 4,       // P2WPKH
  PAYTOP2SHWITNESS = 5,   // P2SH-P2WPKH
  PAYTOTAPROOT = 6        // P2TR
};

/// Request types during signing
enum class RequestType : uint8_t {
  TXINPUT = 0,
  TXOUTPUT = 1,
  TXMETA = 2,
  TXFINISHED = 3,
  TXEXTRADATA = 4,
  TXORIGINPUT = 5,
  TXORIGOUTPUT = 6,
  TXPAYMENTREQ = 7
};

} // namespace trezor

// =============================================================================
// Trezor-specific Features
// =============================================================================

/**
 * Extended features specific to Trezor devices
 */
struct TrezorFeatures : public DeviceFeatures {
  /// Trezor model
  trezor::Model model = trezor::Model::UNKNOWN;

  /// Bootloader mode
  bool bootloader_mode = false;

  /// Bootloader version
  std::string bootloader_version;

  /// Hardware revision
  std::string hw_revision;

  /// SD card present (Model T)
  bool sd_card_present = false;

  /// SD card protection enabled
  bool sd_protection = false;

  /// Wipe code protection enabled
  bool wipe_code_protection = false;

  /// Session ID for persistent sessions
  ByteVector session_id;

  /// Passphrase always on device (Model T)
  bool passphrase_always_on_device = false;

  /// Experimental features enabled
  bool experimental_features = false;

  /// Safety check level
  uint8_t safety_checks = 0;

  /// Homescreen image hash
  ByteVector homescreen_hash;
};

// =============================================================================
// Trezor Wallet Implementation
// =============================================================================

/**
 * Trezor hardware wallet implementation
 *
 * Implements the HardwareWallet interface for Trezor devices.
 * Supports both Trezor One and Trezor Model T.
 */
class TrezorWallet : public HardwareWallet {
public:
  /**
   * Construct Trezor wallet
   */
  TrezorWallet();

  /**
   * Destructor - disconnects if connected
   */
  ~TrezorWallet() override;

  // Non-copyable
  TrezorWallet(const TrezorWallet&) = delete;
  TrezorWallet& operator=(const TrezorWallet&) = delete;

  // Movable
  TrezorWallet(TrezorWallet&& other) noexcept;
  TrezorWallet& operator=(TrezorWallet&& other) noexcept;

  // ----- HardwareWallet Interface -----

  Result<void> connect(const HardwareWalletDevice& device) override;
  void disconnect() override;
  bool isConnected() const override;
  ConnectionState connectionState() const override;

  Result<DeviceFeatures> initialize() override;
  const DeviceFeatures& features() const override;
  DeviceType deviceType() const override;

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

  // ----- Trezor-specific Methods -----

  /**
   * Get Trezor model
   */
  trezor::Model model() const { return trezor_features_.model; }

  /**
   * Get extended Trezor features
   */
  const TrezorFeatures& trezorFeatures() const { return trezor_features_; }

  /**
   * Ping the device
   * @param message Message to echo
   * @param button_protection Require button press
   * @return Echoed message
   */
  Result<std::string> ping(
    const std::string& message,
    bool button_protection = false
  );

  /**
   * Get device entropy
   * @param size Number of bytes to request
   * @return Random bytes from device
   */
  Result<ByteVector> getEntropy(size_t size);

  /**
   * Clear current session
   */
  Result<void> clearSession();

  /**
   * Apply device settings
   * @param label New device label
   * @param use_passphrase Enable/disable passphrase
   * @param homescreen Custom homescreen (TOIF format)
   * @param auto_lock_delay Auto-lock timeout in seconds
   * @param safety_checks Safety check level
   */
  Result<void> applySettings(
    const std::string& label = "",
    std::optional<bool> use_passphrase = std::nullopt,
    const ByteVector& homescreen = {},
    std::optional<uint32_t> auto_lock_delay = std::nullopt,
    std::optional<uint8_t> safety_checks = std::nullopt
  );

  /**
   * Wipe device (factory reset)
   */
  Result<void> wipeDevice();

  /**
   * Change device PIN
   * @param remove If true, remove PIN protection
   */
  Result<void> changePin(bool remove = false);

  /**
   * Set wipe code (secondary PIN that wipes device)
   * @param remove If true, remove wipe code
   */
  Result<void> setWipeCode(bool remove = false);

  /**
   * Enable/disable SD card protection (Model T)
   * @param enable Enable protection
   */
  Result<void> sdProtect(bool enable);

  /**
   * Sign Cosmos/Tendermint transaction
   * @param path Derivation path
   * @param chain_id Chain identifier
   * @param account_number Account number
   * @param sequence Sequence number
   * @param msgs Transaction messages (JSON)
   * @param fee Fee structure (JSON)
   * @param memo Transaction memo
   * @return Signature bytes
   */
  Result<ByteVector> signCosmosTransaction(
    const std::string& path,
    const std::string& chain_id,
    uint64_t account_number,
    uint64_t sequence,
    const std::string& msgs,
    const std::string& fee,
    const std::string& memo = ""
  );

  /**
   * Get ownership proof for CoinJoin
   * @param path Derivation path
   * @param script_type Script type
   * @param commitment_data Optional commitment data
   * @param user_confirmation Require user confirmation
   * @return Ownership proof
   */
  Result<ByteVector> getOwnershipProof(
    const std::string& path,
    trezor::InputScriptType script_type,
    const ByteVector& commitment_data = {},
    bool user_confirmation = false
  );

  /**
   * Reboot to bootloader (for firmware update)
   */
  Result<void> rebootToBootloader();

private:
  std::unique_ptr<HidTransport> transport_;
  TrezorFeatures trezor_features_;
  ConnectionState state_ = ConnectionState::DISCONNECTED;
  ByteVector session_id_;

  // Callbacks
  callbacks::PinEntryCallback pin_callback_;
  callbacks::PassphraseCallback passphrase_callback_;
  callbacks::ConfirmCallback confirm_callback_;
  callbacks::ButtonCallback button_callback_;
  callbacks::ProgressCallback progress_callback_;

  // Protocol helpers
  Result<void> sendMessage(trezor::MessageType type, const ByteVector& data);
  Result<std::pair<trezor::MessageType, ByteVector>> receiveMessage(uint32_t timeout_ms = 0);
  Result<std::pair<trezor::MessageType, ByteVector>> exchange(
    trezor::MessageType type,
    const ByteVector& data,
    uint32_t timeout_ms = 0
  );

  // Handle device requests
  Result<std::pair<trezor::MessageType, ByteVector>> handleDeviceRequest(
    trezor::MessageType type,
    const ByteVector& data,
    uint32_t timeout_ms = 0
  );

  // Message encoding/decoding
  ByteVector encodeMessage(trezor::MessageType type, const ByteVector& data);
  Result<std::pair<trezor::MessageType, ByteVector>> decodeMessage(const ByteVector& data);

  // Path encoding
  ByteVector encodePath(const std::string& path);

  // Transaction helpers
  ByteVector encodeBitcoinTxInput(const BitcoinTxInput& input, uint32_t index);
  ByteVector encodeBitcoinTxOutput(const BitcoinTxOutput& output, uint32_t index);
  ByteVector encodeEthereumTx(const EthereumTransaction& tx);
  ByteVector encodeEthereumTxEIP1559(const EthereumTransaction& tx);

  // Feature parsing
  void parseFeatures(const ByteVector& data);

  // Model-specific handling
  bool isModelT() const { return trezor_features_.model == trezor::Model::T; }
  bool isModelR() const { return trezor_features_.model == trezor::Model::R; }
  bool supportsTouchscreen() const { return isModelT() || isModelR(); }
};

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create Trezor wallet instance
 */
std::unique_ptr<TrezorWallet> createTrezorWallet();

} // namespace hw
} // namespace hd_wallet

#endif // HD_WALLET_HW_TREZOR_H
