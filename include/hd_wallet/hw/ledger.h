/**
 * @file ledger.h
 * @brief Ledger Hardware Wallet Implementation
 *
 * This module provides the Ledger-specific implementation of the
 * hardware wallet interface. Supports Ledger Nano S, Nano X, and Nano S Plus.
 *
 * Protocol Overview:
 * - APDU-based communication (ISO 7816-4)
 * - Application-specific protocols (Bitcoin, Ethereum apps)
 * - HID framing with channel multiplexing
 * - Report size: 64 bytes
 *
 * APDU Structure:
 * - CLA: Instruction class (app-specific)
 * - INS: Instruction code
 * - P1, P2: Parameters
 * - Lc: Data length
 * - Data: Payload
 * - Le: Expected response length
 *
 * Supported Applications:
 * - Bitcoin (mainnet, testnet)
 * - Ethereum (including ERC-20)
 * - Cosmos/Tendermint
 * - Solana
 * - Polkadot/Substrate
 *
 * Note: Different operations require different Ledger apps to be open.
 * The implementation automatically detects which app is running.
 */

#ifndef HD_WALLET_HW_LEDGER_H
#define HD_WALLET_HW_LEDGER_H

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
// Ledger Constants
// =============================================================================

namespace ledger {

/// Ledger HID channel ID
constexpr uint16_t CHANNEL_ID = 0x0101;

/// APDU command tag
constexpr uint8_t APDU_TAG = 0x05;

/// Maximum APDU data size
constexpr size_t MAX_APDU_SIZE = 255;

/// Maximum extended APDU data size
constexpr size_t MAX_EXT_APDU_SIZE = 65535;

// Status words (SW1-SW2)
enum class StatusWord : uint16_t {
  OK = 0x9000,                    // Success
  CONDITIONS_NOT_SATISFIED = 0x6985,  // User rejected
  INCORRECT_LENGTH = 0x6700,
  INVALID_CLA = 0x6E00,
  INVALID_INS = 0x6D00,
  INVALID_P1_P2 = 0x6B00,
  INVALID_DATA = 0x6A80,
  INS_NOT_SUPPORTED = 0x6D00,
  APP_NOT_OPEN = 0x6E01,
  UNKNOWN_ERROR = 0x6F00,
  SIGN_REFUSED = 0x6985,
  LOCKED_DEVICE = 0x6982,
  TECHNICAL_PROBLEM = 0x6F42,
  MEMORY_PROBLEM = 0x9240,
  NO_EF_SELECTED = 0x9400,
  INVALID_OFFSET = 0x9402,
  FILE_NOT_FOUND = 0x9404,
  INCONSISTENT_FILE = 0x9408,
  ALGORITHM_NOT_SUPPORTED = 0x9484,
  INVALID_KCV = 0x9485,
  CODE_NOT_INITIALIZED = 0x9802,
  ACCESS_CONDITION_NOT_FULFILLED = 0x9804,
  CONTRADICTION_SECRET_CODE_STATUS = 0x9808,
  CONTRADICTION_INVALIDATION = 0x9810,
  CODE_BLOCKED = 0x9840,
  MAX_VALUE_REACHED = 0x9850,
  GP_AUTH_FAILED = 0x6300,
  HALTED = 0x6FAA
};

/// Get status word description
const char* statusWordToString(StatusWord sw);

/// Convert status word to Error
Error statusWordToError(StatusWord sw);

/// Ledger model identification
enum class Model : uint8_t {
  UNKNOWN = 0,
  NANO_S = 1,
  NANO_X = 2,
  NANO_S_PLUS = 3,
  STAX = 4
};

/// Get model name
const char* modelToString(Model model);

/// Application identifiers
enum class AppType : uint8_t {
  UNKNOWN = 0,
  BITCOIN = 1,
  BITCOIN_TESTNET = 2,
  ETHEREUM = 3,
  COSMOS = 4,
  SOLANA = 5,
  POLKADOT = 6,
  CARDANO = 7,
  TEZOS = 8,
  BOLOS = 255  // Bootloader/dashboard
};

/// Get app name
const char* appTypeToString(AppType app);

// Application CLA bytes
namespace CLA {
  constexpr uint8_t BITCOIN = 0xE1;
  constexpr uint8_t BITCOIN_LEGACY = 0xE0;
  constexpr uint8_t ETHEREUM = 0xE0;
  constexpr uint8_t BOLOS = 0xB0;
  constexpr uint8_t COSMOS = 0x55;
  constexpr uint8_t SOLANA = 0xE0;
  constexpr uint8_t POLKADOT = 0x90;
}

// Common APDU instructions
namespace INS {
  // Common
  constexpr uint8_t GET_VERSION = 0x01;
  constexpr uint8_t GET_APP_NAME = 0x00;

  // Bitcoin
  constexpr uint8_t BTC_GET_WALLET_PUBLIC_KEY = 0x40;
  constexpr uint8_t BTC_GET_TRUSTED_INPUT = 0x42;
  constexpr uint8_t BTC_HASH_INPUT_START = 0x44;
  constexpr uint8_t BTC_HASH_INPUT_FINALIZE = 0x4A;
  constexpr uint8_t BTC_HASH_SIGN = 0x48;
  constexpr uint8_t BTC_SIGN_MESSAGE = 0x4E;
  constexpr uint8_t BTC_GET_FINGERPRINT = 0x3C;

  // Ethereum
  constexpr uint8_t ETH_GET_ADDRESS = 0x02;
  constexpr uint8_t ETH_SIGN_TX = 0x04;
  constexpr uint8_t ETH_GET_APP_CONFIG = 0x06;
  constexpr uint8_t ETH_SIGN_MESSAGE = 0x08;
  constexpr uint8_t ETH_SIGN_TYPED_DATA = 0x0C;
  constexpr uint8_t ETH_PROVIDE_ERC20 = 0x0A;
  constexpr uint8_t ETH_SET_PLUGIN = 0x16;
  constexpr uint8_t ETH_PROVIDE_NFT = 0x14;
  constexpr uint8_t ETH_EIP712_STRUCT_DEF = 0x1A;
  constexpr uint8_t ETH_EIP712_STRUCT_IMPL = 0x1C;
  constexpr uint8_t ETH_EIP712_FILTERING = 0x1E;

  // BOLOS (dashboard)
  constexpr uint8_t BOLOS_GET_VERSION = 0x01;
  constexpr uint8_t BOLOS_RUN_APP = 0xD8;
  constexpr uint8_t BOLOS_EXIT_APP = 0xA7;
}

} // namespace ledger

// =============================================================================
// APDU Command Builder
// =============================================================================

/**
 * APDU command structure
 */
struct APDUCommand {
  uint8_t cla = 0;
  uint8_t ins = 0;
  uint8_t p1 = 0;
  uint8_t p2 = 0;
  ByteVector data;
  std::optional<uint8_t> le;

  /// Serialize to bytes
  ByteVector serialize() const;

  /// Create command
  static APDUCommand create(
    uint8_t cla,
    uint8_t ins,
    uint8_t p1 = 0,
    uint8_t p2 = 0,
    const ByteVector& data = {},
    std::optional<uint8_t> le = std::nullopt
  );
};

/**
 * APDU response structure
 */
struct APDUResponse {
  ByteVector data;
  ledger::StatusWord status = ledger::StatusWord::UNKNOWN_ERROR;

  /// Check if response indicates success
  bool ok() const { return status == ledger::StatusWord::OK; }

  /// Get error
  Error error() const { return ledger::statusWordToError(status); }
};

// =============================================================================
// Ledger-specific Features
// =============================================================================

/**
 * Extended features specific to Ledger devices
 */
struct LedgerFeatures : public DeviceFeatures {
  /// Ledger model
  ledger::Model model = ledger::Model::UNKNOWN;

  /// Currently running application
  ledger::AppType current_app = ledger::AppType::UNKNOWN;

  /// App name string
  std::string app_name;

  /// App version string
  std::string app_version;

  /// MCU firmware version
  std::string mcu_version;

  /// Secure element version
  std::string se_version;

  /// Target ID (device identifier)
  uint32_t target_id = 0;

  /// Device is locked
  bool locked = false;

  /// Arbitrary data enabled
  bool arbitrary_data_enabled = false;

  /// ERC-20 support enabled
  bool erc20_enabled = false;

  /// EIP-712 full support (Model X, S Plus)
  bool eip712_full_support = false;
};

// =============================================================================
// Ledger Wallet Implementation
// =============================================================================

/**
 * Ledger hardware wallet implementation
 *
 * Implements the HardwareWallet interface for Ledger devices.
 */
class LedgerWallet : public HardwareWallet {
public:
  /**
   * Construct Ledger wallet
   */
  LedgerWallet();

  /**
   * Destructor - disconnects if connected
   */
  ~LedgerWallet() override;

  // Non-copyable
  LedgerWallet(const LedgerWallet&) = delete;
  LedgerWallet& operator=(const LedgerWallet&) = delete;

  // Movable
  LedgerWallet(LedgerWallet&& other) noexcept;
  LedgerWallet& operator=(LedgerWallet&& other) noexcept;

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

  // ----- Ledger-specific Methods -----

  /**
   * Get Ledger model
   */
  ledger::Model model() const { return ledger_features_.model; }

  /**
   * Get extended Ledger features
   */
  const LedgerFeatures& ledgerFeatures() const { return ledger_features_; }

  /**
   * Get currently running application
   */
  ledger::AppType currentApp() const { return ledger_features_.current_app; }

  /**
   * Check if specific app is running
   */
  bool isAppOpen(ledger::AppType app) const {
    return ledger_features_.current_app == app;
  }

  /**
   * Open application by name
   * @param app_name Application name
   */
  Result<void> openApp(const std::string& app_name);

  /**
   * Exit current application (return to dashboard)
   */
  Result<void> exitApp();

  /**
   * Get device info from bootloader/dashboard
   */
  Result<void> getDeviceInfo();

  /**
   * Get application configuration
   */
  Result<void> getAppConfig();

  /**
   * Send raw APDU command
   * @param command APDU command
   * @return APDU response
   */
  Result<APDUResponse> sendAPDU(const APDUCommand& command);

  /**
   * Send APDU and check status
   * @param command APDU command
   * @return Response data on success
   */
  Result<ByteVector> sendAPDUChecked(const APDUCommand& command);

  // ----- Bitcoin App Methods -----

  /**
   * Get Bitcoin wallet public key
   * @param path Derivation path
   * @param display Show on device
   * @param address_type Address type to display
   * @return Public key and chain code
   */
  Result<std::pair<Bytes33, Bytes32>> getBitcoinPublicKey(
    const std::string& path,
    bool display = false,
    BitcoinAddressType address_type = BitcoinAddressType::P2WPKH
  );

  /**
   * Get Bitcoin address
   * @param path Derivation path
   * @param address_type Address type
   * @param display Show on device
   * @return Address string
   */
  Result<std::string> getBitcoinAddress(
    const std::string& path,
    BitcoinAddressType address_type,
    bool display = false
  );

  /**
   * Get master fingerprint
   * @return 4-byte fingerprint
   */
  Result<uint32_t> getMasterFingerprint();

  // ----- Ethereum App Methods -----

  /**
   * Get Ethereum address
   * @param path Derivation path
   * @param display Show on device
   * @param chain_id Chain ID for display
   * @return Address (hex string with 0x prefix)
   */
  Result<std::string> getEthereumAddress(
    const std::string& path,
    bool display = false,
    uint64_t chain_id = 1
  );

  /**
   * Provide ERC-20 token info for display
   * @param contract_address Token contract address
   * @param ticker Token ticker symbol
   * @param decimals Token decimals
   * @param chain_id Chain ID
   */
  Result<void> provideERC20Info(
    const std::string& contract_address,
    const std::string& ticker,
    uint8_t decimals,
    uint64_t chain_id = 1
  );

  /**
   * Sign EIP-712 typed data (full struct support)
   * @param path Derivation path
   * @param json_data Full EIP-712 JSON structure
   * @return Signature
   */
  Result<SignedMessage> signEIP712Full(
    const std::string& path,
    const std::string& json_data
  );

  // ----- Cosmos App Methods -----

  /**
   * Get Cosmos address
   * @param path Derivation path
   * @param hrp Address prefix (e.g., "cosmos", "osmo")
   * @param display Show on device
   * @return Bech32 address
   */
  Result<std::string> getCosmosAddress(
    const std::string& path,
    const std::string& hrp = "cosmos",
    bool display = false
  );

  /**
   * Sign Cosmos transaction
   * @param path Derivation path
   * @param tx_json Transaction JSON
   * @return Signature
   */
  Result<ByteVector> signCosmosTransaction(
    const std::string& path,
    const std::string& tx_json
  );

private:
  std::unique_ptr<HidTransport> transport_;
  LedgerFeatures ledger_features_;
  ConnectionState state_ = ConnectionState::DISCONNECTED;

  // Callbacks
  callbacks::PinEntryCallback pin_callback_;
  callbacks::PassphraseCallback passphrase_callback_;
  callbacks::ConfirmCallback confirm_callback_;
  callbacks::ButtonCallback button_callback_;
  callbacks::ProgressCallback progress_callback_;

  // APDU helpers
  Result<APDUResponse> exchangeAPDU(const ByteVector& apdu);
  ByteVector frameAPDU(const ByteVector& apdu);
  Result<ByteVector> unframeResponse();

  // Path encoding (Ledger format)
  ByteVector encodePath(const std::string& path);

  // Bitcoin helpers
  ByteVector encodeBitcoinInput(const BitcoinTxInput& input);
  ByteVector encodeBitcoinOutput(const BitcoinTxOutput& output);
  Result<ByteVector> getTrustedInput(const ByteVector& prev_tx, uint32_t index);
  Result<void> hashInputStart(const BitcoinTransaction& tx, bool new_tx);
  Result<void> hashInputFinalize(const BitcoinTransaction& tx);
  Result<ByteVector> hashSign(const BitcoinTxInput& input, uint32_t lock_time, uint8_t sighash_type);

  // Ethereum helpers
  ByteVector encodeEthereumTxLegacy(const EthereumTransaction& tx);
  ByteVector encodeEthereumTxEIP1559(const EthereumTransaction& tx);
  Result<ByteVector> signEthereumTxChunked(const ByteVector& encoded_tx, const std::string& path);

  // Feature parsing
  void parseDeviceInfo(const ByteVector& data);
  void parseAppInfo(const ByteVector& data);
  ledger::AppType detectApp(const std::string& app_name);

  // Model detection from target ID
  ledger::Model detectModel(uint32_t target_id);
};

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create Ledger wallet instance
 */
std::unique_ptr<LedgerWallet> createLedgerWallet();

} // namespace hw
} // namespace hd_wallet

#endif // HD_WALLET_HW_LEDGER_H
