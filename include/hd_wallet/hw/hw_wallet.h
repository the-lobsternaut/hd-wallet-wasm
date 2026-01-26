/**
 * @file hw_wallet.h
 * @brief Hardware Wallet Abstract Interface
 *
 * This module provides the base interface for hardware wallet integration.
 * It defines common operations that all hardware wallets support:
 *
 * - Device connection and initialization
 * - Public key retrieval with derivation path
 * - Transaction signing (Bitcoin, Ethereum, etc.)
 * - Message signing
 * - Device features and capabilities
 *
 * Concrete implementations are provided for:
 * - KeepKey (keepkey.h)
 * - Trezor (trezor.h)
 * - Ledger (ledger.h)
 *
 * All hardware I/O goes through the WASI bridge, allowing this code
 * to work in WASM environments with host-provided USB access.
 */

#ifndef HD_WALLET_HW_WALLET_H
#define HD_WALLET_HW_WALLET_H

#include "../config.h"
#include "../types.h"
#include "../bip32.h"
#include "hw_transport.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Forward Declarations
// =============================================================================

class HidTransport;

// =============================================================================
// Device Status
// =============================================================================

/**
 * Hardware wallet connection state
 */
enum class ConnectionState {
  /// Not connected
  DISCONNECTED = 0,

  /// Connected but not initialized
  CONNECTED = 1,

  /// Initialized and ready
  READY = 2,

  /// Waiting for user interaction (PIN, passphrase, confirmation)
  AWAITING_USER = 3,

  /// Device is busy processing
  BUSY = 4,

  /// Error state (requires reconnection)
  ERROR = 5
};

/**
 * Get connection state name
 */
const char* connectionStateToString(ConnectionState state);

/**
 * Device capabilities flags
 */
enum class DeviceCapability : uint32_t {
  NONE = 0,

  /// Can sign Bitcoin transactions
  BITCOIN_SIGNING = 1 << 0,

  /// Can sign Ethereum transactions
  ETHEREUM_SIGNING = 1 << 1,

  /// Can sign arbitrary messages
  MESSAGE_SIGNING = 1 << 2,

  /// Supports passphrase entry
  PASSPHRASE = 1 << 3,

  /// Has a display for verification
  DISPLAY = 1 << 4,

  /// Supports multiple accounts
  MULTIPLE_ACCOUNTS = 1 << 5,

  /// Supports PIN protection
  PIN_PROTECTION = 1 << 6,

  /// Can export xpub
  XPUB_EXPORT = 1 << 7,

  /// Supports U2F/FIDO
  U2F = 1 << 8,

  /// Supports firmware updates
  FIRMWARE_UPDATE = 1 << 9,

  /// Supports secp256k1 curve
  CURVE_SECP256K1 = 1 << 10,

  /// Supports ed25519 curve
  CURVE_ED25519 = 1 << 11,

  /// Supports NIST P-256 curve
  CURVE_P256 = 1 << 12,

  /// Supports Cosmos/Tendermint signing
  COSMOS_SIGNING = 1 << 13,

  /// Supports Solana signing
  SOLANA_SIGNING = 1 << 14
};

/// Combine capability flags
inline DeviceCapability operator|(DeviceCapability a, DeviceCapability b) {
  return static_cast<DeviceCapability>(
    static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
  );
}

/// Check capability flag
inline bool hasCapability(DeviceCapability caps, DeviceCapability flag) {
  return (static_cast<uint32_t>(caps) & static_cast<uint32_t>(flag)) != 0;
}

// =============================================================================
// Device Features
// =============================================================================

/**
 * Hardware wallet device features and information
 *
 * Populated during device initialization, contains information
 * about the connected device's capabilities and state.
 */
struct DeviceFeatures {
  /// Device type
  DeviceType device_type = DeviceType::UNKNOWN;

  /// Device capabilities
  DeviceCapability capabilities = DeviceCapability::NONE;

  /// Firmware version
  std::string firmware_version;

  /// Device label (user-set name)
  std::string label;

  /// Device serial number
  std::string serial_number;

  /// Device ID (internal identifier)
  std::string device_id;

  /// Device manufacturer
  std::string manufacturer;

  /// Whether device is initialized with a seed
  bool initialized = false;

  /// Whether PIN is enabled
  bool pin_protection = false;

  /// Whether passphrase is enabled
  bool passphrase_protection = false;

  /// Whether device needs PIN entry
  bool needs_pin = false;

  /// Whether device needs passphrase entry
  bool needs_passphrase = false;

  /// Coin types supported
  std::vector<CoinType> supported_coins;
};

// =============================================================================
// Callback Types
// =============================================================================

/**
 * User interaction callback types
 *
 * These callbacks are invoked when the hardware wallet requires
 * user interaction. The host application should display appropriate
 * UI and return the user's input.
 */
namespace callbacks {

/**
 * PIN entry callback
 * @param retry_count Number of attempts remaining
 * @return PIN string, or empty to cancel
 */
using PinEntryCallback = std::function<std::string(int retry_count)>;

/**
 * Passphrase entry callback
 * @param on_device true if passphrase should be entered on device
 * @return Passphrase string, or empty for no passphrase
 */
using PassphraseCallback = std::function<std::string(bool on_device)>;

/**
 * Confirmation callback - prompts user to confirm on device
 * @param message Message describing what to confirm
 * @return true if user confirmed, false if cancelled
 */
using ConfirmCallback = std::function<bool(const std::string& message)>;

/**
 * Button request callback - prompts user to press button
 * @param message Message describing what button to press
 */
using ButtonCallback = std::function<void(const std::string& message)>;

/**
 * Progress callback for long operations
 * @param current Current progress value
 * @param total Total progress value
 * @param message Progress message
 */
using ProgressCallback = std::function<void(int current, int total, const std::string& message)>;

} // namespace callbacks

// =============================================================================
// Transaction Types
// =============================================================================

/**
 * Bitcoin transaction input for signing
 */
struct BitcoinTxInput {
  /// Previous transaction hash (32 bytes, little-endian)
  ByteVector prev_hash;

  /// Previous output index
  uint32_t prev_index = 0;

  /// Derivation path for signing key
  std::string derivation_path;

  /// Script type for this input
  BitcoinAddressType script_type = BitcoinAddressType::P2WPKH;

  /// Amount in satoshis (required for SegWit)
  uint64_t amount = 0;

  /// Sequence number
  uint32_t sequence = 0xFFFFFFFF;

  /// Previous output script (for non-SegWit)
  ByteVector script_pubkey;
};

/**
 * Bitcoin transaction output
 */
struct BitcoinTxOutput {
  /// Output amount in satoshis
  uint64_t amount = 0;

  /// Destination address
  std::string address;

  /// Script type
  BitcoinAddressType script_type = BitcoinAddressType::P2WPKH;

  /// Change output derivation path (empty if not change)
  std::string change_path;
};

/**
 * Bitcoin transaction for signing
 */
struct BitcoinTransaction {
  /// Version number
  uint32_t version = 2;

  /// Lock time
  uint32_t lock_time = 0;

  /// Transaction inputs
  std::vector<BitcoinTxInput> inputs;

  /// Transaction outputs
  std::vector<BitcoinTxOutput> outputs;
};

/**
 * Ethereum transaction for signing
 */
struct EthereumTransaction {
  /// Derivation path for signing key
  std::string derivation_path;

  /// Chain ID (1 = mainnet, etc.)
  uint64_t chain_id = 1;

  /// Nonce
  uint64_t nonce = 0;

  /// Gas price (wei)
  ByteVector gas_price;

  /// Gas limit
  uint64_t gas_limit = 21000;

  /// Recipient address (empty for contract creation)
  std::string to;

  /// Value (wei)
  ByteVector value;

  /// Data (for contract calls)
  ByteVector data;

  /// EIP-1559: Max fee per gas (optional)
  std::optional<ByteVector> max_fee_per_gas;

  /// EIP-1559: Max priority fee per gas (optional)
  std::optional<ByteVector> max_priority_fee_per_gas;
};

/**
 * Signed transaction result
 */
struct SignedTransaction {
  /// Signature (v, r, s for Ethereum; DER for Bitcoin)
  ByteVector signature;

  /// Full signed transaction (if device returns it)
  ByteVector serialized_tx;

  /// Transaction hash
  ByteVector tx_hash;
};

/**
 * Message signing result
 */
struct SignedMessage {
  /// Signature bytes
  ByteVector signature;

  /// Recovery ID (for recoverable signatures)
  uint8_t recovery_id = 0;

  /// Address that signed (for verification)
  std::string address;
};

// =============================================================================
// Hardware Wallet Base Class
// =============================================================================

/**
 * Abstract base class for hardware wallet implementations
 *
 * This class defines the common interface for all hardware wallet types.
 * Concrete implementations handle device-specific protocols.
 */
class HardwareWallet {
public:
  /**
   * Virtual destructor
   */
  virtual ~HardwareWallet() = default;

  // ----- Connection Management -----

  /**
   * Connect to device
   *
   * Opens the transport connection and performs initial handshake.
   *
   * @param device Device to connect to
   * @return Error code
   */
  virtual Result<void> connect(const HardwareWalletDevice& device) = 0;

  /**
   * Disconnect from device
   */
  virtual void disconnect() = 0;

  /**
   * Check if connected
   */
  virtual bool isConnected() const = 0;

  /**
   * Get connection state
   */
  virtual ConnectionState connectionState() const = 0;

  // ----- Device Information -----

  /**
   * Initialize device and retrieve features
   *
   * Must be called after connect() to query device capabilities.
   *
   * @return Device features
   */
  virtual Result<DeviceFeatures> initialize() = 0;

  /**
   * Get cached device features (from last initialize())
   */
  virtual const DeviceFeatures& features() const = 0;

  /**
   * Get device type
   */
  virtual DeviceType deviceType() const = 0;

  // ----- PIN and Passphrase -----

  /**
   * Enter PIN (if required)
   *
   * @param pin PIN string
   * @return Error code
   */
  virtual Result<void> enterPin(const std::string& pin) = 0;

  /**
   * Enter passphrase (if required)
   *
   * @param passphrase Passphrase string (empty for no passphrase)
   * @return Error code
   */
  virtual Result<void> enterPassphrase(const std::string& passphrase) = 0;

  /**
   * Cancel current operation
   */
  virtual Result<void> cancel() = 0;

  // ----- Key Operations -----

  /**
   * Get public key for derivation path
   *
   * @param path Derivation path (e.g., "m/44'/60'/0'/0/0")
   * @param display If true, show address on device for verification
   * @return Public key (compressed)
   */
  virtual Result<Bytes33> getPublicKey(
    const std::string& path,
    bool display = false
  ) = 0;

  /**
   * Get extended public key (xpub) for derivation path
   *
   * @param path Derivation path
   * @param display If true, show on device for verification
   * @return Extended public key string
   */
  virtual Result<std::string> getExtendedPublicKey(
    const std::string& path,
    bool display = false
  ) = 0;

  /**
   * Get address for derivation path
   *
   * @param path Derivation path
   * @param coin_type Coin type for address format
   * @param display If true, show on device for verification
   * @return Address string
   */
  virtual Result<std::string> getAddress(
    const std::string& path,
    CoinType coin_type,
    bool display = false
  ) = 0;

  // ----- Transaction Signing -----

  /**
   * Sign a Bitcoin transaction
   *
   * @param tx Transaction to sign
   * @return Signed transaction
   */
  virtual Result<SignedTransaction> signBitcoinTransaction(
    const BitcoinTransaction& tx
  ) = 0;

  /**
   * Sign an Ethereum transaction
   *
   * @param tx Transaction to sign
   * @return Signed transaction
   */
  virtual Result<SignedTransaction> signEthereumTransaction(
    const EthereumTransaction& tx
  ) = 0;

  // ----- Message Signing -----

  /**
   * Sign a message (Bitcoin-style)
   *
   * @param path Derivation path for signing key
   * @param message Message to sign
   * @return Signed message
   */
  virtual Result<SignedMessage> signMessage(
    const std::string& path,
    const std::string& message
  ) = 0;

  /**
   * Sign a message (Ethereum-style, EIP-191)
   *
   * @param path Derivation path for signing key
   * @param message Message to sign
   * @return Signed message
   */
  virtual Result<SignedMessage> signEthereumMessage(
    const std::string& path,
    const std::string& message
  ) = 0;

  /**
   * Sign typed data (EIP-712)
   *
   * @param path Derivation path for signing key
   * @param domain_separator Domain separator hash
   * @param struct_hash Struct hash
   * @return Signed message
   */
  virtual Result<SignedMessage> signTypedData(
    const std::string& path,
    const Bytes32& domain_separator,
    const Bytes32& struct_hash
  ) = 0;

  // ----- Callbacks -----

  /**
   * Set PIN entry callback
   */
  virtual void setPinCallback(callbacks::PinEntryCallback callback) = 0;

  /**
   * Set passphrase entry callback
   */
  virtual void setPassphraseCallback(callbacks::PassphraseCallback callback) = 0;

  /**
   * Set confirmation callback
   */
  virtual void setConfirmCallback(callbacks::ConfirmCallback callback) = 0;

  /**
   * Set button request callback
   */
  virtual void setButtonCallback(callbacks::ButtonCallback callback) = 0;

  /**
   * Set progress callback
   */
  virtual void setProgressCallback(callbacks::ProgressCallback callback) = 0;

protected:
  /// Protected constructor
  HardwareWallet() = default;
};

// =============================================================================
// Factory Functions
// =============================================================================

/**
 * Create hardware wallet instance for device
 *
 * Factory function that creates the appropriate implementation
 * based on device type.
 *
 * @param device Device to create wallet for
 * @return Hardware wallet instance or nullptr on error
 */
std::unique_ptr<HardwareWallet> createHardwareWallet(
  const HardwareWalletDevice& device
);

/**
 * Create hardware wallet instance for device type
 *
 * @param type Device type
 * @return Hardware wallet instance or nullptr on error
 */
std::unique_ptr<HardwareWallet> createHardwareWallet(DeviceType type);

/**
 * Enumerate and connect to first available device
 *
 * Convenience function that enumerates devices and connects to
 * the first one found.
 *
 * @return Connected hardware wallet or nullptr if no device found
 */
std::unique_ptr<HardwareWallet> connectToFirstDevice();

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Parse derivation path string to components
 *
 * @param path Path string (e.g., "m/44'/60'/0'/0/0")
 * @return Vector of indices (hardened indices have bit 31 set)
 */
Result<std::vector<uint32_t>> parseDerivationPath(const std::string& path);

/**
 * Format derivation path to string
 *
 * @param components Path components
 * @return Path string
 */
std::string formatDerivationPath(const std::vector<uint32_t>& components);

/**
 * Validate derivation path for coin type
 *
 * @param path Derivation path
 * @param coin_type Coin type
 * @return true if path is valid for coin type
 */
bool validateDerivationPath(const std::string& path, CoinType coin_type);

} // namespace hw
} // namespace hd_wallet

#endif // HD_WALLET_HW_WALLET_H
