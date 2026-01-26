/**
 * @file ledger.cpp
 * @brief Ledger Hardware Wallet Implementation
 *
 * Implements the Ledger-specific APDU protocol for hardware wallet communication.
 * Supports Ledger Nano S, Nano X, and Nano S Plus.
 */

#include "hd_wallet/hw/ledger.h"
#include "hd_wallet/hw/hw_transport.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Ledger Constants and Helpers
// =============================================================================

namespace ledger {

const char* statusWordToString(StatusWord sw) {
  switch (sw) {
    case StatusWord::OK: return "Success";
    case StatusWord::CONDITIONS_NOT_SATISFIED: return "Conditions not satisfied / Sign refused";
    // SIGN_REFUSED has same value as CONDITIONS_NOT_SATISFIED (0x6985)
    case StatusWord::INCORRECT_LENGTH: return "Incorrect length";
    case StatusWord::INVALID_CLA: return "Invalid CLA";
    case StatusWord::INVALID_INS: return "Invalid instruction / Instruction not supported";
    // INS_NOT_SUPPORTED has same value as INVALID_INS (0x6D00)
    case StatusWord::INVALID_P1_P2: return "Invalid P1/P2";
    case StatusWord::INVALID_DATA: return "Invalid data";
    case StatusWord::APP_NOT_OPEN: return "Application not open";
    case StatusWord::UNKNOWN_ERROR: return "Unknown error";
    case StatusWord::LOCKED_DEVICE: return "Device locked";
    case StatusWord::TECHNICAL_PROBLEM: return "Technical problem";
    case StatusWord::MEMORY_PROBLEM: return "Memory problem";
    default: return "Unknown status";
  }
}

Error statusWordToError(StatusWord sw) {
  switch (sw) {
    case StatusWord::OK:
      return Error::OK;
    case StatusWord::CONDITIONS_NOT_SATISFIED:
    // SIGN_REFUSED has same value as CONDITIONS_NOT_SATISFIED (0x6985)
      return Error::USER_CANCELLED;
    case StatusWord::LOCKED_DEVICE:
      return Error::DEVICE_BUSY;
    case StatusWord::APP_NOT_OPEN:
      return Error::DEVICE_NOT_SUPPORTED;
    default:
      return Error::DEVICE_COMM_ERROR;
  }
}

const char* modelToString(Model model) {
  switch (model) {
    case Model::NANO_S: return "Ledger Nano S";
    case Model::NANO_X: return "Ledger Nano X";
    case Model::NANO_S_PLUS: return "Ledger Nano S Plus";
    case Model::STAX: return "Ledger Stax";
    default: return "Unknown";
  }
}

const char* appTypeToString(AppType app) {
  switch (app) {
    case AppType::BITCOIN: return "Bitcoin";
    case AppType::BITCOIN_TESTNET: return "Bitcoin Testnet";
    case AppType::ETHEREUM: return "Ethereum";
    case AppType::COSMOS: return "Cosmos";
    case AppType::SOLANA: return "Solana";
    case AppType::POLKADOT: return "Polkadot";
    case AppType::CARDANO: return "Cardano";
    case AppType::TEZOS: return "Tezos";
    case AppType::BOLOS: return "Dashboard";
    default: return "Unknown";
  }
}

} // namespace ledger

// =============================================================================
// APDU Command Implementation
// =============================================================================

ByteVector APDUCommand::serialize() const {
  ByteVector result;

  result.push_back(cla);
  result.push_back(ins);
  result.push_back(p1);
  result.push_back(p2);

  if (!data.empty()) {
    result.push_back(static_cast<uint8_t>(data.size()));
    result.insert(result.end(), data.begin(), data.end());
  } else if (le.has_value()) {
    result.push_back(0x00);  // No data, but expect response
  }

  if (le.has_value()) {
    result.push_back(le.value());
  }

  return result;
}

APDUCommand APDUCommand::create(
  uint8_t cla,
  uint8_t ins,
  uint8_t p1,
  uint8_t p2,
  const ByteVector& data,
  std::optional<uint8_t> le
) {
  APDUCommand cmd;
  cmd.cla = cla;
  cmd.ins = ins;
  cmd.p1 = p1;
  cmd.p2 = p2;
  cmd.data = data;
  cmd.le = le;
  return cmd;
}

// =============================================================================
// LedgerWallet Implementation
// =============================================================================

LedgerWallet::LedgerWallet()
  : transport_(nullptr),
    state_(ConnectionState::DISCONNECTED) {}

LedgerWallet::~LedgerWallet() {
  disconnect();
}

LedgerWallet::LedgerWallet(LedgerWallet&& other) noexcept
  : transport_(std::move(other.transport_)),
    ledger_features_(std::move(other.ledger_features_)),
    state_(other.state_),
    pin_callback_(std::move(other.pin_callback_)),
    passphrase_callback_(std::move(other.passphrase_callback_)),
    confirm_callback_(std::move(other.confirm_callback_)),
    button_callback_(std::move(other.button_callback_)),
    progress_callback_(std::move(other.progress_callback_)) {
  other.state_ = ConnectionState::DISCONNECTED;
}

LedgerWallet& LedgerWallet::operator=(LedgerWallet&& other) noexcept {
  if (this != &other) {
    disconnect();
    transport_ = std::move(other.transport_);
    ledger_features_ = std::move(other.ledger_features_);
    state_ = other.state_;
    pin_callback_ = std::move(other.pin_callback_);
    passphrase_callback_ = std::move(other.passphrase_callback_);
    confirm_callback_ = std::move(other.confirm_callback_);
    button_callback_ = std::move(other.button_callback_);
    progress_callback_ = std::move(other.progress_callback_);
    other.state_ = ConnectionState::DISCONNECTED;
  }
  return *this;
}

// =============================================================================
// Connection Management
// =============================================================================

Result<void> LedgerWallet::connect(const HardwareWalletDevice& device) {
  if (state_ != ConnectionState::DISCONNECTED) {
    disconnect();
  }

  transport_ = createTransport();
  if (!transport_) {
    return Result<void>::fail(Error::BRIDGE_NOT_SET);
  }

  TransportError err = transport_->open(device.path);
  if (err != TransportError::OK) {
    transport_.reset();
    return Result<void>::fail(transportErrorToError(err));
  }

  state_ = ConnectionState::CONNECTED;

  // Set device type from enumeration
  switch (device.type) {
    case DeviceType::LEDGER_NANO_S:
      ledger_features_.model = ledger::Model::NANO_S;
      ledger_features_.device_type = DeviceType::LEDGER_NANO_S;
      break;
    case DeviceType::LEDGER_NANO_X:
      ledger_features_.model = ledger::Model::NANO_X;
      ledger_features_.device_type = DeviceType::LEDGER_NANO_X;
      break;
    case DeviceType::LEDGER_NANO_S_PLUS:
      ledger_features_.model = ledger::Model::NANO_S_PLUS;
      ledger_features_.device_type = DeviceType::LEDGER_NANO_S_PLUS;
      break;
    default:
      ledger_features_.model = ledger::Model::UNKNOWN;
      ledger_features_.device_type = device.type;
      break;
  }

  ledger_features_.serial_number = device.serial_number;

  return Result<void>::success();
}

void LedgerWallet::disconnect() {
  if (transport_) {
    transport_->close();
    transport_.reset();
  }
  state_ = ConnectionState::DISCONNECTED;
  ledger_features_ = LedgerFeatures{};
}

bool LedgerWallet::isConnected() const {
  return transport_ && transport_->isConnected();
}

ConnectionState LedgerWallet::connectionState() const {
  return state_;
}

// =============================================================================
// Device Initialization
// =============================================================================

Result<DeviceFeatures> LedgerWallet::initialize() {
  if (!isConnected()) {
    return Result<DeviceFeatures>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Try to get device info from dashboard/bootloader
  auto info_result = getDeviceInfo();
  if (!info_result.ok()) {
    // Device might have an app open, try to detect it
    auto config_result = getAppConfig();
    if (!config_result.ok()) {
      state_ = ConnectionState::ERROR;
      return Result<DeviceFeatures>::fail(Error::DEVICE_COMM_ERROR);
    }
  }

  state_ = ConnectionState::READY;

  // Set capabilities based on detected app
  ledger_features_.capabilities = DeviceCapability::DISPLAY |
                                  DeviceCapability::XPUB_EXPORT |
                                  DeviceCapability::CURVE_SECP256K1;

  if (ledger_features_.current_app == ledger::AppType::BITCOIN ||
      ledger_features_.current_app == ledger::AppType::BITCOIN_TESTNET) {
    ledger_features_.capabilities = ledger_features_.capabilities | DeviceCapability::BITCOIN_SIGNING;
    ledger_features_.capabilities = ledger_features_.capabilities | DeviceCapability::MESSAGE_SIGNING;
  }

  if (ledger_features_.current_app == ledger::AppType::ETHEREUM) {
    ledger_features_.capabilities = ledger_features_.capabilities | DeviceCapability::ETHEREUM_SIGNING;
    ledger_features_.capabilities = ledger_features_.capabilities | DeviceCapability::MESSAGE_SIGNING;
  }

  if (ledger_features_.current_app == ledger::AppType::COSMOS) {
    ledger_features_.capabilities = ledger_features_.capabilities | DeviceCapability::COSMOS_SIGNING;
  }

  // Model X and S Plus have better capabilities
  if (ledger_features_.model == ledger::Model::NANO_X ||
      ledger_features_.model == ledger::Model::NANO_S_PLUS) {
    ledger_features_.eip712_full_support = true;
  }

  return Result<DeviceFeatures>::success(DeviceFeatures(ledger_features_));
}

const DeviceFeatures& LedgerWallet::features() const {
  return ledger_features_;
}

DeviceType LedgerWallet::deviceType() const {
  return ledger_features_.device_type;
}

// =============================================================================
// PIN and Passphrase (Ledger handles these on-device)
// =============================================================================

Result<void> LedgerWallet::enterPin(const std::string& pin) {
  // Ledger PIN is always entered on device
  return Result<void>::fail(Error::NOT_SUPPORTED);
}

Result<void> LedgerWallet::enterPassphrase(const std::string& passphrase) {
  // Ledger passphrase (if enabled) is entered on device
  return Result<void>::fail(Error::NOT_SUPPORTED);
}

Result<void> LedgerWallet::cancel() {
  // No explicit cancel command for Ledger
  state_ = ConnectionState::READY;
  return Result<void>::success();
}

// =============================================================================
// Key Operations
// =============================================================================

Result<Bytes33> LedgerWallet::getPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<Bytes33>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Check which app is running and use appropriate method
  if (ledger_features_.current_app == ledger::AppType::ETHEREUM) {
    auto result = getEthereumAddress(path, display);
    if (!result.ok()) {
      return Result<Bytes33>::fail(result.error);
    }
    // For Ethereum, we'd need to get the public key separately
    // This is a simplified version
    return Result<Bytes33>::fail(Error::NOT_SUPPORTED);
  }

  // Bitcoin app
  auto result = getBitcoinPublicKey(path, display);
  if (!result.ok()) {
    return Result<Bytes33>::fail(result.error);
  }

  return Result<Bytes33>::success(Bytes33(result.value.first));
}

Result<std::string> LedgerWallet::getExtendedPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  // Get public key and chain code, then format as xpub
  auto pk_result = getBitcoinPublicKey(path, display);
  if (!pk_result.ok()) {
    return Result<std::string>::fail(pk_result.error);
  }

  // Would need to construct xpub from public key and chain code
  // This is a placeholder - real implementation would serialize properly
  return Result<std::string>::fail(Error::NOT_SUPPORTED);
}

Result<std::string> LedgerWallet::getAddress(
  const std::string& path,
  CoinType coin_type,
  bool display
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (coin_type == CoinType::ETHEREUM || coin_type == CoinType::ETHEREUM_CLASSIC) {
    return getEthereumAddress(path, display);
  }

  if (coin_type == CoinType::BITCOIN || coin_type == CoinType::BITCOIN_TESTNET) {
    return getBitcoinAddress(path, BitcoinAddressType::P2WPKH, display);
  }

  if (coin_type == CoinType::COSMOS) {
    return getCosmosAddress(path, "cosmos", display);
  }

  return Result<std::string>::fail(Error::NOT_SUPPORTED);
}

// =============================================================================
// Transaction Signing
// =============================================================================

Result<SignedTransaction> LedgerWallet::signBitcoinTransaction(const BitcoinTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (ledger_features_.current_app != ledger::AppType::BITCOIN &&
      ledger_features_.current_app != ledger::AppType::BITCOIN_TESTNET) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  state_ = ConnectionState::BUSY;

  if (button_callback_) {
    button_callback_("Please review and sign the transaction on your Ledger");
  }

  SignedTransaction signed_tx;
  std::vector<ByteVector> signatures;

  // For each input, we need to:
  // 1. Get trusted input (hash of previous transaction)
  // 2. Start hash for this input
  // 3. Finalize hash with outputs
  // 4. Sign

  // Simplified implementation - real one would handle full protocol
  for (size_t i = 0; i < tx.inputs.size(); ++i) {
    const auto& input = tx.inputs[i];

    // Start hash input
    auto start_result = hashInputStart(tx, i == 0);
    if (!start_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(start_result.error);
    }

    // Finalize with outputs
    auto finalize_result = hashInputFinalize(tx);
    if (!finalize_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(finalize_result.error);
    }

    // Sign this input
    auto sign_result = hashSign(input, tx.lock_time, 0x01);  // SIGHASH_ALL
    if (!sign_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(sign_result.error);
    }

    signatures.push_back(sign_result.value);
  }

  // Combine signatures
  for (const auto& sig : signatures) {
    signed_tx.signature.insert(signed_tx.signature.end(), sig.begin(), sig.end());
  }

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::success(std::move(signed_tx));
}

Result<SignedTransaction> LedgerWallet::signEthereumTransaction(const EthereumTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (ledger_features_.current_app != ledger::AppType::ETHEREUM) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  state_ = ConnectionState::BUSY;

  if (button_callback_) {
    button_callback_("Please review and sign the transaction on your Ledger");
  }

  // Encode transaction (RLP format)
  ByteVector encoded_tx = tx.max_fee_per_gas.has_value()
    ? encodeEthereumTxEIP1559(tx)
    : encodeEthereumTxLegacy(tx);

  // Sign in chunks
  auto sign_result = signEthereumTxChunked(encoded_tx, tx.derivation_path);
  if (!sign_result.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(sign_result.error);
  }

  SignedTransaction signed_tx;
  signed_tx.signature = sign_result.value;

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::success(std::move(signed_tx));
}

// =============================================================================
// Message Signing
// =============================================================================

Result<SignedMessage> LedgerWallet::signMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (ledger_features_.current_app != ledger::AppType::BITCOIN &&
      ledger_features_.current_app != ledger::AppType::BITCOIN_TESTNET) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  if (button_callback_) {
    button_callback_("Please review and sign the message on your Ledger");
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector path_data = encodePath(path);

  // Prepare message with Bitcoin signed message format
  std::string prefixed_message = "\x18" "Bitcoin Signed Message:\n";
  prefixed_message += static_cast<char>(message.size());
  prefixed_message += message;

  // First APDU: path + message length + first chunk
  ByteVector first_data;
  first_data.insert(first_data.end(), path_data.begin(), path_data.end());

  uint16_t msg_len = static_cast<uint16_t>(message.size());
  first_data.push_back(static_cast<uint8_t>(msg_len & 0xFF));
  first_data.push_back(static_cast<uint8_t>((msg_len >> 8) & 0xFF));

  size_t first_chunk = std::min(message.size(), static_cast<size_t>(255 - first_data.size()));
  first_data.insert(first_data.end(), message.begin(), message.begin() + first_chunk);

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_SIGN_MESSAGE,
    0x00,  // First chunk
    0x00,
    first_data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  size_t offset = first_chunk;

  // Send remaining chunks
  while (offset < message.size() && result.value.status == ledger::StatusWord::OK) {
    size_t chunk_size = std::min(message.size() - offset, static_cast<size_t>(255));
    ByteVector chunk_data(message.begin() + offset, message.begin() + offset + chunk_size);
    offset += chunk_size;

    bool is_last = (offset >= message.size());

    cmd = APDUCommand::create(
      ledger::CLA::BITCOIN,
      ledger::INS::BTC_SIGN_MESSAGE,
      is_last ? 0x80 : 0x01,  // Last or continuation
      0x00,
      chunk_data
    );

    result = sendAPDU(cmd);
    if (!result.ok()) {
      return Result<SignedMessage>::fail(result.error);
    }
  }

  if (!result.value.ok()) {
    return Result<SignedMessage>::fail(result.value.error());
  }

  SignedMessage signed_msg;
  if (result.value.data.size() >= 65) {
    signed_msg.recovery_id = result.value.data[0] - 27;
    signed_msg.signature.assign(result.value.data.begin(), result.value.data.begin() + 65);
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> LedgerWallet::signEthereumMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (ledger_features_.current_app != ledger::AppType::ETHEREUM) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  if (button_callback_) {
    button_callback_("Please review and sign the message on your Ledger");
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector path_data = encodePath(path);

  // First APDU: path + message length
  ByteVector first_data;
  first_data.insert(first_data.end(), path_data.begin(), path_data.end());

  uint32_t msg_len = static_cast<uint32_t>(message.size());
  first_data.push_back(static_cast<uint8_t>((msg_len >> 24) & 0xFF));
  first_data.push_back(static_cast<uint8_t>((msg_len >> 16) & 0xFF));
  first_data.push_back(static_cast<uint8_t>((msg_len >> 8) & 0xFF));
  first_data.push_back(static_cast<uint8_t>(msg_len & 0xFF));

  size_t first_chunk = std::min(message.size(), static_cast<size_t>(255 - first_data.size()));
  first_data.insert(first_data.end(), message.begin(), message.begin() + first_chunk);

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_SIGN_MESSAGE,
    0x00,  // First chunk
    0x00,
    first_data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  size_t offset = first_chunk;

  // Send remaining chunks
  while (offset < message.size()) {
    if (result.value.status != ledger::StatusWord::OK) {
      break;
    }

    size_t chunk_size = std::min(message.size() - offset, static_cast<size_t>(255));
    ByteVector chunk_data(message.begin() + offset, message.begin() + offset + chunk_size);
    offset += chunk_size;

    cmd = APDUCommand::create(
      ledger::CLA::ETHEREUM,
      ledger::INS::ETH_SIGN_MESSAGE,
      0x80,  // Continuation
      0x00,
      chunk_data
    );

    result = sendAPDU(cmd);
    if (!result.ok()) {
      return Result<SignedMessage>::fail(result.error);
    }
  }

  if (!result.value.ok()) {
    return Result<SignedMessage>::fail(result.value.error());
  }

  SignedMessage signed_msg;
  if (result.value.data.size() >= 65) {
    // Ledger returns v, r, s
    signed_msg.recovery_id = result.value.data[0] - 27;
    signed_msg.signature.assign(result.value.data.begin(), result.value.data.begin() + 65);
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> LedgerWallet::signTypedData(
  const std::string& path,
  const Bytes32& domain_separator,
  const Bytes32& struct_hash
) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (ledger_features_.current_app != ledger::AppType::ETHEREUM) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  if (button_callback_) {
    button_callback_("Please review and sign the typed data on your Ledger");
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector data = encodePath(path);

  // Add domain separator
  data.insert(data.end(), domain_separator.begin(), domain_separator.end());

  // Add struct hash
  data.insert(data.end(), struct_hash.begin(), struct_hash.end());

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_SIGN_TYPED_DATA,
    0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<SignedMessage>::fail(result.value.error());
  }

  SignedMessage signed_msg;
  if (result.value.data.size() >= 65) {
    signed_msg.recovery_id = result.value.data[0] - 27;
    signed_msg.signature.assign(result.value.data.begin(), result.value.data.begin() + 65);
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

// =============================================================================
// Callbacks
// =============================================================================

void LedgerWallet::setPinCallback(callbacks::PinEntryCallback callback) {
  pin_callback_ = std::move(callback);
}

void LedgerWallet::setPassphraseCallback(callbacks::PassphraseCallback callback) {
  passphrase_callback_ = std::move(callback);
}

void LedgerWallet::setConfirmCallback(callbacks::ConfirmCallback callback) {
  confirm_callback_ = std::move(callback);
}

void LedgerWallet::setButtonCallback(callbacks::ButtonCallback callback) {
  button_callback_ = std::move(callback);
}

void LedgerWallet::setProgressCallback(callbacks::ProgressCallback callback) {
  progress_callback_ = std::move(callback);
}

// =============================================================================
// Ledger-specific Methods
// =============================================================================

Result<void> LedgerWallet::openApp(const std::string& app_name) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector data(app_name.begin(), app_name.end());

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BOLOS,
    ledger::INS::BOLOS_RUN_APP,
    0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<void>::fail(result.value.error());
  }

  // Update current app
  ledger_features_.current_app = detectApp(app_name);
  ledger_features_.app_name = app_name;

  return Result<void>::success();
}

Result<void> LedgerWallet::exitApp() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BOLOS,
    ledger::INS::BOLOS_EXIT_APP,
    0x00,
    0x00
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  ledger_features_.current_app = ledger::AppType::BOLOS;
  ledger_features_.app_name = "";

  return Result<void>::success();
}

Result<void> LedgerWallet::getDeviceInfo() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Get version from BOLOS
  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BOLOS,
    ledger::INS::BOLOS_GET_VERSION,
    0x00,
    0x00,
    {},
    0x00  // Expect response
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  if (result.value.ok()) {
    parseDeviceInfo(result.value.data);
  }

  return Result<void>::success();
}

Result<void> LedgerWallet::getAppConfig() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Try Ethereum app config
  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_GET_APP_CONFIG,
    0x00,
    0x00,
    {},
    0x00
  );

  auto result = sendAPDU(cmd);
  if (result.ok() && result.value.ok()) {
    ledger_features_.current_app = ledger::AppType::ETHEREUM;
    ledger_features_.app_name = "Ethereum";
    parseAppInfo(result.value.data);
    return Result<void>::success();
  }

  // Try Bitcoin app
  cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::GET_VERSION,
    0x00,
    0x00,
    {},
    0x00
  );

  result = sendAPDU(cmd);
  if (result.ok() && result.value.ok()) {
    ledger_features_.current_app = ledger::AppType::BITCOIN;
    ledger_features_.app_name = "Bitcoin";
    parseAppInfo(result.value.data);
    return Result<void>::success();
  }

  // Dashboard/BOLOS
  ledger_features_.current_app = ledger::AppType::BOLOS;

  return Result<void>::success();
}

Result<APDUResponse> LedgerWallet::sendAPDU(const APDUCommand& command) {
  ByteVector apdu = command.serialize();
  return exchangeAPDU(apdu);
}

Result<ByteVector> LedgerWallet::sendAPDUChecked(const APDUCommand& command) {
  auto result = sendAPDU(command);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<ByteVector>::fail(result.value.error());
  }

  return Result<ByteVector>::success(std::move(result.value.data));
}

// =============================================================================
// Bitcoin App Methods
// =============================================================================

Result<std::pair<Bytes33, Bytes32>> LedgerWallet::getBitcoinPublicKey(
  const std::string& path,
  bool display,
  BitcoinAddressType address_type
) {
  if (!isConnected()) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(path_result.error);
  }

  ByteVector data = encodePath(path);

  uint8_t p1 = display ? 0x01 : 0x00;
  uint8_t p2 = 0x00;  // Legacy format

  switch (address_type) {
    case BitcoinAddressType::P2PKH: p2 = 0x00; break;
    case BitcoinAddressType::P2SH: p2 = 0x01; break;
    case BitcoinAddressType::P2WPKH: p2 = 0x02; break;
    case BitcoinAddressType::P2TR: p2 = 0x03; break;
    default: p2 = 0x02; break;
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_GET_WALLET_PUBLIC_KEY,
    p1,
    p2,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(result.value.error());
  }

  // Response: public_key_len(1) + public_key(65) + address_len(1) + address + chain_code(32)
  const auto& resp = result.value.data;
  if (resp.size() < 1) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t pubkey_len = resp[0];
  if (resp.size() < 1 + pubkey_len + 1) {
    return Result<std::pair<Bytes33, Bytes32>>::fail(Error::INVALID_RESPONSE);
  }

  // Extract uncompressed public key and compress it
  Bytes33 pubkey;
  if (pubkey_len == 65) {
    // Compress the key
    uint8_t prefix = (resp[1 + 64] & 1) ? 0x03 : 0x02;
    pubkey[0] = prefix;
    std::copy(resp.begin() + 2, resp.begin() + 34, pubkey.begin() + 1);
  } else if (pubkey_len == 33) {
    std::copy(resp.begin() + 1, resp.begin() + 34, pubkey.begin());
  }

  // Skip address
  size_t offset = 1 + pubkey_len;
  uint8_t addr_len = resp[offset];
  offset += 1 + addr_len;

  // Extract chain code
  Bytes32 chain_code;
  if (offset + 32 <= resp.size()) {
    std::copy(resp.begin() + offset, resp.begin() + offset + 32, chain_code.begin());
  }

  return Result<std::pair<Bytes33, Bytes32>>::success(std::make_pair(pubkey, chain_code));
}

Result<std::string> LedgerWallet::getBitcoinAddress(
  const std::string& path,
  BitcoinAddressType address_type,
  bool display
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector data = encodePath(path);

  uint8_t p1 = display ? 0x01 : 0x00;
  uint8_t p2 = 0x00;

  switch (address_type) {
    case BitcoinAddressType::P2PKH: p2 = 0x00; break;
    case BitcoinAddressType::P2SH: p2 = 0x01; break;
    case BitcoinAddressType::P2WPKH: p2 = 0x02; break;
    case BitcoinAddressType::P2TR: p2 = 0x03; break;
    default: p2 = 0x02; break;
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_GET_WALLET_PUBLIC_KEY,
    p1,
    p2,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<std::string>::fail(result.value.error());
  }

  // Parse response to extract address
  const auto& resp = result.value.data;
  if (resp.size() < 1) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t pubkey_len = resp[0];
  size_t offset = 1 + pubkey_len;

  if (offset >= resp.size()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t addr_len = resp[offset];
  offset++;

  if (offset + addr_len > resp.size()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string address(resp.begin() + offset, resp.begin() + offset + addr_len);
  return Result<std::string>::success(std::move(address));
}

Result<uint32_t> LedgerWallet::getMasterFingerprint() {
  if (!isConnected()) {
    return Result<uint32_t>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_GET_FINGERPRINT,
    0x00,
    0x00
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<uint32_t>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<uint32_t>::fail(result.value.error());
  }

  if (result.value.data.size() < 4) {
    return Result<uint32_t>::fail(Error::INVALID_RESPONSE);
  }

  uint32_t fingerprint = (static_cast<uint32_t>(result.value.data[0]) << 24) |
                         (static_cast<uint32_t>(result.value.data[1]) << 16) |
                         (static_cast<uint32_t>(result.value.data[2]) << 8) |
                         static_cast<uint32_t>(result.value.data[3]);

  return Result<uint32_t>::success(std::move(fingerprint));
}

// =============================================================================
// Ethereum App Methods
// =============================================================================

Result<std::string> LedgerWallet::getEthereumAddress(
  const std::string& path,
  bool display,
  uint64_t chain_id
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector data = encodePath(path);

  // Add chain ID for display (optional)
  if (chain_id > 0 && display) {
    for (int i = 7; i >= 0; --i) {
      data.push_back(static_cast<uint8_t>((chain_id >> (i * 8)) & 0xFF));
    }
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_GET_ADDRESS,
    display ? 0x01 : 0x00,
    chain_id > 0 ? 0x01 : 0x00,  // With chain ID
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<std::string>::fail(result.value.error());
  }

  // Response: public_key(65) + address_len(1) + address
  const auto& resp = result.value.data;
  if (resp.size() < 66) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t addr_len = resp[65];
  if (resp.size() < 66 + addr_len) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string address(resp.begin() + 66, resp.begin() + 66 + addr_len);

  // Ensure 0x prefix
  if (address.size() >= 2 && address[0] != '0') {
    address = "0x" + address;
  }

  return Result<std::string>::success(std::move(address));
}

Result<void> LedgerWallet::provideERC20Info(
  const std::string& contract_address,
  const std::string& ticker,
  uint8_t decimals,
  uint64_t chain_id
) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector data;

  // Ticker (up to 12 chars)
  std::string truncated_ticker = ticker.substr(0, 12);
  data.push_back(static_cast<uint8_t>(truncated_ticker.size()));
  data.insert(data.end(), truncated_ticker.begin(), truncated_ticker.end());

  // Contract address (20 bytes)
  std::string addr = contract_address;
  if (addr.size() >= 2 && addr[0] == '0' && addr[1] == 'x') {
    addr = addr.substr(2);
  }
  for (size_t i = 0; i + 1 < addr.size() && data.size() < 255; i += 2) {
    data.push_back(static_cast<uint8_t>(std::stoul(addr.substr(i, 2), nullptr, 16)));
  }

  // Decimals
  data.push_back(decimals);

  // Chain ID
  for (int i = 3; i >= 0; --i) {
    data.push_back(static_cast<uint8_t>((chain_id >> (i * 8)) & 0xFF));
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_PROVIDE_ERC20,
    0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<void>::fail(result.value.error());
  }

  return Result<void>::success();
}

Result<SignedMessage> LedgerWallet::signEIP712Full(
  const std::string& path,
  const std::string& json_data
) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (!ledger_features_.eip712_full_support) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  // Full EIP-712 support requires multiple APDUs to send struct definitions
  // This is a simplified version - full implementation would parse JSON and
  // send type definitions before message data

  return Result<SignedMessage>::fail(Error::NOT_SUPPORTED);
}

// =============================================================================
// Cosmos App Methods
// =============================================================================

Result<std::string> LedgerWallet::getCosmosAddress(
  const std::string& path,
  const std::string& hrp,
  bool display
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector data = encodePath(path);

  // Add HRP
  data.push_back(static_cast<uint8_t>(hrp.size()));
  data.insert(data.end(), hrp.begin(), hrp.end());

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::COSMOS,
    0x04,  // INS_GET_ADDR
    display ? 0x01 : 0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<std::string>::fail(result.value.error());
  }

  // Response: public_key(33) + address
  const auto& resp = result.value.data;
  if (resp.size() <= 33) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string address(resp.begin() + 33, resp.end());
  return Result<std::string>::success(std::move(address));
}

Result<ByteVector> LedgerWallet::signCosmosTransaction(
  const std::string& path,
  const std::string& tx_json
) {
  if (!isConnected()) {
    return Result<ByteVector>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (button_callback_) {
    button_callback_("Please review and sign the transaction on your Ledger");
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<ByteVector>::fail(path_result.error);
  }

  ByteVector path_data = encodePath(path);

  // First chunk: path + tx start
  ByteVector first_data;
  first_data.insert(first_data.end(), path_data.begin(), path_data.end());

  size_t first_chunk = std::min(tx_json.size(), static_cast<size_t>(255 - first_data.size()));
  first_data.insert(first_data.end(), tx_json.begin(), tx_json.begin() + first_chunk);

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::COSMOS,
    0x02,  // INS_SIGN
    0x00,  // First chunk
    0x00,
    first_data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  size_t offset = first_chunk;

  // Send remaining chunks
  while (offset < tx_json.size()) {
    if (result.value.status != ledger::StatusWord::OK) {
      return Result<ByteVector>::fail(result.value.error());
    }

    size_t chunk_size = std::min(tx_json.size() - offset, static_cast<size_t>(255));
    ByteVector chunk_data(tx_json.begin() + offset, tx_json.begin() + offset + chunk_size);
    offset += chunk_size;

    bool is_last = (offset >= tx_json.size());

    cmd = APDUCommand::create(
      ledger::CLA::COSMOS,
      0x02,
      is_last ? 0x02 : 0x01,  // Last or continuation
      0x00,
      chunk_data
    );

    result = sendAPDU(cmd);
    if (!result.ok()) {
      return Result<ByteVector>::fail(result.error);
    }
  }

  if (!result.value.ok()) {
    return Result<ByteVector>::fail(result.value.error());
  }

  return Result<ByteVector>::success(std::move(result.value.data));
}

// =============================================================================
// APDU Transport
// =============================================================================

Result<APDUResponse> LedgerWallet::exchangeAPDU(const ByteVector& apdu) {
  if (!transport_) {
    return Result<APDUResponse>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Frame APDU for HID transport
  ByteVector framed = frameAPDU(apdu);

  // Send all frames
  constexpr size_t frame_size = HID_REPORT_SIZE;
  for (size_t offset = 0; offset < framed.size(); offset += frame_size) {
    size_t chunk_size = std::min(frame_size, framed.size() - offset);
    ByteVector frame(framed.begin() + offset, framed.begin() + offset + chunk_size);

    TransportError err = transport_->writeRaw(frame);
    if (err != TransportError::OK) {
      return Result<APDUResponse>::fail(transportErrorToError(err));
    }
  }

  // Read response
  auto response_result = unframeResponse();
  if (!response_result.ok()) {
    return Result<APDUResponse>::fail(response_result.error);
  }

  APDUResponse response;

  // Extract status word (last 2 bytes)
  const auto& resp = response_result.value;
  if (resp.size() >= 2) {
    response.status = static_cast<ledger::StatusWord>(
      (static_cast<uint16_t>(resp[resp.size() - 2]) << 8) |
      static_cast<uint16_t>(resp[resp.size() - 1])
    );

    if (resp.size() > 2) {
      response.data.assign(resp.begin(), resp.end() - 2);
    }
  } else {
    response.status = ledger::StatusWord::UNKNOWN_ERROR;
  }

  return Result<APDUResponse>::success(std::move(response));
}

ByteVector LedgerWallet::frameAPDU(const ByteVector& apdu) {
  ByteVector result;

  // Ledger HID framing:
  // First packet: channel(2) + tag(1) + seq(2) + length(2) + data
  // Continuation: channel(2) + tag(1) + seq(2) + data

  constexpr size_t header_first = 7;  // channel + tag + seq + length
  constexpr size_t header_cont = 5;   // channel + tag + seq
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  uint16_t seq = 0;
  size_t offset = 0;

  // First packet
  {
    ByteVector packet(HID_REPORT_SIZE, 0);
    size_t pos = 0;

    // Channel ID (big-endian)
    packet[pos++] = static_cast<uint8_t>((ledger::CHANNEL_ID >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(ledger::CHANNEL_ID & 0xFF);

    // Tag
    packet[pos++] = ledger::APDU_TAG;

    // Sequence (big-endian)
    packet[pos++] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(seq & 0xFF);

    // Length (big-endian)
    uint16_t length = static_cast<uint16_t>(apdu.size());
    packet[pos++] = static_cast<uint8_t>((length >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(length & 0xFF);

    // Data
    size_t chunk = std::min(payload_first, apdu.size());
    std::memcpy(packet.data() + pos, apdu.data(), chunk);
    offset += chunk;

    result.insert(result.end(), packet.begin(), packet.end());
    ++seq;
  }

  // Continuation packets
  while (offset < apdu.size()) {
    ByteVector packet(HID_REPORT_SIZE, 0);
    size_t pos = 0;

    // Channel ID
    packet[pos++] = static_cast<uint8_t>((ledger::CHANNEL_ID >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(ledger::CHANNEL_ID & 0xFF);

    // Tag
    packet[pos++] = ledger::APDU_TAG;

    // Sequence
    packet[pos++] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    packet[pos++] = static_cast<uint8_t>(seq & 0xFF);

    // Data
    size_t remaining = apdu.size() - offset;
    size_t chunk = std::min(payload_cont, remaining);
    std::memcpy(packet.data() + pos, apdu.data() + offset, chunk);
    offset += chunk;

    result.insert(result.end(), packet.begin(), packet.end());
    ++seq;
  }

  return result;
}

Result<ByteVector> LedgerWallet::unframeResponse() {
  ByteVector response;

  constexpr size_t header_first = 7;
  constexpr size_t header_cont = 5;
  constexpr size_t payload_first = HID_REPORT_SIZE - header_first;
  constexpr size_t payload_cont = HID_REPORT_SIZE - header_cont;

  uint16_t expected_length = 0;
  uint16_t expected_seq = 0;

  // Read first packet
  {
    ByteVector packet;
    TransportError err = transport_->readRaw(packet, USER_INTERACTION_TIMEOUT_MS);
    if (err != TransportError::OK) {
      return Result<ByteVector>::fail(transportErrorToError(err));
    }

    if (packet.size() < header_first) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify channel
    uint16_t channel = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    if (channel != ledger::CHANNEL_ID) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify tag
    if (packet[2] != ledger::APDU_TAG) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify sequence
    uint16_t seq = (static_cast<uint16_t>(packet[3]) << 8) | packet[4];
    if (seq != 0) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Get length
    expected_length = (static_cast<uint16_t>(packet[5]) << 8) | packet[6];

    // Extract data
    size_t chunk = std::min(static_cast<size_t>(payload_first),
                           static_cast<size_t>(expected_length));
    response.insert(response.end(), packet.begin() + header_first,
                   packet.begin() + header_first + chunk);

    ++expected_seq;
  }

  // Read continuation packets
  while (response.size() < expected_length) {
    ByteVector packet;
    TransportError err = transport_->readRaw(packet, USER_INTERACTION_TIMEOUT_MS);
    if (err != TransportError::OK) {
      return Result<ByteVector>::fail(transportErrorToError(err));
    }

    if (packet.size() < header_cont) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify channel
    uint16_t channel = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    if (channel != ledger::CHANNEL_ID) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify tag
    if (packet[2] != ledger::APDU_TAG) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Verify sequence
    uint16_t seq = (static_cast<uint16_t>(packet[3]) << 8) | packet[4];
    if (seq != expected_seq) {
      return Result<ByteVector>::fail(Error::INVALID_RESPONSE);
    }

    // Extract data
    size_t remaining = expected_length - response.size();
    size_t chunk = std::min(payload_cont, remaining);
    response.insert(response.end(), packet.begin() + header_cont,
                   packet.begin() + header_cont + chunk);

    ++expected_seq;
  }

  return Result<ByteVector>::success(std::move(response));
}

// =============================================================================
// Path Encoding
// =============================================================================

ByteVector LedgerWallet::encodePath(const std::string& path) {
  auto result = parseDerivationPath(path);
  if (!result.ok()) {
    return {};
  }

  ByteVector encoded;

  // Number of components
  encoded.push_back(static_cast<uint8_t>(result.value.size()));

  // Each component as uint32 big-endian
  for (uint32_t comp : result.value) {
    encoded.push_back(static_cast<uint8_t>((comp >> 24) & 0xFF));
    encoded.push_back(static_cast<uint8_t>((comp >> 16) & 0xFF));
    encoded.push_back(static_cast<uint8_t>((comp >> 8) & 0xFF));
    encoded.push_back(static_cast<uint8_t>(comp & 0xFF));
  }

  return encoded;
}

// =============================================================================
// Transaction Encoding
// =============================================================================

ByteVector LedgerWallet::encodeBitcoinInput(const BitcoinTxInput& input) {
  ByteVector result;

  // Previous hash
  result.insert(result.end(), input.prev_hash.begin(), input.prev_hash.end());

  // Previous index (LE)
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((input.prev_index >> (i * 8)) & 0xFF));
  }

  // Script length + script (for non-SegWit)
  if (!input.script_pubkey.empty()) {
    result.push_back(static_cast<uint8_t>(input.script_pubkey.size()));
    result.insert(result.end(), input.script_pubkey.begin(), input.script_pubkey.end());
  } else {
    result.push_back(0x00);
  }

  // Sequence (LE)
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((input.sequence >> (i * 8)) & 0xFF));
  }

  return result;
}

ByteVector LedgerWallet::encodeBitcoinOutput(const BitcoinTxOutput& output) {
  ByteVector result;

  // Amount (LE)
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((output.amount >> (i * 8)) & 0xFF));
  }

  // Script would be derived from address
  // This is simplified - real implementation would create proper scriptPubKey

  return result;
}

Result<ByteVector> LedgerWallet::getTrustedInput(const ByteVector& prev_tx, uint32_t index) {
  // Trusted input is used for non-SegWit inputs
  // Would send previous transaction to device for verification
  return Result<ByteVector>::fail(Error::NOT_SUPPORTED);
}

Result<void> LedgerWallet::hashInputStart(const BitcoinTransaction& tx, bool new_tx) {
  ByteVector data;

  // Version
  for (int i = 0; i < 4; ++i) {
    data.push_back(static_cast<uint8_t>((tx.version >> (i * 8)) & 0xFF));
  }

  // Number of inputs
  data.push_back(static_cast<uint8_t>(tx.inputs.size()));

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_HASH_INPUT_START,
    0x00,
    new_tx ? 0x00 : 0x80,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<void>::fail(result.value.error());
  }

  return Result<void>::success();
}

Result<void> LedgerWallet::hashInputFinalize(const BitcoinTransaction& tx) {
  ByteVector data;

  // Number of outputs
  data.push_back(static_cast<uint8_t>(tx.outputs.size()));

  // Encode each output
  for (const auto& output : tx.outputs) {
    // Amount
    for (int i = 0; i < 8; ++i) {
      data.push_back(static_cast<uint8_t>((output.amount >> (i * 8)) & 0xFF));
    }

    // Change path or address would go here
  }

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_HASH_INPUT_FINALIZE,
    0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<void>::fail(result.value.error());
  }

  return Result<void>::success();
}

Result<ByteVector> LedgerWallet::hashSign(
  const BitcoinTxInput& input,
  uint32_t lock_time,
  uint8_t sighash_type
) {
  ByteVector data = encodePath(input.derivation_path);

  // Lock time
  for (int i = 0; i < 4; ++i) {
    data.push_back(static_cast<uint8_t>((lock_time >> (i * 8)) & 0xFF));
  }

  // Sighash type
  data.push_back(sighash_type);

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::BITCOIN,
    ledger::INS::BTC_HASH_SIGN,
    0x00,
    0x00,
    data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  if (!result.value.ok()) {
    return Result<ByteVector>::fail(result.value.error());
  }

  return Result<ByteVector>::success(std::move(result.value.data));
}

ByteVector LedgerWallet::encodeEthereumTxLegacy(const EthereumTransaction& tx) {
  // RLP encode legacy transaction
  std::vector<ByteVector> items;

  // Nonce
  ByteVector nonce_bytes;
  uint64_t nonce = tx.nonce;
  while (nonce > 0) {
    nonce_bytes.insert(nonce_bytes.begin(), static_cast<uint8_t>(nonce & 0xFF));
    nonce >>= 8;
  }
  items.push_back(nonce_bytes);

  // Gas price
  items.push_back(tx.gas_price);

  // Gas limit
  ByteVector gas_bytes;
  uint64_t gas = tx.gas_limit;
  while (gas > 0) {
    gas_bytes.insert(gas_bytes.begin(), static_cast<uint8_t>(gas & 0xFF));
    gas >>= 8;
  }
  items.push_back(gas_bytes);

  // To address
  ByteVector to_bytes;
  std::string to = tx.to;
  if (to.size() >= 2 && to[0] == '0' && to[1] == 'x') {
    to = to.substr(2);
  }
  for (size_t i = 0; i + 1 < to.size(); i += 2) {
    to_bytes.push_back(static_cast<uint8_t>(std::stoul(to.substr(i, 2), nullptr, 16)));
  }
  items.push_back(to_bytes);

  // Value
  items.push_back(tx.value);

  // Data
  items.push_back(tx.data);

  // Chain ID (for EIP-155)
  ByteVector chain_bytes;
  uint64_t chain = tx.chain_id;
  while (chain > 0) {
    chain_bytes.insert(chain_bytes.begin(), static_cast<uint8_t>(chain & 0xFF));
    chain >>= 8;
  }
  items.push_back(chain_bytes);

  // Empty r, s for signing
  items.push_back({});
  items.push_back({});

  // Simplified RLP encoding
  ByteVector result;
  size_t total_size = 0;
  for (const auto& item : items) {
    if (item.empty()) {
      total_size += 1;
    } else if (item.size() == 1 && item[0] < 0x80) {
      total_size += 1;
    } else {
      total_size += 1 + item.size();
    }
  }

  if (total_size <= 55) {
    result.push_back(0xC0 + static_cast<uint8_t>(total_size));
  } else {
    ByteVector len_bytes;
    size_t len = total_size;
    while (len > 0) {
      len_bytes.insert(len_bytes.begin(), static_cast<uint8_t>(len & 0xFF));
      len >>= 8;
    }
    result.push_back(0xF7 + static_cast<uint8_t>(len_bytes.size()));
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
  }

  for (const auto& item : items) {
    if (item.empty()) {
      result.push_back(0x80);
    } else if (item.size() == 1 && item[0] < 0x80) {
      result.push_back(item[0]);
    } else {
      result.push_back(0x80 + static_cast<uint8_t>(item.size()));
      result.insert(result.end(), item.begin(), item.end());
    }
  }

  return result;
}

ByteVector LedgerWallet::encodeEthereumTxEIP1559(const EthereumTransaction& tx) {
  // EIP-1559 transaction encoding
  // Type 2 transaction: 0x02 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list])

  ByteVector result;
  result.push_back(0x02);  // Transaction type

  // RLP encode the rest (simplified)
  std::vector<ByteVector> items;

  // Chain ID
  ByteVector chain_bytes;
  uint64_t chain = tx.chain_id;
  while (chain > 0) {
    chain_bytes.insert(chain_bytes.begin(), static_cast<uint8_t>(chain & 0xFF));
    chain >>= 8;
  }
  items.push_back(chain_bytes);

  // Nonce
  ByteVector nonce_bytes;
  uint64_t nonce = tx.nonce;
  while (nonce > 0) {
    nonce_bytes.insert(nonce_bytes.begin(), static_cast<uint8_t>(nonce & 0xFF));
    nonce >>= 8;
  }
  items.push_back(nonce_bytes);

  // Max priority fee
  items.push_back(tx.max_priority_fee_per_gas.value_or(ByteVector{}));

  // Max fee
  items.push_back(tx.max_fee_per_gas.value_or(ByteVector{}));

  // Gas limit
  ByteVector gas_bytes;
  uint64_t gas = tx.gas_limit;
  while (gas > 0) {
    gas_bytes.insert(gas_bytes.begin(), static_cast<uint8_t>(gas & 0xFF));
    gas >>= 8;
  }
  items.push_back(gas_bytes);

  // To
  ByteVector to_bytes;
  std::string to = tx.to;
  if (to.size() >= 2 && to[0] == '0' && to[1] == 'x') {
    to = to.substr(2);
  }
  for (size_t i = 0; i + 1 < to.size(); i += 2) {
    to_bytes.push_back(static_cast<uint8_t>(std::stoul(to.substr(i, 2), nullptr, 16)));
  }
  items.push_back(to_bytes);

  // Value
  items.push_back(tx.value);

  // Data
  items.push_back(tx.data);

  // Access list (empty)
  items.push_back({});

  // Encode as RLP list (simplified)
  size_t total_size = 0;
  for (const auto& item : items) {
    if (item.empty()) {
      total_size += 1;
    } else if (item.size() == 1 && item[0] < 0x80) {
      total_size += 1;
    } else {
      total_size += 1 + item.size();
    }
  }

  if (total_size <= 55) {
    result.push_back(0xC0 + static_cast<uint8_t>(total_size));
  } else {
    ByteVector len_bytes;
    size_t len = total_size;
    while (len > 0) {
      len_bytes.insert(len_bytes.begin(), static_cast<uint8_t>(len & 0xFF));
      len >>= 8;
    }
    result.push_back(0xF7 + static_cast<uint8_t>(len_bytes.size()));
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
  }

  for (const auto& item : items) {
    if (item.empty()) {
      result.push_back(0x80);
    } else if (item.size() == 1 && item[0] < 0x80) {
      result.push_back(item[0]);
    } else {
      result.push_back(0x80 + static_cast<uint8_t>(item.size()));
      result.insert(result.end(), item.begin(), item.end());
    }
  }

  return result;
}

Result<ByteVector> LedgerWallet::signEthereumTxChunked(
  const ByteVector& encoded_tx,
  const std::string& path
) {
  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<ByteVector>::fail(path_result.error);
  }

  ByteVector path_data = encodePath(path);

  // First chunk: path + tx start
  ByteVector first_data;
  first_data.insert(first_data.end(), path_data.begin(), path_data.end());

  size_t first_chunk = std::min(encoded_tx.size(), static_cast<size_t>(255 - first_data.size()));
  first_data.insert(first_data.end(), encoded_tx.begin(), encoded_tx.begin() + first_chunk);

  APDUCommand cmd = APDUCommand::create(
    ledger::CLA::ETHEREUM,
    ledger::INS::ETH_SIGN_TX,
    0x00,  // First chunk
    0x00,
    first_data
  );

  auto result = sendAPDU(cmd);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  size_t offset = first_chunk;

  // Send remaining chunks
  while (offset < encoded_tx.size()) {
    if (result.value.status != ledger::StatusWord::OK) {
      return Result<ByteVector>::fail(result.value.error());
    }

    size_t chunk_size = std::min(encoded_tx.size() - offset, static_cast<size_t>(255));
    ByteVector chunk_data(encoded_tx.begin() + offset, encoded_tx.begin() + offset + chunk_size);
    offset += chunk_size;

    cmd = APDUCommand::create(
      ledger::CLA::ETHEREUM,
      ledger::INS::ETH_SIGN_TX,
      0x80,  // Continuation
      0x00,
      chunk_data
    );

    result = sendAPDU(cmd);
    if (!result.ok()) {
      return Result<ByteVector>::fail(result.error);
    }
  }

  if (!result.value.ok()) {
    return Result<ByteVector>::fail(result.value.error());
  }

  return Result<ByteVector>::success(std::move(result.value.data));
}

// =============================================================================
// Feature Parsing
// =============================================================================

void LedgerWallet::parseDeviceInfo(const ByteVector& data) {
  if (data.size() < 4) {
    return;
  }

  // Target ID
  ledger_features_.target_id = (static_cast<uint32_t>(data[0]) << 24) |
                               (static_cast<uint32_t>(data[1]) << 16) |
                               (static_cast<uint32_t>(data[2]) << 8) |
                               static_cast<uint32_t>(data[3]);

  ledger_features_.model = detectModel(ledger_features_.target_id);

  // SE version follows
  if (data.size() > 5) {
    uint8_t se_len = data[4];
    if (data.size() >= 5 + se_len) {
      ledger_features_.se_version = std::string(data.begin() + 5, data.begin() + 5 + se_len);
    }
  }

  ledger_features_.initialized = true;
}

void LedgerWallet::parseAppInfo(const ByteVector& data) {
  // App configuration varies by app
  // Ethereum: [arbitrary_data_enabled(1)] [erc20_enabled(1)] [version...]

  if (!data.empty()) {
    ledger_features_.arbitrary_data_enabled = (data[0] & 0x01) != 0;
  }

  if (data.size() > 1) {
    ledger_features_.erc20_enabled = (data[1] & 0x01) != 0;
  }

  // Version string follows
  if (data.size() > 2) {
    // Parse version (format varies)
    uint8_t major = data.size() > 2 ? data[2] : 0;
    uint8_t minor = data.size() > 3 ? data[3] : 0;
    uint8_t patch = data.size() > 4 ? data[4] : 0;

    ledger_features_.app_version = std::to_string(major) + "." +
                                   std::to_string(minor) + "." +
                                   std::to_string(patch);
  }
}

ledger::AppType LedgerWallet::detectApp(const std::string& app_name) {
  std::string lower = app_name;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  if (lower.find("bitcoin") != std::string::npos) {
    if (lower.find("test") != std::string::npos) {
      return ledger::AppType::BITCOIN_TESTNET;
    }
    return ledger::AppType::BITCOIN;
  }

  if (lower.find("ethereum") != std::string::npos || lower.find("eth") != std::string::npos) {
    return ledger::AppType::ETHEREUM;
  }

  if (lower.find("cosmos") != std::string::npos) {
    return ledger::AppType::COSMOS;
  }

  if (lower.find("solana") != std::string::npos) {
    return ledger::AppType::SOLANA;
  }

  if (lower.find("polkadot") != std::string::npos) {
    return ledger::AppType::POLKADOT;
  }

  if (lower.find("cardano") != std::string::npos) {
    return ledger::AppType::CARDANO;
  }

  if (lower.find("tezos") != std::string::npos) {
    return ledger::AppType::TEZOS;
  }

  return ledger::AppType::UNKNOWN;
}

ledger::Model LedgerWallet::detectModel(uint32_t target_id) {
  // Target ID format encodes device family
  uint32_t family = (target_id >> 24) & 0xFF;

  switch (family) {
    case 0x31:  // Nano S
      return ledger::Model::NANO_S;
    case 0x33:  // Nano X
      return ledger::Model::NANO_X;
    case 0x34:  // Nano S Plus
      return ledger::Model::NANO_S_PLUS;
    case 0x35:  // Stax
      return ledger::Model::STAX;
    default:
      return ledger::Model::UNKNOWN;
  }
}

// =============================================================================
// Factory Function
// =============================================================================

std::unique_ptr<LedgerWallet> createLedgerWallet() {
  return std::make_unique<LedgerWallet>();
}

} // namespace hw
} // namespace hd_wallet
