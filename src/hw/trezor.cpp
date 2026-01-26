/**
 * @file trezor.cpp
 * @brief Trezor Hardware Wallet Implementation
 *
 * Implements the Trezor-specific protocol for hardware wallet communication.
 * Supports both Trezor One and Trezor Model T.
 */

#include "hd_wallet/hw/trezor.h"
#include "hd_wallet/hw/hw_transport.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Trezor Constants and Helpers
// =============================================================================

namespace trezor {

const char* modelToString(Model model) {
  switch (model) {
    case Model::ONE: return "Trezor One";
    case Model::T: return "Trezor Model T";
    case Model::R: return "Trezor Safe 3";
    default: return "Unknown";
  }
}

const char* failureCodeToString(FailureCode code) {
  switch (code) {
    case FailureCode::UNEXPECTED_MESSAGE: return "Unexpected message";
    case FailureCode::BUTTON_EXPECTED: return "Button expected";
    case FailureCode::DATA_ERROR: return "Data error";
    case FailureCode::ACTION_CANCELLED: return "Action cancelled";
    case FailureCode::PIN_EXPECTED: return "PIN expected";
    case FailureCode::PIN_CANCELLED: return "PIN cancelled";
    case FailureCode::PIN_INVALID: return "Invalid PIN";
    case FailureCode::INVALID_SIGNATURE: return "Invalid signature";
    case FailureCode::PROCESS_ERROR: return "Process error";
    case FailureCode::NOT_ENOUGH_FUNDS: return "Not enough funds";
    case FailureCode::NOT_INITIALIZED: return "Device not initialized";
    case FailureCode::PIN_MISMATCH: return "PIN mismatch";
    case FailureCode::WIPE_CODE_MISMATCH: return "Wipe code mismatch";
    case FailureCode::INVALID_SESSION: return "Invalid session";
    case FailureCode::FIRMWARE_ERROR: return "Firmware error";
    default: return "Unknown error";
  }
}

} // namespace trezor

// =============================================================================
// TrezorWallet Implementation
// =============================================================================

TrezorWallet::TrezorWallet()
  : transport_(nullptr),
    state_(ConnectionState::DISCONNECTED) {}

TrezorWallet::~TrezorWallet() {
  disconnect();
}

TrezorWallet::TrezorWallet(TrezorWallet&& other) noexcept
  : transport_(std::move(other.transport_)),
    trezor_features_(std::move(other.trezor_features_)),
    state_(other.state_),
    session_id_(std::move(other.session_id_)),
    pin_callback_(std::move(other.pin_callback_)),
    passphrase_callback_(std::move(other.passphrase_callback_)),
    confirm_callback_(std::move(other.confirm_callback_)),
    button_callback_(std::move(other.button_callback_)),
    progress_callback_(std::move(other.progress_callback_)) {
  other.state_ = ConnectionState::DISCONNECTED;
}

TrezorWallet& TrezorWallet::operator=(TrezorWallet&& other) noexcept {
  if (this != &other) {
    disconnect();
    transport_ = std::move(other.transport_);
    trezor_features_ = std::move(other.trezor_features_);
    state_ = other.state_;
    session_id_ = std::move(other.session_id_);
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

Result<void> TrezorWallet::connect(const HardwareWalletDevice& device) {
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

  // Set device type based on enumeration
  if (device.type == DeviceType::TREZOR_T) {
    trezor_features_.model = trezor::Model::T;
    trezor_features_.device_type = DeviceType::TREZOR_T;
  } else {
    trezor_features_.model = trezor::Model::ONE;
    trezor_features_.device_type = DeviceType::TREZOR_ONE;
  }

  trezor_features_.serial_number = device.serial_number;

  return Result<void>::success();
}

void TrezorWallet::disconnect() {
  if (transport_) {
    transport_->close();
    transport_.reset();
  }
  state_ = ConnectionState::DISCONNECTED;
  trezor_features_ = TrezorFeatures{};
  session_id_.clear();
}

bool TrezorWallet::isConnected() const {
  return transport_ && transport_->isConnected();
}

ConnectionState TrezorWallet::connectionState() const {
  return state_;
}

// =============================================================================
// Device Initialization
// =============================================================================

Result<DeviceFeatures> TrezorWallet::initialize() {
  if (!isConnected()) {
    return Result<DeviceFeatures>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Build Initialize message
  ByteVector init_msg;

  // Optionally include session_id for session continuity
  if (!session_id_.empty()) {
    init_msg.push_back(0x01);  // Field tag
    init_msg.push_back(static_cast<uint8_t>(session_id_.size()));
    init_msg.insert(init_msg.end(), session_id_.begin(), session_id_.end());
  }

  auto result = exchange(trezor::MessageType::INITIALIZE, init_msg);
  if (!result.ok()) {
    state_ = ConnectionState::ERROR;
    return Result<DeviceFeatures>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  if (msg_type != trezor::MessageType::FEATURES) {
    state_ = ConnectionState::ERROR;
    return Result<DeviceFeatures>::fail(Error::DEVICE_COMM_ERROR);
  }

  parseFeatures(data);
  state_ = ConnectionState::READY;

  if (trezor_features_.needs_pin) {
    state_ = ConnectionState::AWAITING_USER;
  }

  return Result<DeviceFeatures>::success(DeviceFeatures(trezor_features_));
}

const DeviceFeatures& TrezorWallet::features() const {
  return trezor_features_;
}

DeviceType TrezorWallet::deviceType() const {
  return trezor_features_.device_type;
}

// =============================================================================
// PIN and Passphrase
// =============================================================================

Result<void> TrezorWallet::enterPin(const std::string& pin) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector pin_msg;

  // For Trezor One: PIN is scrambled matrix position
  // For Model T: PIN is entered on device, this shouldn't be called
  if (isModelT()) {
    return Result<void>::fail(Error::NOT_SUPPORTED);
  }

  pin_msg.push_back(static_cast<uint8_t>(pin.size()));
  pin_msg.insert(pin_msg.end(), pin.begin(), pin.end());

  auto result = exchange(trezor::MessageType::PIN_MATRIX_ACK, pin_msg);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;
  auto handled = handleDeviceRequest(msg_type, data);

  return handled.ok() ? Result<void>::success() : Result<void>::fail(handled.error);
}

Result<void> TrezorWallet::enterPassphrase(const std::string& passphrase) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector pass_msg;

  // Passphrase length (2 bytes LE)
  uint16_t len = static_cast<uint16_t>(passphrase.size());
  pass_msg.push_back(static_cast<uint8_t>(len & 0xFF));
  pass_msg.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
  pass_msg.insert(pass_msg.end(), passphrase.begin(), passphrase.end());

  // For Model T, indicate if passphrase is on device
  if (supportsTouchscreen() && trezor_features_.passphrase_always_on_device) {
    pass_msg.push_back(0x01);  // on_device flag
  }

  auto result = exchange(trezor::MessageType::PASSPHRASE_ACK, pass_msg);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;
  auto handled = handleDeviceRequest(msg_type, data);

  return handled.ok() ? Result<void>::success() : Result<void>::fail(handled.error);
}

Result<void> TrezorWallet::cancel() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = sendMessage(trezor::MessageType::CANCEL, empty);
  if (!result.ok()) {
    return result;
  }

  state_ = ConnectionState::READY;
  return Result<void>::success();
}

// =============================================================================
// Key Operations
// =============================================================================

Result<Bytes33> TrezorWallet::getPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<Bytes33>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<Bytes33>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Show on display
  if (display) {
    msg.push_back(0x02);  // show_display field tag
    msg.push_back(0x01);
  }

  // Curve name (default secp256k1)
  const std::string curve_name = "secp256k1";
  msg.push_back(0x05);  // ecdsa_curve_name field tag
  msg.push_back(static_cast<uint8_t>(curve_name.size()));
  msg.insert(msg.end(), curve_name.begin(), curve_name.end());

  auto result = exchange(trezor::MessageType::GET_PUBLIC_KEY, msg,
                         display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<Bytes33>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                      display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<Bytes33>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::PUBLIC_KEY) {
    return Result<Bytes33>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Parse public key from HDNodeType structure
  // node: depth(1), fingerprint(4), child_num(4), chain_code(32), public_key(33)
  if (data.size() < 74) {
    return Result<Bytes33>::fail(Error::INVALID_RESPONSE);
  }

  Bytes33 pubkey;
  std::copy(data.begin() + 41, data.begin() + 74, pubkey.begin());

  return Result<Bytes33>::success(std::move(pubkey));
}

Result<std::string> TrezorWallet::getExtendedPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  if (display) {
    msg.push_back(0x02);
    msg.push_back(0x01);
  }

  const std::string curve_name = "secp256k1";
  msg.push_back(0x05);
  msg.push_back(static_cast<uint8_t>(curve_name.size()));
  msg.insert(msg.end(), curve_name.begin(), curve_name.end());

  auto result = exchange(trezor::MessageType::GET_PUBLIC_KEY, msg,
                         display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                      display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<std::string>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::PUBLIC_KEY) {
    return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
  }

  // xpub string follows the HDNodeType
  if (data.size() < 79) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  size_t xpub_offset = 78;
  uint8_t xpub_len = data[xpub_offset];
  if (xpub_offset + 1 + xpub_len > data.size()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string xpub(data.begin() + xpub_offset + 1,
                   data.begin() + xpub_offset + 1 + xpub_len);

  return Result<std::string>::success(std::move(xpub));
}

Result<std::string> TrezorWallet::getAddress(
  const std::string& path,
  CoinType coin_type,
  bool display
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Ethereum addresses
  if (coin_type == CoinType::ETHEREUM || coin_type == CoinType::ETHEREUM_CLASSIC) {
    auto path_result = parseDerivationPath(path);
    if (!path_result.ok()) {
      return Result<std::string>::fail(path_result.error);
    }

    ByteVector msg = encodePath(path);

    if (display) {
      msg.push_back(0x02);
      msg.push_back(0x01);
    }

    auto result = exchange(trezor::MessageType::ETHEREUM_GET_ADDRESS, msg,
                           display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
    if (!result.ok()) {
      return Result<std::string>::fail(result.error);
    }

    auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                        display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
    if (!handled.ok()) {
      return Result<std::string>::fail(handled.error);
    }

    auto [msg_type, data] = handled.value;

    if (msg_type != trezor::MessageType::ETHEREUM_ADDRESS) {
      return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
    }

    // Address is 20 bytes binary
    if (data.size() >= 20) {
      std::stringstream ss;
      ss << "0x";
      for (size_t i = 0; i < 20; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
      }
      return Result<std::string>::success(ss.str());
    }

    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  // Bitcoin addresses
  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Coin name
  std::string coin_name = "Bitcoin";
  if (coin_type == CoinType::BITCOIN_TESTNET) {
    coin_name = "Testnet";
  } else if (coin_type == CoinType::LITECOIN) {
    coin_name = "Litecoin";
  }
  msg.push_back(static_cast<uint8_t>(coin_name.size()));
  msg.insert(msg.end(), coin_name.begin(), coin_name.end());

  if (display) {
    msg.push_back(0x02);
    msg.push_back(0x01);
  }

  // Script type (P2WPKH by default)
  msg.push_back(0x04);
  msg.push_back(static_cast<uint8_t>(trezor::InputScriptType::SPENDWITNESS));

  auto result = exchange(trezor::MessageType::GET_ADDRESS, msg,
                         display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                      display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<std::string>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::ADDRESS) {
    return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Parse address string
  if (data.empty()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t addr_len = data[0];
  if (data.size() < 1 + addr_len) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string address(data.begin() + 1, data.begin() + 1 + addr_len);
  return Result<std::string>::success(std::move(address));
}

// =============================================================================
// Transaction Signing
// =============================================================================

Result<SignedTransaction> TrezorWallet::signBitcoinTransaction(const BitcoinTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  state_ = ConnectionState::BUSY;

  // Build SignTx message
  ByteVector msg;

  // outputs_count
  msg.push_back(static_cast<uint8_t>(tx.outputs.size()));

  // inputs_count
  msg.push_back(static_cast<uint8_t>(tx.inputs.size()));

  // coin_name
  const std::string coin_name = "Bitcoin";
  msg.push_back(static_cast<uint8_t>(coin_name.size()));
  msg.insert(msg.end(), coin_name.begin(), coin_name.end());

  // version
  for (int i = 0; i < 4; ++i) {
    msg.push_back(static_cast<uint8_t>((tx.version >> (i * 8)) & 0xFF));
  }

  // lock_time
  for (int i = 0; i < 4; ++i) {
    msg.push_back(static_cast<uint8_t>((tx.lock_time >> (i * 8)) & 0xFF));
  }

  auto result = exchange(trezor::MessageType::SIGN_TX, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(result.error);
  }

  SignedTransaction signed_tx;
  std::vector<ByteVector> signatures;

  auto [msg_type, data] = result.value;
  uint32_t input_index = 0;
  uint32_t output_index = 0;

  // Handle TxRequest/TxAck protocol
  while (msg_type == trezor::MessageType::TX_REQUEST) {
    if (data.empty()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(Error::DEVICE_COMM_ERROR);
    }

    uint8_t request_type = data[0];
    ByteVector ack_data;

    switch (request_type) {
      case static_cast<uint8_t>(trezor::RequestType::TXINPUT):
        if (input_index < tx.inputs.size()) {
          ack_data = encodeBitcoinTxInput(tx.inputs[input_index], input_index);
          ++input_index;
        }
        break;

      case static_cast<uint8_t>(trezor::RequestType::TXOUTPUT):
        if (output_index < tx.outputs.size()) {
          ack_data = encodeBitcoinTxOutput(tx.outputs[output_index], output_index);
          ++output_index;
        }
        break;

      case static_cast<uint8_t>(trezor::RequestType::TXFINISHED):
        // Signing complete
        if (data.size() > 1) {
          signed_tx.serialized_tx.assign(data.begin() + 1, data.end());
        }
        state_ = ConnectionState::READY;
        return Result<SignedTransaction>::success(std::move(signed_tx));

      default:
        // Could be TXMETA, TXEXTRADATA, etc.
        break;
    }

    // Check for signature in response
    if (data.size() > 2 && data[1] != 0) {
      size_t sig_offset = 2;
      uint8_t sig_len = data[1];
      if (sig_offset + sig_len <= data.size()) {
        ByteVector sig(data.begin() + sig_offset, data.begin() + sig_offset + sig_len);
        signatures.push_back(std::move(sig));
      }
    }

    auto ack_result = exchange(trezor::MessageType::TX_ACK, ack_data, USER_INTERACTION_TIMEOUT_MS);
    if (!ack_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(ack_result.error);
    }

    auto handled = handleDeviceRequest(ack_result.value.first, ack_result.value.second, USER_INTERACTION_TIMEOUT_MS);
    if (!handled.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(handled.error);
    }

    msg_type = handled.value.first;
    data = handled.value.second;
  }

  // Combine all signatures
  for (const auto& sig : signatures) {
    signed_tx.signature.insert(signed_tx.signature.end(), sig.begin(), sig.end());
  }

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::success(std::move(signed_tx));
}

Result<SignedTransaction> TrezorWallet::signEthereumTransaction(const EthereumTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  state_ = ConnectionState::BUSY;

  // Choose message type based on EIP-1559 support
  trezor::MessageType msg_type_to_send = tx.max_fee_per_gas.has_value()
    ? trezor::MessageType::ETHEREUM_SIGN_TX_EIP1559
    : trezor::MessageType::ETHEREUM_SIGN_TX;

  ByteVector msg = tx.max_fee_per_gas.has_value()
    ? encodeEthereumTxEIP1559(tx)
    : encodeEthereumTx(tx);

  auto result = exchange(msg_type_to_send, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  // Handle data chunking if needed
  size_t data_offset = 0;
  const size_t chunk_size = 1024;

  while (msg_type == trezor::MessageType::ETHEREUM_TX_REQUEST) {
    ByteVector chunk;

    if (data_offset < tx.data.size()) {
      size_t remaining = tx.data.size() - data_offset;
      size_t to_send = std::min(remaining, chunk_size);
      chunk.assign(tx.data.begin() + data_offset, tx.data.begin() + data_offset + to_send);
      data_offset += to_send;
    }

    auto chunk_result = exchange(trezor::MessageType::ETHEREUM_TX_ACK, chunk, USER_INTERACTION_TIMEOUT_MS);
    if (!chunk_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(chunk_result.error);
    }

    auto chunk_handled = handleDeviceRequest(chunk_result.value.first, chunk_result.value.second, USER_INTERACTION_TIMEOUT_MS);
    if (!chunk_handled.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(chunk_handled.error);
    }

    msg_type = chunk_handled.value.first;
    data = chunk_handled.value.second;
  }

  // Parse signature response
  if (data.size() < 65) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(Error::INVALID_RESPONSE);
  }

  SignedTransaction signed_tx;
  signed_tx.signature.assign(data.begin(), data.begin() + 65);

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::success(std::move(signed_tx));
}

// =============================================================================
// Message Signing
// =============================================================================

Result<SignedMessage> TrezorWallet::signMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Message
  uint32_t msg_len = static_cast<uint32_t>(message.size());
  for (int i = 0; i < 4; ++i) {
    msg.push_back(static_cast<uint8_t>((msg_len >> (i * 8)) & 0xFF));
  }
  msg.insert(msg.end(), message.begin(), message.end());

  // Coin name
  const std::string coin_name = "Bitcoin";
  msg.push_back(static_cast<uint8_t>(coin_name.size()));
  msg.insert(msg.end(), coin_name.begin(), coin_name.end());

  auto result = exchange(trezor::MessageType::SIGN_MESSAGE, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<SignedMessage>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::MESSAGE_SIGNATURE) {
    return Result<SignedMessage>::fail(Error::DEVICE_COMM_ERROR);
  }

  SignedMessage signed_msg;
  if (data.size() >= 65) {
    signed_msg.recovery_id = data[0];
    signed_msg.signature.assign(data.begin() + 1, data.begin() + 65);
  }

  // Address follows signature
  if (data.size() > 65) {
    uint8_t addr_len = data[65];
    if (data.size() >= 66 + addr_len) {
      signed_msg.address.assign(data.begin() + 66, data.begin() + 66 + addr_len);
    }
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> TrezorWallet::signEthereumMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Message as bytes
  uint32_t msg_len = static_cast<uint32_t>(message.size());
  for (int i = 0; i < 4; ++i) {
    msg.push_back(static_cast<uint8_t>((msg_len >> (i * 8)) & 0xFF));
  }
  msg.insert(msg.end(), message.begin(), message.end());

  auto result = exchange(trezor::MessageType::ETHEREUM_SIGN_MESSAGE, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<SignedMessage>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::ETHEREUM_MESSAGE_SIGNATURE) {
    return Result<SignedMessage>::fail(Error::DEVICE_COMM_ERROR);
  }

  SignedMessage signed_msg;
  if (data.size() >= 65) {
    signed_msg.signature.assign(data.begin(), data.begin() + 65);
    signed_msg.recovery_id = data[0] - 27;
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> TrezorWallet::signTypedData(
  const std::string& path,
  const Bytes32& domain_separator,
  const Bytes32& struct_hash
) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Domain separator hash
  msg.insert(msg.end(), domain_separator.begin(), domain_separator.end());

  // Struct hash
  msg.insert(msg.end(), struct_hash.begin(), struct_hash.end());

  auto result = exchange(trezor::MessageType::ETHEREUM_SIGN_TYPED_DATA, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<SignedMessage>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::ETHEREUM_TYPED_DATA_SIGNATURE) {
    return Result<SignedMessage>::fail(Error::DEVICE_COMM_ERROR);
  }

  SignedMessage signed_msg;
  if (data.size() >= 65) {
    signed_msg.signature.assign(data.begin(), data.begin() + 65);
    signed_msg.recovery_id = data[0] - 27;
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

// =============================================================================
// Callbacks
// =============================================================================

void TrezorWallet::setPinCallback(callbacks::PinEntryCallback callback) {
  pin_callback_ = std::move(callback);
}

void TrezorWallet::setPassphraseCallback(callbacks::PassphraseCallback callback) {
  passphrase_callback_ = std::move(callback);
}

void TrezorWallet::setConfirmCallback(callbacks::ConfirmCallback callback) {
  confirm_callback_ = std::move(callback);
}

void TrezorWallet::setButtonCallback(callbacks::ButtonCallback callback) {
  button_callback_ = std::move(callback);
}

void TrezorWallet::setProgressCallback(callbacks::ProgressCallback callback) {
  progress_callback_ = std::move(callback);
}

// =============================================================================
// Trezor-specific Methods
// =============================================================================

Result<std::string> TrezorWallet::ping(const std::string& message, bool button_protection) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;
  msg.push_back(static_cast<uint8_t>(message.size()));
  msg.insert(msg.end(), message.begin(), message.end());

  if (button_protection) {
    msg.push_back(0x01);  // button_protection flag
  }

  auto result = exchange(trezor::MessageType::PING, msg,
                         button_protection ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                      button_protection ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<std::string>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
  }

  if (data.empty()) {
    return Result<std::string>::success("");
  }

  uint8_t len = data[0];
  if (data.size() < 1 + len) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string response(data.begin() + 1, data.begin() + 1 + len);
  return Result<std::string>::success(std::move(response));
}

Result<ByteVector> TrezorWallet::getEntropy(size_t size) {
  if (!isConnected()) {
    return Result<ByteVector>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (size > 1024) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  ByteVector msg;
  uint32_t sz = static_cast<uint32_t>(size);
  for (int i = 0; i < 4; ++i) {
    msg.push_back(static_cast<uint8_t>((sz >> (i * 8)) & 0xFF));
  }

  auto result = exchange(trezor::MessageType::GET_ENTROPY, msg);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second);
  if (!handled.ok()) {
    return Result<ByteVector>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::ENTROPY) {
    return Result<ByteVector>::fail(Error::DEVICE_COMM_ERROR);
  }

  return Result<ByteVector>::success(std::move(data));
}

Result<void> TrezorWallet::clearSession() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = exchange(trezor::MessageType::CLEAR_SESSION, empty);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  session_id_.clear();
  trezor_features_.needs_pin = trezor_features_.pin_protection;
  trezor_features_.needs_passphrase = trezor_features_.passphrase_protection;

  return Result<void>::success();
}

Result<void> TrezorWallet::applySettings(
  const std::string& label,
  std::optional<bool> use_passphrase,
  const ByteVector& homescreen,
  std::optional<uint32_t> auto_lock_delay,
  std::optional<uint8_t> safety_checks
) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;

  if (!label.empty()) {
    msg.push_back(0x02);
    msg.push_back(static_cast<uint8_t>(label.size()));
    msg.insert(msg.end(), label.begin(), label.end());
  }

  if (use_passphrase.has_value()) {
    msg.push_back(0x03);
    msg.push_back(use_passphrase.value() ? 1 : 0);
  }

  if (!homescreen.empty()) {
    msg.push_back(0x04);
    uint16_t hs_len = static_cast<uint16_t>(homescreen.size());
    msg.push_back(static_cast<uint8_t>(hs_len & 0xFF));
    msg.push_back(static_cast<uint8_t>((hs_len >> 8) & 0xFF));
    msg.insert(msg.end(), homescreen.begin(), homescreen.end());
  }

  if (auto_lock_delay.has_value()) {
    msg.push_back(0x06);
    for (int i = 0; i < 4; ++i) {
      msg.push_back(static_cast<uint8_t>((auto_lock_delay.value() >> (i * 8)) & 0xFF));
    }
  }

  if (safety_checks.has_value()) {
    msg.push_back(0x10);
    msg.push_back(safety_checks.value());
  }

  auto result = exchange(trezor::MessageType::APPLY_SETTINGS, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<void>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Update cached features
  if (!label.empty()) {
    trezor_features_.label = label;
  }
  if (use_passphrase.has_value()) {
    trezor_features_.passphrase_protection = use_passphrase.value();
  }

  return Result<void>::success();
}

Result<void> TrezorWallet::wipeDevice() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = exchange(trezor::MessageType::WIPE_DEVICE, empty, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<void>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  trezor_features_.initialized = false;
  trezor_features_.pin_protection = false;
  trezor_features_.passphrase_protection = false;

  return Result<void>::success();
}

Result<void> TrezorWallet::changePin(bool remove) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;
  msg.push_back(remove ? 1 : 0);

  auto result = exchange(trezor::MessageType::CHANGE_PIN, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<void>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  trezor_features_.pin_protection = !remove;

  return Result<void>::success();
}

Result<void> TrezorWallet::setWipeCode(bool remove) {
  // Only supported on newer firmware
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Would send ChangeWipeCode message
  return Result<void>::fail(Error::NOT_SUPPORTED);
}

Result<void> TrezorWallet::sdProtect(bool enable) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (!supportsTouchscreen()) {
    return Result<void>::fail(Error::DEVICE_NOT_SUPPORTED);
  }

  ByteVector msg;
  msg.push_back(enable ? 0x01 : 0x02);  // ENABLE = 1, DISABLE = 2

  auto result = exchange(trezor::MessageType::SD_PROTECT, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<void>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  trezor_features_.sd_protection = enable;

  return Result<void>::success();
}

Result<ByteVector> TrezorWallet::signCosmosTransaction(
  const std::string& path,
  const std::string& chain_id,
  uint64_t account_number,
  uint64_t sequence,
  const std::string& msgs,
  const std::string& fee,
  const std::string& memo
) {
  if (!isConnected()) {
    return Result<ByteVector>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<ByteVector>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Chain ID
  msg.push_back(static_cast<uint8_t>(chain_id.size()));
  msg.insert(msg.end(), chain_id.begin(), chain_id.end());

  // Account number
  for (int i = 0; i < 8; ++i) {
    msg.push_back(static_cast<uint8_t>((account_number >> (i * 8)) & 0xFF));
  }

  // Sequence
  for (int i = 0; i < 8; ++i) {
    msg.push_back(static_cast<uint8_t>((sequence >> (i * 8)) & 0xFF));
  }

  // Messages (JSON)
  uint16_t msgs_len = static_cast<uint16_t>(msgs.size());
  msg.push_back(static_cast<uint8_t>(msgs_len & 0xFF));
  msg.push_back(static_cast<uint8_t>((msgs_len >> 8) & 0xFF));
  msg.insert(msg.end(), msgs.begin(), msgs.end());

  // Fee (JSON)
  uint16_t fee_len = static_cast<uint16_t>(fee.size());
  msg.push_back(static_cast<uint8_t>(fee_len & 0xFF));
  msg.push_back(static_cast<uint8_t>((fee_len >> 8) & 0xFF));
  msg.insert(msg.end(), fee.begin(), fee.end());

  // Memo
  msg.push_back(static_cast<uint8_t>(memo.size()));
  msg.insert(msg.end(), memo.begin(), memo.end());

  auto result = exchange(trezor::MessageType::COSMOS_SIGN_TX, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<ByteVector>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::COSMOS_SIGNED_TX) {
    return Result<ByteVector>::fail(Error::DEVICE_COMM_ERROR);
  }

  return Result<ByteVector>::success(std::move(data));
}

Result<ByteVector> TrezorWallet::getOwnershipProof(
  const std::string& path,
  trezor::InputScriptType script_type,
  const ByteVector& commitment_data,
  bool user_confirmation
) {
  if (!isConnected()) {
    return Result<ByteVector>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<ByteVector>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Script type
  msg.push_back(static_cast<uint8_t>(script_type));

  // Commitment data
  if (!commitment_data.empty()) {
    msg.push_back(static_cast<uint8_t>(commitment_data.size()));
    msg.insert(msg.end(), commitment_data.begin(), commitment_data.end());
  } else {
    msg.push_back(0);
  }

  // User confirmation
  msg.push_back(user_confirmation ? 1 : 0);

  auto result = exchange(trezor::MessageType::GET_OWNERSHIP_PROOF, msg,
                         user_confirmation ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  auto handled = handleDeviceRequest(result.value.first, result.value.second,
                                      user_confirmation ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!handled.ok()) {
    return Result<ByteVector>::fail(handled.error);
  }

  auto [msg_type, data] = handled.value;

  if (msg_type != trezor::MessageType::OWNERSHIP_PROOF) {
    return Result<ByteVector>::fail(Error::DEVICE_COMM_ERROR);
  }

  return Result<ByteVector>::success(std::move(data));
}

Result<void> TrezorWallet::rebootToBootloader() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = exchange(trezor::MessageType::REBOOT_TO_BOOTLOADER, empty, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  // Device will disconnect after rebooting
  disconnect();

  return Result<void>::success();
}

// =============================================================================
// Protocol Helpers
// =============================================================================

Result<void> TrezorWallet::sendMessage(trezor::MessageType type, const ByteVector& data) {
  if (!transport_) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector encoded = encodeMessage(type, data);

  TransportError err = transport_->sendMessage(trezor::CHANNEL_MAGIC, 0x3F, encoded);
  if (err != TransportError::OK) {
    return Result<void>::fail(transportErrorToError(err));
  }

  return Result<void>::success();
}

Result<std::pair<trezor::MessageType, ByteVector>> TrezorWallet::receiveMessage(uint32_t timeout_ms) {
  if (!transport_) {
    return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector response;
  TransportError err = transport_->receiveMessage(trezor::CHANNEL_MAGIC, 0x3F, response, timeout_ms);
  if (err != TransportError::OK) {
    return Result<std::pair<trezor::MessageType, ByteVector>>::fail(transportErrorToError(err));
  }

  return decodeMessage(response);
}

Result<std::pair<trezor::MessageType, ByteVector>> TrezorWallet::exchange(
  trezor::MessageType type,
  const ByteVector& data,
  uint32_t timeout_ms
) {
  auto send_result = sendMessage(type, data);
  if (!send_result.ok()) {
    return Result<std::pair<trezor::MessageType, ByteVector>>::fail(send_result.error);
  }

  return receiveMessage(timeout_ms);
}

Result<std::pair<trezor::MessageType, ByteVector>> TrezorWallet::handleDeviceRequest(
  trezor::MessageType type,
  const ByteVector& data,
  uint32_t timeout_ms
) {
  trezor::MessageType current_type = type;
  ByteVector current_data = data;

  while (true) {
    switch (current_type) {
      case trezor::MessageType::PIN_MATRIX_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        if (supportsTouchscreen()) {
          // Model T enters PIN on device, just wait
          if (button_callback_) {
            button_callback_("Enter PIN on device");
          }

          auto recv_result = receiveMessage(USER_INTERACTION_TIMEOUT_MS);
          if (!recv_result.ok()) {
            return recv_result;
          }

          current_type = recv_result.value.first;
          current_data = recv_result.value.second;
        } else {
          // Trezor One uses PIN matrix
          if (!pin_callback_) {
            return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
          }

          int retry_count = current_data.empty() ? 3 : current_data[0];
          std::string pin = pin_callback_(retry_count);

          if (pin.empty()) {
            cancel();
            return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
          }

          auto result = enterPin(pin);
          if (!result.ok()) {
            return Result<std::pair<trezor::MessageType, ByteVector>>::fail(result.error);
          }

          auto recv_result = receiveMessage(timeout_ms);
          if (!recv_result.ok()) {
            return recv_result;
          }

          current_type = recv_result.value.first;
          current_data = recv_result.value.second;
        }
        break;
      }

      case trezor::MessageType::PASSPHRASE_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        bool on_device = !current_data.empty() && current_data[0] != 0;

        if (supportsTouchscreen() && trezor_features_.passphrase_always_on_device) {
          on_device = true;
        }

        if (on_device) {
          if (button_callback_) {
            button_callback_("Enter passphrase on device");
          }

          // Send ack indicating on-device entry
          ByteVector ack;
          ack.push_back(0x01);  // on_device = true
          auto result = exchange(trezor::MessageType::PASSPHRASE_ACK, ack, USER_INTERACTION_TIMEOUT_MS);
          if (!result.ok()) {
            return result;
          }

          current_type = result.value.first;
          current_data = result.value.second;
        } else {
          std::string passphrase;
          if (passphrase_callback_) {
            passphrase = passphrase_callback_(false);
          }

          auto result = enterPassphrase(passphrase);
          if (!result.ok()) {
            return Result<std::pair<trezor::MessageType, ByteVector>>::fail(result.error);
          }

          auto recv_result = receiveMessage(timeout_ms);
          if (!recv_result.ok()) {
            return recv_result;
          }

          current_type = recv_result.value.first;
          current_data = recv_result.value.second;
        }
        break;
      }

      case trezor::MessageType::BUTTON_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        if (button_callback_) {
          std::string msg = "Confirm on device";
          if (!current_data.empty()) {
            uint8_t btn_type = current_data[0];
            switch (btn_type) {
              case 3: msg = "Confirm output on device"; break;
              case 8: msg = "Confirm transaction on device"; break;
              case 10: msg = "Verify address on device"; break;
              case 11: msg = "Verify public key on device"; break;
              case 14: msg = "Choose passphrase source on device"; break;
              case 15: msg = "Enter passphrase on device"; break;
              default: break;
            }
          }
          button_callback_(msg);
        }

        // Send ButtonAck
        ByteVector empty;
        auto result = exchange(trezor::MessageType::BUTTON_ACK, empty, timeout_ms);
        if (!result.ok()) {
          return result;
        }

        current_type = result.value.first;
        current_data = result.value.second;
        break;
      }

      case trezor::MessageType::PASSPHRASE_STATE_REQUEST: {
        // Model T sends this after passphrase to confirm session
        ByteVector ack;
        auto result = exchange(trezor::MessageType::PASSPHRASE_STATE_ACK, ack, timeout_ms);
        if (!result.ok()) {
          return result;
        }

        current_type = result.value.first;
        current_data = result.value.second;
        break;
      }

      case trezor::MessageType::FAILURE: {
        uint8_t code = current_data.empty() ? 0 : current_data[0];

        if (code == static_cast<uint8_t>(trezor::FailureCode::ACTION_CANCELLED) ||
            code == static_cast<uint8_t>(trezor::FailureCode::PIN_CANCELLED)) {
          return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
        }

        return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::DEVICE_COMM_ERROR);
      }

      default:
        state_ = ConnectionState::READY;
        return Result<std::pair<trezor::MessageType, ByteVector>>::success(
          std::make_pair(current_type, std::move(current_data))
        );
    }
  }
}

// =============================================================================
// Message Encoding/Decoding
// =============================================================================

ByteVector TrezorWallet::encodeMessage(trezor::MessageType type, const ByteVector& data) {
  ByteVector result;

  // Message type (2 bytes BE)
  uint16_t msg_type = static_cast<uint16_t>(type);
  result.push_back(static_cast<uint8_t>((msg_type >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>(msg_type & 0xFF));

  // Length (4 bytes BE)
  uint32_t length = static_cast<uint32_t>(data.size());
  result.push_back(static_cast<uint8_t>((length >> 24) & 0xFF));
  result.push_back(static_cast<uint8_t>((length >> 16) & 0xFF));
  result.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>(length & 0xFF));

  // Data
  result.insert(result.end(), data.begin(), data.end());

  return result;
}

Result<std::pair<trezor::MessageType, ByteVector>> TrezorWallet::decodeMessage(const ByteVector& data) {
  if (data.size() < 6) {
    return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::INVALID_RESPONSE);
  }

  uint16_t msg_type = (static_cast<uint16_t>(data[0]) << 8) | data[1];

  uint32_t length = (static_cast<uint32_t>(data[2]) << 24) |
                    (static_cast<uint32_t>(data[3]) << 16) |
                    (static_cast<uint32_t>(data[4]) << 8) |
                    static_cast<uint32_t>(data[5]);

  if (data.size() < 6 + length) {
    return Result<std::pair<trezor::MessageType, ByteVector>>::fail(Error::INVALID_RESPONSE);
  }

  ByteVector payload(data.begin() + 6, data.begin() + 6 + length);

  return Result<std::pair<trezor::MessageType, ByteVector>>::success(
    std::make_pair(static_cast<trezor::MessageType>(msg_type), std::move(payload))
  );
}

// =============================================================================
// Path Encoding
// =============================================================================

ByteVector TrezorWallet::encodePath(const std::string& path) {
  auto result = parseDerivationPath(path);
  if (!result.ok()) {
    return {};
  }

  ByteVector encoded;

  // Number of components
  encoded.push_back(static_cast<uint8_t>(result.value.size()));

  // Each component as uint32 BE
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

ByteVector TrezorWallet::encodeBitcoinTxInput(const BitcoinTxInput& input, uint32_t index) {
  ByteVector result;

  // Path
  ByteVector path = encodePath(input.derivation_path);
  result.insert(result.end(), path.begin(), path.end());

  // Prev hash
  result.insert(result.end(), input.prev_hash.begin(), input.prev_hash.end());

  // Prev index
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((input.prev_index >> (i * 8)) & 0xFF));
  }

  // Script type
  trezor::InputScriptType script_type;
  switch (input.script_type) {
    case BitcoinAddressType::P2PKH: script_type = trezor::InputScriptType::SPENDADDRESS; break;
    case BitcoinAddressType::P2SH: script_type = trezor::InputScriptType::SPENDP2SHWITNESS; break;
    case BitcoinAddressType::P2WPKH: script_type = trezor::InputScriptType::SPENDWITNESS; break;
    case BitcoinAddressType::P2TR: script_type = trezor::InputScriptType::SPENDTAPROOT; break;
    default: script_type = trezor::InputScriptType::SPENDWITNESS; break;
  }
  result.push_back(static_cast<uint8_t>(script_type));

  // Amount (8 bytes LE)
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((input.amount >> (i * 8)) & 0xFF));
  }

  // Sequence
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((input.sequence >> (i * 8)) & 0xFF));
  }

  return result;
}

ByteVector TrezorWallet::encodeBitcoinTxOutput(const BitcoinTxOutput& output, uint32_t index) {
  ByteVector result;

  // Amount
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((output.amount >> (i * 8)) & 0xFF));
  }

  // Script type
  trezor::OutputScriptType script_type;
  switch (output.script_type) {
    case BitcoinAddressType::P2PKH: script_type = trezor::OutputScriptType::PAYTOADDRESS; break;
    case BitcoinAddressType::P2SH: script_type = trezor::OutputScriptType::PAYTOSCRIPTHASH; break;
    case BitcoinAddressType::P2WPKH: script_type = trezor::OutputScriptType::PAYTOWITNESS; break;
    case BitcoinAddressType::P2TR: script_type = trezor::OutputScriptType::PAYTOTAPROOT; break;
    default: script_type = trezor::OutputScriptType::PAYTOWITNESS; break;
  }
  result.push_back(static_cast<uint8_t>(script_type));

  // Change path or address
  if (!output.change_path.empty()) {
    ByteVector path = encodePath(output.change_path);
    result.insert(result.end(), path.begin(), path.end());
  } else {
    result.push_back(static_cast<uint8_t>(output.address.size()));
    result.insert(result.end(), output.address.begin(), output.address.end());
  }

  return result;
}

ByteVector TrezorWallet::encodeEthereumTx(const EthereumTransaction& tx) {
  ByteVector result;

  // Path
  ByteVector path = encodePath(tx.derivation_path);
  result.insert(result.end(), path.begin(), path.end());

  // Nonce
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.nonce >> (i * 8)) & 0xFF));
  }

  // Gas price
  result.push_back(static_cast<uint8_t>(tx.gas_price.size()));
  result.insert(result.end(), tx.gas_price.begin(), tx.gas_price.end());

  // Gas limit
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.gas_limit >> (i * 8)) & 0xFF));
  }

  // To address
  if (tx.to.empty()) {
    result.push_back(0);
  } else {
    result.push_back(20);
    std::string to_hex = tx.to;
    if (to_hex.size() >= 2 && to_hex[0] == '0' && to_hex[1] == 'x') {
      to_hex = to_hex.substr(2);
    }
    for (size_t i = 0; i + 1 < to_hex.size(); i += 2) {
      uint8_t byte = static_cast<uint8_t>(std::stoul(to_hex.substr(i, 2), nullptr, 16));
      result.push_back(byte);
    }
  }

  // Value
  result.push_back(static_cast<uint8_t>(tx.value.size()));
  result.insert(result.end(), tx.value.begin(), tx.value.end());

  // Data length and first chunk
  uint32_t data_len = static_cast<uint32_t>(tx.data.size());
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((data_len >> (i * 8)) & 0xFF));
  }

  size_t first_chunk = std::min(tx.data.size(), static_cast<size_t>(1024));
  result.insert(result.end(), tx.data.begin(), tx.data.begin() + first_chunk);

  // Chain ID
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.chain_id >> (i * 8)) & 0xFF));
  }

  return result;
}

ByteVector TrezorWallet::encodeEthereumTxEIP1559(const EthereumTransaction& tx) {
  ByteVector result;

  // Path
  ByteVector path = encodePath(tx.derivation_path);
  result.insert(result.end(), path.begin(), path.end());

  // Nonce
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.nonce >> (i * 8)) & 0xFF));
  }

  // Max fee per gas
  if (tx.max_fee_per_gas.has_value()) {
    result.push_back(static_cast<uint8_t>(tx.max_fee_per_gas->size()));
    result.insert(result.end(), tx.max_fee_per_gas->begin(), tx.max_fee_per_gas->end());
  } else {
    result.push_back(0);
  }

  // Max priority fee per gas
  if (tx.max_priority_fee_per_gas.has_value()) {
    result.push_back(static_cast<uint8_t>(tx.max_priority_fee_per_gas->size()));
    result.insert(result.end(), tx.max_priority_fee_per_gas->begin(), tx.max_priority_fee_per_gas->end());
  } else {
    result.push_back(0);
  }

  // Gas limit
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.gas_limit >> (i * 8)) & 0xFF));
  }

  // To address
  if (tx.to.empty()) {
    result.push_back(0);
  } else {
    result.push_back(20);
    std::string to_hex = tx.to;
    if (to_hex.size() >= 2 && to_hex[0] == '0' && to_hex[1] == 'x') {
      to_hex = to_hex.substr(2);
    }
    for (size_t i = 0; i + 1 < to_hex.size(); i += 2) {
      uint8_t byte = static_cast<uint8_t>(std::stoul(to_hex.substr(i, 2), nullptr, 16));
      result.push_back(byte);
    }
  }

  // Value
  result.push_back(static_cast<uint8_t>(tx.value.size()));
  result.insert(result.end(), tx.value.begin(), tx.value.end());

  // Data length and first chunk
  uint32_t data_len = static_cast<uint32_t>(tx.data.size());
  for (int i = 0; i < 4; ++i) {
    result.push_back(static_cast<uint8_t>((data_len >> (i * 8)) & 0xFF));
  }

  size_t first_chunk = std::min(tx.data.size(), static_cast<size_t>(1024));
  result.insert(result.end(), tx.data.begin(), tx.data.begin() + first_chunk);

  // Chain ID
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((tx.chain_id >> (i * 8)) & 0xFF));
  }

  return result;
}

// =============================================================================
// Feature Parsing
// =============================================================================

void TrezorWallet::parseFeatures(const ByteVector& data) {
  trezor_features_.capabilities = DeviceCapability::BITCOIN_SIGNING |
                                  DeviceCapability::ETHEREUM_SIGNING |
                                  DeviceCapability::MESSAGE_SIGNING |
                                  DeviceCapability::DISPLAY |
                                  DeviceCapability::PIN_PROTECTION |
                                  DeviceCapability::PASSPHRASE |
                                  DeviceCapability::XPUB_EXPORT |
                                  DeviceCapability::CURVE_SECP256K1 |
                                  DeviceCapability::CURVE_ED25519;

  size_t offset = 0;

  while (offset < data.size()) {
    if (offset + 1 >= data.size()) break;

    uint8_t field_tag = data[offset++];
    uint8_t field_len = data[offset++];

    if (offset + field_len > data.size()) break;

    switch (field_tag) {
      case 1:  // vendor
        trezor_features_.manufacturer = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 2:  // major_version
        if (field_len >= 1) {
          trezor_features_.firmware_version = std::to_string(data[offset]);
        }
        break;

      case 5:  // device_id
        trezor_features_.device_id = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 6:  // pin_protection
        if (field_len >= 1) {
          trezor_features_.pin_protection = data[offset] != 0;
        }
        break;

      case 7:  // passphrase_protection
        if (field_len >= 1) {
          trezor_features_.passphrase_protection = data[offset] != 0;
        }
        break;

      case 10:  // label
        trezor_features_.label = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 12:  // initialized
        if (field_len >= 1) {
          trezor_features_.initialized = data[offset] != 0;
        }
        break;

      case 14:  // bootloader_mode
        if (field_len >= 1) {
          trezor_features_.bootloader_mode = data[offset] != 0;
        }
        break;

      case 21:  // model
        if (field_len >= 1) {
          if (data[offset] == '1') {
            trezor_features_.model = trezor::Model::ONE;
            trezor_features_.device_type = DeviceType::TREZOR_ONE;
          } else if (data[offset] == 'T') {
            trezor_features_.model = trezor::Model::T;
            trezor_features_.device_type = DeviceType::TREZOR_T;
          } else if (data[offset] == 'R') {
            trezor_features_.model = trezor::Model::R;
            trezor_features_.device_type = DeviceType::TREZOR_T;  // Treat as T for now
          }
        }
        break;

      case 26:  // session_id
        session_id_.assign(data.begin() + offset, data.begin() + offset + field_len);
        trezor_features_.session_id = session_id_;
        break;

      case 27:  // passphrase_always_on_device
        if (field_len >= 1) {
          trezor_features_.passphrase_always_on_device = data[offset] != 0;
        }
        break;

      case 29:  // safety_checks
        if (field_len >= 1) {
          trezor_features_.safety_checks = data[offset];
        }
        break;

      case 32:  // experimental_features
        if (field_len >= 1) {
          trezor_features_.experimental_features = data[offset] != 0;
        }
        break;

      default:
        break;
    }

    offset += field_len;
  }

  trezor_features_.needs_pin = trezor_features_.pin_protection;
  trezor_features_.needs_passphrase = trezor_features_.passphrase_protection;

  // Add Cosmos support for Model T
  if (supportsTouchscreen()) {
    trezor_features_.capabilities = trezor_features_.capabilities | DeviceCapability::COSMOS_SIGNING;
  }
}

// =============================================================================
// Factory Function
// =============================================================================

std::unique_ptr<TrezorWallet> createTrezorWallet() {
  return std::make_unique<TrezorWallet>();
}

} // namespace hw
} // namespace hd_wallet
