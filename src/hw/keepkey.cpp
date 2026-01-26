/**
 * @file keepkey.cpp
 * @brief KeepKey Hardware Wallet Implementation
 *
 * Implements the KeepKey-specific protocol for hardware wallet communication.
 * KeepKey uses a protocol similar to Trezor with protobuf-like message encoding.
 */

#include "hd_wallet/hw/keepkey.h"
#include "hd_wallet/hw/hw_transport.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace hd_wallet {
namespace hw {

// =============================================================================
// KeepKey Failure Code Strings
// =============================================================================

namespace keepkey {

const char* failureCodeToString(FailureCode code) {
  switch (code) {
    case FailureCode::UNEXPECTED_MESSAGE:
      return "Unexpected message";
    case FailureCode::BUTTON_EXPECTED:
      return "Button expected";
    case FailureCode::DATA_ERROR:
      return "Data error";
    case FailureCode::ACTION_CANCELLED:
      return "Action cancelled";
    case FailureCode::PIN_EXPECTED:
      return "PIN expected";
    case FailureCode::PIN_CANCELLED:
      return "PIN cancelled";
    case FailureCode::PIN_INVALID:
      return "Invalid PIN";
    case FailureCode::INVALID_SIGNATURE:
      return "Invalid signature";
    case FailureCode::PROCESS_ERROR:
      return "Process error";
    case FailureCode::NOT_ENOUGH_FUNDS:
      return "Not enough funds";
    case FailureCode::NOT_INITIALIZED:
      return "Device not initialized";
    case FailureCode::PIN_MISMATCH:
      return "PIN mismatch";
    case FailureCode::FIRMWARE_ERROR:
      return "Firmware error";
    default:
      return "Unknown error";
  }
}

} // namespace keepkey

// =============================================================================
// KeepKeyWallet Implementation
// =============================================================================

KeepKeyWallet::KeepKeyWallet()
  : transport_(nullptr),
    state_(ConnectionState::DISCONNECTED) {}

KeepKeyWallet::~KeepKeyWallet() {
  disconnect();
}

KeepKeyWallet::KeepKeyWallet(KeepKeyWallet&& other) noexcept
  : transport_(std::move(other.transport_)),
    features_(std::move(other.features_)),
    state_(other.state_),
    pin_callback_(std::move(other.pin_callback_)),
    passphrase_callback_(std::move(other.passphrase_callback_)),
    confirm_callback_(std::move(other.confirm_callback_)),
    button_callback_(std::move(other.button_callback_)),
    progress_callback_(std::move(other.progress_callback_)) {
  other.state_ = ConnectionState::DISCONNECTED;
}

KeepKeyWallet& KeepKeyWallet::operator=(KeepKeyWallet&& other) noexcept {
  if (this != &other) {
    disconnect();
    transport_ = std::move(other.transport_);
    features_ = std::move(other.features_);
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

Result<void> KeepKeyWallet::connect(const HardwareWalletDevice& device) {
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
  features_.device_type = DeviceType::KEEPKEY;
  features_.serial_number = device.serial_number;

  return Result<void>::success();
}

void KeepKeyWallet::disconnect() {
  if (transport_) {
    transport_->close();
    transport_.reset();
  }
  state_ = ConnectionState::DISCONNECTED;
  features_ = DeviceFeatures{};
}

bool KeepKeyWallet::isConnected() const {
  return transport_ && transport_->isConnected();
}

ConnectionState KeepKeyWallet::connectionState() const {
  return state_;
}

// =============================================================================
// Device Initialization
// =============================================================================

Result<DeviceFeatures> KeepKeyWallet::initialize() {
  if (!isConnected()) {
    return Result<DeviceFeatures>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Send Initialize message (empty payload)
  ByteVector init_msg;

  auto result = exchange(keepkey::MessageType::INITIALIZE, init_msg);
  if (!result.ok()) {
    state_ = ConnectionState::ERROR;
    return Result<DeviceFeatures>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  if (msg_type != keepkey::MessageType::FEATURES) {
    state_ = ConnectionState::ERROR;
    return Result<DeviceFeatures>::fail(Error::DEVICE_COMM_ERROR);
  }

  parseFeatures(data);
  state_ = ConnectionState::READY;

  if (features_.needs_pin) {
    state_ = ConnectionState::AWAITING_USER;
  }

  return Result<DeviceFeatures>::success(DeviceFeatures(features_));
}

const DeviceFeatures& KeepKeyWallet::features() const {
  return features_;
}

// =============================================================================
// PIN and Passphrase
// =============================================================================

Result<void> KeepKeyWallet::enterPin(const std::string& pin) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Encode PIN as simple length-prefixed string
  ByteVector pin_msg;
  pin_msg.push_back(static_cast<uint8_t>(pin.size()));
  pin_msg.insert(pin_msg.end(), pin.begin(), pin.end());

  auto result = exchange(keepkey::MessageType::PIN_MATRIX_ACK, pin_msg);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  // Handle possible further requests
  return handleDeviceRequest(msg_type, data).ok()
    ? Result<void>::success()
    : Result<void>::fail(Error::DEVICE_COMM_ERROR);
}

Result<void> KeepKeyWallet::enterPassphrase(const std::string& passphrase) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Encode passphrase
  ByteVector pass_msg;
  uint16_t len = static_cast<uint16_t>(passphrase.size());
  pass_msg.push_back(static_cast<uint8_t>(len & 0xFF));
  pass_msg.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
  pass_msg.insert(pass_msg.end(), passphrase.begin(), passphrase.end());

  auto result = exchange(keepkey::MessageType::PASSPHRASE_ACK, pass_msg);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  return handleDeviceRequest(msg_type, data).ok()
    ? Result<void>::success()
    : Result<void>::fail(Error::DEVICE_COMM_ERROR);
}

Result<void> KeepKeyWallet::cancel() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = sendMessage(keepkey::MessageType::CANCEL, empty);
  if (!result.ok()) {
    return result;
  }

  state_ = ConnectionState::READY;
  return Result<void>::success();
}

// =============================================================================
// Key Operations
// =============================================================================

Result<Bytes33> KeepKeyWallet::getPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<Bytes33>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // Parse and encode path
  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<Bytes33>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Add display flag
  msg.push_back(display ? 1 : 0);

  // Add curve type (secp256k1 = "secp256k1")
  const std::string curve_name = "secp256k1";
  msg.push_back(static_cast<uint8_t>(curve_name.size()));
  msg.insert(msg.end(), curve_name.begin(), curve_name.end());

  auto result = exchange(keepkey::MessageType::GET_PUBLIC_KEY, msg,
                         display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<Bytes33>::fail(result.error);
  }

  // Handle any device requests (button, PIN, etc.)
  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second,
                                               display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::PUBLIC_KEY) {
    return Result<Bytes33>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Parse public key from response
  // Response format: [node][xpub_string]
  // node: [depth][fingerprint(4)][child_num(4)][chain_code(32)][public_key(33)]
  if (data.size() < 78) {  // Minimum size for node
    return Result<Bytes33>::fail(Error::INVALID_RESPONSE);
  }

  // Extract public key (33 bytes at offset 1 + 4 + 4 + 32 = 41)
  Bytes33 pubkey;
  std::copy(data.begin() + 41, data.begin() + 74, pubkey.begin());

  return Result<Bytes33>::success(std::move(pubkey));
}

Result<std::string> KeepKeyWallet::getExtendedPublicKey(const std::string& path, bool display) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<std::string>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);
  msg.push_back(display ? 1 : 0);

  const std::string curve_name = "secp256k1";
  msg.push_back(static_cast<uint8_t>(curve_name.size()));
  msg.insert(msg.end(), curve_name.begin(), curve_name.end());

  auto result = exchange(keepkey::MessageType::GET_PUBLIC_KEY, msg,
                         display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second,
                                               display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::PUBLIC_KEY) {
    return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Response contains xpub string after the node data
  // Find xpub string (length-prefixed after node)
  if (data.size() < 79) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  size_t xpub_offset = 78;  // After node data
  if (xpub_offset >= data.size()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  uint8_t xpub_len = data[xpub_offset];
  if (xpub_offset + 1 + xpub_len > data.size()) {
    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  std::string xpub(data.begin() + xpub_offset + 1,
                   data.begin() + xpub_offset + 1 + xpub_len);

  return Result<std::string>::success(std::move(xpub));
}

Result<std::string> KeepKeyWallet::getAddress(
  const std::string& path,
  CoinType coin_type,
  bool display
) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  // For Ethereum, use Ethereum-specific message
  if (coin_type == CoinType::ETHEREUM || coin_type == CoinType::ETHEREUM_CLASSIC) {
    auto path_result = parseDerivationPath(path);
    if (!path_result.ok()) {
      return Result<std::string>::fail(path_result.error);
    }

    ByteVector msg = encodePath(path);
    msg.push_back(display ? 1 : 0);

    auto result = exchange(keepkey::MessageType::ETHEREUM_GET_ADDRESS, msg,
                           display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS);
    if (!result.ok()) {
      return Result<std::string>::fail(result.error);
    }

    auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second,
                                                 display ? USER_INTERACTION_TIMEOUT_MS : DEFAULT_TIMEOUT_MS).value;

    if (msg_type != keepkey::MessageType::ETHEREUM_ADDRESS) {
      return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
    }

    // Parse address from response (20 bytes binary or hex string)
    if (data.size() >= 20) {
      // Convert to hex string with 0x prefix
      std::stringstream ss;
      ss << "0x";
      for (size_t i = 0; i < 20; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
      }
      return Result<std::string>::success(ss.str());
    }

    return Result<std::string>::fail(Error::INVALID_RESPONSE);
  }

  // For Bitcoin and other coins, get public key and derive address
  // (Address derivation would be implemented separately)
  return Result<std::string>::fail(Error::NOT_SUPPORTED);
}

// =============================================================================
// Transaction Signing
// =============================================================================

Result<SignedTransaction> KeepKeyWallet::signBitcoinTransaction(const BitcoinTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  state_ = ConnectionState::BUSY;

  // Build SignTx message
  ByteVector msg;

  // outputs_count (varint)
  msg.push_back(static_cast<uint8_t>(tx.outputs.size()));

  // inputs_count (varint)
  msg.push_back(static_cast<uint8_t>(tx.inputs.size()));

  // coin_name
  const std::string coin_name = "Bitcoin";
  msg.push_back(static_cast<uint8_t>(coin_name.size()));
  msg.insert(msg.end(), coin_name.begin(), coin_name.end());

  // version
  msg.push_back(static_cast<uint8_t>(tx.version & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.version >> 8) & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.version >> 16) & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.version >> 24) & 0xFF));

  // lock_time
  msg.push_back(static_cast<uint8_t>(tx.lock_time & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.lock_time >> 8) & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.lock_time >> 16) & 0xFF));
  msg.push_back(static_cast<uint8_t>((tx.lock_time >> 24) & 0xFF));

  auto result = exchange(keepkey::MessageType::SIGN_TX, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(result.error);
  }

  SignedTransaction signed_tx;
  ByteVector serialized;

  // Handle TxRequest/TxAck flow
  auto [msg_type, data] = result.value;
  uint32_t input_index = 0;
  uint32_t output_index = 0;

  while (msg_type == keepkey::MessageType::TX_REQUEST) {
    // Parse request type from data
    if (data.empty()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(Error::DEVICE_COMM_ERROR);
    }

    uint8_t request_type = data[0];
    ByteVector ack_data;

    switch (request_type) {
      case 0:  // TXINPUT
        if (input_index < tx.inputs.size()) {
          ack_data = encodeBitcoinTxInput(tx.inputs[input_index], input_index);
          ++input_index;
        }
        break;

      case 1:  // TXOUTPUT
        if (output_index < tx.outputs.size()) {
          ack_data = encodeBitcoinTxOutput(tx.outputs[output_index], output_index);
          ++output_index;
        }
        break;

      case 3:  // TXFINISHED
        // Signing complete, extract signature
        if (data.size() > 1) {
          signed_tx.signature.assign(data.begin() + 1, data.end());
        }
        state_ = ConnectionState::READY;
        return Result<SignedTransaction>::success(std::move(signed_tx));

      default:
        state_ = ConnectionState::READY;
        return Result<SignedTransaction>::fail(Error::DEVICE_COMM_ERROR);
    }

    auto ack_result = exchange(keepkey::MessageType::TX_ACK, ack_data, USER_INTERACTION_TIMEOUT_MS);
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

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::fail(Error::DEVICE_COMM_ERROR);
}

Result<SignedTransaction> KeepKeyWallet::signEthereumTransaction(const EthereumTransaction& tx) {
  if (!isConnected()) {
    return Result<SignedTransaction>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  state_ = ConnectionState::BUSY;

  ByteVector msg = encodeEthereumTx(tx);

  auto result = exchange(keepkey::MessageType::ETHEREUM_SIGN_TX, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  // Handle chunked data if needed
  while (msg_type == keepkey::MessageType::ETHEREUM_TX_REQUEST) {
    // Send next chunk of data
    ByteVector chunk;
    // ... encode next chunk of tx.data if it was too large

    auto chunk_result = exchange(keepkey::MessageType::ETHEREUM_TX_ACK, chunk, USER_INTERACTION_TIMEOUT_MS);
    if (!chunk_result.ok()) {
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(chunk_result.error);
    }

    auto handled = handleDeviceRequest(chunk_result.value.first, chunk_result.value.second, USER_INTERACTION_TIMEOUT_MS);
    msg_type = handled.value.first;
    data = handled.value.second;
  }

  if (msg_type != keepkey::MessageType::ETHEREUM_TX_REQUEST) {
    // Final response should contain signature
    if (data.size() < 65) {  // v + r + s
      state_ = ConnectionState::READY;
      return Result<SignedTransaction>::fail(Error::INVALID_RESPONSE);
    }

    SignedTransaction signed_tx;
    // Parse v, r, s from response
    // v: 1 byte, r: 32 bytes, s: 32 bytes
    signed_tx.signature.assign(data.begin(), data.end());

    state_ = ConnectionState::READY;
    return Result<SignedTransaction>::success(std::move(signed_tx));
  }

  state_ = ConnectionState::READY;
  return Result<SignedTransaction>::fail(Error::DEVICE_COMM_ERROR);
}

// =============================================================================
// Message Signing
// =============================================================================

Result<SignedMessage> KeepKeyWallet::signMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Add message
  uint32_t msg_len = static_cast<uint32_t>(message.size());
  msg.push_back(static_cast<uint8_t>(msg_len & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 8) & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 16) & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 24) & 0xFF));
  msg.insert(msg.end(), message.begin(), message.end());

  // Add coin name
  const std::string coin_name = "Bitcoin";
  msg.push_back(static_cast<uint8_t>(coin_name.size()));
  msg.insert(msg.end(), coin_name.begin(), coin_name.end());

  auto result = exchange(keepkey::MessageType::SIGN_MESSAGE, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::MESSAGE_SIGNATURE) {
    return Result<SignedMessage>::fail(Error::DEVICE_COMM_ERROR);
  }

  SignedMessage signed_msg;

  // Parse signature (65 bytes: recovery_id + r + s)
  if (data.size() >= 65) {
    signed_msg.recovery_id = data[0];
    signed_msg.signature.assign(data.begin() + 1, data.begin() + 65);
  }

  // Parse address if present
  if (data.size() > 65) {
    uint8_t addr_len = data[65];
    if (data.size() >= 66 + addr_len) {
      signed_msg.address.assign(data.begin() + 66, data.begin() + 66 + addr_len);
    }
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> KeepKeyWallet::signEthereumMessage(const std::string& path, const std::string& message) {
  if (!isConnected()) {
    return Result<SignedMessage>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  auto path_result = parseDerivationPath(path);
  if (!path_result.ok()) {
    return Result<SignedMessage>::fail(path_result.error);
  }

  ByteVector msg = encodePath(path);

  // Add message (as bytes)
  uint32_t msg_len = static_cast<uint32_t>(message.size());
  msg.push_back(static_cast<uint8_t>(msg_len & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 8) & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 16) & 0xFF));
  msg.push_back(static_cast<uint8_t>((msg_len >> 24) & 0xFF));
  msg.insert(msg.end(), message.begin(), message.end());

  auto result = exchange(keepkey::MessageType::ETHEREUM_SIGN_MESSAGE, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::ETHEREUM_MESSAGE_SIGNATURE) {
    return Result<SignedMessage>::fail(Error::DEVICE_COMM_ERROR);
  }

  SignedMessage signed_msg;

  // Parse signature (v + r + s = 65 bytes)
  if (data.size() >= 65) {
    signed_msg.signature.assign(data.begin(), data.begin() + 65);
    signed_msg.recovery_id = data[0] - 27;  // v is 27 or 28
  }

  return Result<SignedMessage>::success(std::move(signed_msg));
}

Result<SignedMessage> KeepKeyWallet::signTypedData(
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

  // Add domain separator
  msg.insert(msg.end(), domain_separator.begin(), domain_separator.end());

  // Add struct hash
  msg.insert(msg.end(), struct_hash.begin(), struct_hash.end());

  auto result = exchange(keepkey::MessageType::ETHEREUM_SIGN_TYPED_DATA, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<SignedMessage>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::ETHEREUM_TYPED_DATA_SIGNATURE) {
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

void KeepKeyWallet::setPinCallback(callbacks::PinEntryCallback callback) {
  pin_callback_ = std::move(callback);
}

void KeepKeyWallet::setPassphraseCallback(callbacks::PassphraseCallback callback) {
  passphrase_callback_ = std::move(callback);
}

void KeepKeyWallet::setConfirmCallback(callbacks::ConfirmCallback callback) {
  confirm_callback_ = std::move(callback);
}

void KeepKeyWallet::setButtonCallback(callbacks::ButtonCallback callback) {
  button_callback_ = std::move(callback);
}

void KeepKeyWallet::setProgressCallback(callbacks::ProgressCallback callback) {
  progress_callback_ = std::move(callback);
}

// =============================================================================
// KeepKey-specific Methods
// =============================================================================

Result<std::string> KeepKeyWallet::ping(const std::string& message) {
  if (!isConnected()) {
    return Result<std::string>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;
  msg.push_back(static_cast<uint8_t>(message.size()));
  msg.insert(msg.end(), message.begin(), message.end());

  auto result = exchange(keepkey::MessageType::PING, msg);
  if (!result.ok()) {
    return Result<std::string>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  if (msg_type != keepkey::MessageType::SUCCESS) {
    return Result<std::string>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Extract echoed message
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

Result<ByteVector> KeepKeyWallet::getEntropy(size_t size) {
  if (!isConnected()) {
    return Result<ByteVector>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  if (size > 1024) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  ByteVector msg;
  uint32_t sz = static_cast<uint32_t>(size);
  msg.push_back(static_cast<uint8_t>(sz & 0xFF));
  msg.push_back(static_cast<uint8_t>((sz >> 8) & 0xFF));
  msg.push_back(static_cast<uint8_t>((sz >> 16) & 0xFF));
  msg.push_back(static_cast<uint8_t>((sz >> 24) & 0xFF));

  auto result = exchange(keepkey::MessageType::GET_ENTROPY, msg);
  if (!result.ok()) {
    return Result<ByteVector>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second).value;

  if (msg_type != keepkey::MessageType::ENTROPY) {
    return Result<ByteVector>::fail(Error::DEVICE_COMM_ERROR);
  }

  return Result<ByteVector>::success(std::move(data));
}

Result<void> KeepKeyWallet::clearSession() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = exchange(keepkey::MessageType::CLEAR_SESSION, empty);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = result.value;

  if (msg_type != keepkey::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  features_.needs_pin = features_.pin_protection;
  features_.needs_passphrase = features_.passphrase_protection;

  return Result<void>::success();
}

Result<void> KeepKeyWallet::applySettings(
  const std::string& label,
  std::optional<bool> use_passphrase,
  const std::string& language
) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;

  // Encode optional fields
  if (!language.empty()) {
    msg.push_back(0x01);  // Field tag for language
    msg.push_back(static_cast<uint8_t>(language.size()));
    msg.insert(msg.end(), language.begin(), language.end());
  }

  if (!label.empty()) {
    msg.push_back(0x02);  // Field tag for label
    msg.push_back(static_cast<uint8_t>(label.size()));
    msg.insert(msg.end(), label.begin(), label.end());
  }

  if (use_passphrase.has_value()) {
    msg.push_back(0x03);  // Field tag for use_passphrase
    msg.push_back(use_passphrase.value() ? 1 : 0);
  }

  auto result = exchange(keepkey::MessageType::APPLY_SETTINGS, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Update cached features
  if (!label.empty()) {
    features_.label = label;
  }
  if (use_passphrase.has_value()) {
    features_.passphrase_protection = use_passphrase.value();
  }

  return Result<void>::success();
}

Result<void> KeepKeyWallet::wipeDevice() {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector empty;
  auto result = exchange(keepkey::MessageType::WIPE_DEVICE, empty, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  // Device is now uninitialized
  features_.initialized = false;
  features_.pin_protection = false;
  features_.passphrase_protection = false;

  return Result<void>::success();
}

Result<void> KeepKeyWallet::changePin(bool remove) {
  if (!isConnected()) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector msg;
  msg.push_back(remove ? 1 : 0);

  auto result = exchange(keepkey::MessageType::CHANGE_PIN, msg, USER_INTERACTION_TIMEOUT_MS);
  if (!result.ok()) {
    return Result<void>::fail(result.error);
  }

  auto [msg_type, data] = handleDeviceRequest(result.value.first, result.value.second, USER_INTERACTION_TIMEOUT_MS).value;

  if (msg_type != keepkey::MessageType::SUCCESS) {
    return Result<void>::fail(Error::DEVICE_COMM_ERROR);
  }

  features_.pin_protection = !remove;

  return Result<void>::success();
}

// =============================================================================
// Protocol Helpers
// =============================================================================

Result<void> KeepKeyWallet::sendMessage(keepkey::MessageType type, const ByteVector& data) {
  if (!transport_) {
    return Result<void>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector encoded = encodeMessage(type, data);

  TransportError err = transport_->sendMessage(keepkey::CHANNEL_ID, keepkey::MESSAGE_MAGIC, encoded);
  if (err != TransportError::OK) {
    return Result<void>::fail(transportErrorToError(err));
  }

  return Result<void>::success();
}

Result<std::pair<keepkey::MessageType, ByteVector>> KeepKeyWallet::receiveMessage(uint32_t timeout_ms) {
  if (!transport_) {
    return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::DEVICE_NOT_CONNECTED);
  }

  ByteVector response;
  TransportError err = transport_->receiveMessage(keepkey::CHANNEL_ID, keepkey::MESSAGE_MAGIC, response, timeout_ms);
  if (err != TransportError::OK) {
    return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(transportErrorToError(err));
  }

  return decodeMessage(response);
}

Result<std::pair<keepkey::MessageType, ByteVector>> KeepKeyWallet::exchange(
  keepkey::MessageType type,
  const ByteVector& data,
  uint32_t timeout_ms
) {
  auto send_result = sendMessage(type, data);
  if (!send_result.ok()) {
    return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(send_result.error);
  }

  return receiveMessage(timeout_ms);
}

Result<std::pair<keepkey::MessageType, ByteVector>> KeepKeyWallet::handleDeviceRequest(
  keepkey::MessageType type,
  const ByteVector& data,
  uint32_t timeout_ms
) {
  keepkey::MessageType current_type = type;
  ByteVector current_data = data;

  while (true) {
    switch (current_type) {
      case keepkey::MessageType::PIN_MATRIX_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        if (!pin_callback_) {
          return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
        }

        int retry_count = current_data.empty() ? 3 : current_data[0];
        std::string pin = pin_callback_(retry_count);

        if (pin.empty()) {
          cancel();
          return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
        }

        auto result = enterPin(pin);
        if (!result.ok()) {
          return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(result.error);
        }

        auto recv_result = receiveMessage(timeout_ms);
        if (!recv_result.ok()) {
          return recv_result;
        }

        current_type = recv_result.value.first;
        current_data = recv_result.value.second;
        break;
      }

      case keepkey::MessageType::PASSPHRASE_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        if (!passphrase_callback_) {
          // Send empty passphrase
          auto result = enterPassphrase("");
          if (!result.ok()) {
            return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(result.error);
          }
        } else {
          bool on_device = !current_data.empty() && current_data[0] != 0;
          std::string passphrase = passphrase_callback_(on_device);

          auto result = enterPassphrase(passphrase);
          if (!result.ok()) {
            return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(result.error);
          }
        }

        auto recv_result = receiveMessage(timeout_ms);
        if (!recv_result.ok()) {
          return recv_result;
        }

        current_type = recv_result.value.first;
        current_data = recv_result.value.second;
        break;
      }

      case keepkey::MessageType::BUTTON_REQUEST: {
        state_ = ConnectionState::AWAITING_USER;

        if (button_callback_) {
          std::string msg = "Please confirm on device";
          if (current_data.size() > 1) {
            uint8_t btn_type = current_data[0];
            // Map button type to message
            switch (btn_type) {
              case 3: msg = "Confirm output on device"; break;
              case 8: msg = "Confirm transaction on device"; break;
              case 10: msg = "Verify address on device"; break;
              case 11: msg = "Verify public key on device"; break;
              default: break;
            }
          }
          button_callback_(msg);
        }

        // Send ButtonAck
        ByteVector empty;
        auto result = exchange(keepkey::MessageType::BUTTON_ACK, empty, timeout_ms);
        if (!result.ok()) {
          return result;
        }

        current_type = result.value.first;
        current_data = result.value.second;
        break;
      }

      case keepkey::MessageType::FAILURE: {
        // Parse failure code
        uint8_t code = current_data.empty() ? 0 : current_data[0];

        if (code == static_cast<uint8_t>(keepkey::FailureCode::ACTION_CANCELLED) ||
            code == static_cast<uint8_t>(keepkey::FailureCode::PIN_CANCELLED)) {
          return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::USER_CANCELLED);
        }

        return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::DEVICE_COMM_ERROR);
      }

      default:
        // Not a request that needs handling
        state_ = ConnectionState::READY;
        return Result<std::pair<keepkey::MessageType, ByteVector>>::success(
          std::make_pair(current_type, std::move(current_data))
        );
    }
  }
}

// =============================================================================
// Message Encoding/Decoding
// =============================================================================

ByteVector KeepKeyWallet::encodeMessage(keepkey::MessageType type, const ByteVector& data) {
  ByteVector result;

  // Message type (2 bytes, big-endian)
  uint16_t msg_type = static_cast<uint16_t>(type);
  result.push_back(static_cast<uint8_t>((msg_type >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>(msg_type & 0xFF));

  // Data length (4 bytes, big-endian)
  uint32_t length = static_cast<uint32_t>(data.size());
  result.push_back(static_cast<uint8_t>((length >> 24) & 0xFF));
  result.push_back(static_cast<uint8_t>((length >> 16) & 0xFF));
  result.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>(length & 0xFF));

  // Data
  result.insert(result.end(), data.begin(), data.end());

  return result;
}

Result<std::pair<keepkey::MessageType, ByteVector>> KeepKeyWallet::decodeMessage(const ByteVector& data) {
  if (data.size() < 6) {
    return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::INVALID_RESPONSE);
  }

  // Message type
  uint16_t msg_type = (static_cast<uint16_t>(data[0]) << 8) | data[1];

  // Length
  uint32_t length = (static_cast<uint32_t>(data[2]) << 24) |
                    (static_cast<uint32_t>(data[3]) << 16) |
                    (static_cast<uint32_t>(data[4]) << 8) |
                    static_cast<uint32_t>(data[5]);

  if (data.size() < 6 + length) {
    return Result<std::pair<keepkey::MessageType, ByteVector>>::fail(Error::INVALID_RESPONSE);
  }

  ByteVector payload(data.begin() + 6, data.begin() + 6 + length);

  return Result<std::pair<keepkey::MessageType, ByteVector>>::success(
    std::make_pair(static_cast<keepkey::MessageType>(msg_type), std::move(payload))
  );
}

// =============================================================================
// Path Encoding
// =============================================================================

ByteVector KeepKeyWallet::encodePath(const std::string& path) {
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

ByteVector KeepKeyWallet::encodeBitcoinTxInput(const BitcoinTxInput& input, uint32_t index) {
  ByteVector result;

  // Path
  ByteVector path = encodePath(input.derivation_path);
  result.insert(result.end(), path.begin(), path.end());

  // Previous hash (32 bytes)
  result.insert(result.end(), input.prev_hash.begin(), input.prev_hash.end());

  // Previous index (4 bytes LE)
  result.push_back(static_cast<uint8_t>(input.prev_index & 0xFF));
  result.push_back(static_cast<uint8_t>((input.prev_index >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>((input.prev_index >> 16) & 0xFF));
  result.push_back(static_cast<uint8_t>((input.prev_index >> 24) & 0xFF));

  // Script type
  uint8_t script_type = 0;
  switch (input.script_type) {
    case BitcoinAddressType::P2PKH: script_type = 0; break;
    case BitcoinAddressType::P2SH: script_type = 1; break;
    case BitcoinAddressType::P2WPKH: script_type = 3; break;
    case BitcoinAddressType::P2WSH: script_type = 4; break;
    case BitcoinAddressType::P2TR: script_type = 5; break;
  }
  result.push_back(script_type);

  // Amount (8 bytes LE) - for SegWit
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((input.amount >> (i * 8)) & 0xFF));
  }

  // Sequence (4 bytes LE)
  result.push_back(static_cast<uint8_t>(input.sequence & 0xFF));
  result.push_back(static_cast<uint8_t>((input.sequence >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>((input.sequence >> 16) & 0xFF));
  result.push_back(static_cast<uint8_t>((input.sequence >> 24) & 0xFF));

  return result;
}

ByteVector KeepKeyWallet::encodeBitcoinTxOutput(const BitcoinTxOutput& output, uint32_t index) {
  ByteVector result;

  // Amount (8 bytes LE)
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<uint8_t>((output.amount >> (i * 8)) & 0xFF));
  }

  // Script type
  uint8_t script_type = 0;
  switch (output.script_type) {
    case BitcoinAddressType::P2PKH: script_type = 0; break;
    case BitcoinAddressType::P2SH: script_type = 1; break;
    case BitcoinAddressType::P2WPKH: script_type = 4; break;
    case BitcoinAddressType::P2WSH: script_type = 5; break;
    case BitcoinAddressType::P2TR: script_type = 6; break;
  }
  result.push_back(script_type);

  // If change output, include path
  if (!output.change_path.empty()) {
    ByteVector path = encodePath(output.change_path);
    result.insert(result.end(), path.begin(), path.end());
  } else {
    // Address
    result.push_back(static_cast<uint8_t>(output.address.size()));
    result.insert(result.end(), output.address.begin(), output.address.end());
  }

  return result;
}

ByteVector KeepKeyWallet::encodeEthereumTx(const EthereumTransaction& tx) {
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

  // To address (20 bytes or empty for contract creation)
  if (tx.to.empty()) {
    result.push_back(0);
  } else {
    result.push_back(20);
    // Convert hex string to bytes (skip 0x prefix)
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

  // Data length and initial chunk
  uint32_t data_len = static_cast<uint32_t>(tx.data.size());
  result.push_back(static_cast<uint8_t>(data_len & 0xFF));
  result.push_back(static_cast<uint8_t>((data_len >> 8) & 0xFF));
  result.push_back(static_cast<uint8_t>((data_len >> 16) & 0xFF));
  result.push_back(static_cast<uint8_t>((data_len >> 24) & 0xFF));

  // First chunk of data (up to 1024 bytes)
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

void KeepKeyWallet::parseFeatures(const ByteVector& data) {
  // Simple parsing - in real implementation would use protobuf
  // This is a simplified version that extracts key fields

  features_.device_type = DeviceType::KEEPKEY;
  features_.capabilities = DeviceCapability::BITCOIN_SIGNING |
                          DeviceCapability::ETHEREUM_SIGNING |
                          DeviceCapability::MESSAGE_SIGNING |
                          DeviceCapability::DISPLAY |
                          DeviceCapability::PIN_PROTECTION |
                          DeviceCapability::PASSPHRASE |
                          DeviceCapability::XPUB_EXPORT |
                          DeviceCapability::CURVE_SECP256K1;

  // Parse fields from data
  size_t offset = 0;

  while (offset < data.size()) {
    if (offset + 1 >= data.size()) break;

    uint8_t field_tag = data[offset++];
    uint8_t field_len = data[offset++];

    if (offset + field_len > data.size()) break;

    switch (field_tag) {
      case 1:  // vendor
        features_.manufacturer = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 2:  // major_version
        if (field_len >= 1) {
          features_.firmware_version = std::to_string(data[offset]);
        }
        break;

      case 9:  // device_id
        features_.device_id = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 10:  // pin_protection
        if (field_len >= 1) {
          features_.pin_protection = data[offset] != 0;
        }
        break;

      case 11:  // passphrase_protection
        if (field_len >= 1) {
          features_.passphrase_protection = data[offset] != 0;
        }
        break;

      case 13:  // label
        features_.label = std::string(data.begin() + offset, data.begin() + offset + field_len);
        break;

      case 14:  // initialized
        if (field_len >= 1) {
          features_.initialized = data[offset] != 0;
        }
        break;

      case 24:  // needs_pin_setup (inverted for needs_pin)
        if (field_len >= 1) {
          features_.needs_pin = features_.pin_protection && (data[offset] == 0);
        }
        break;

      default:
        break;
    }

    offset += field_len;
  }

  features_.needs_passphrase = features_.passphrase_protection;
}

// =============================================================================
// Factory Function
// =============================================================================

std::unique_ptr<KeepKeyWallet> createKeepKeyWallet() {
  return std::make_unique<KeepKeyWallet>();
}

} // namespace hw
} // namespace hd_wallet
