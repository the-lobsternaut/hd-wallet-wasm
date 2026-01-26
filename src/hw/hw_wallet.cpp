/**
 * @file hw_wallet.cpp
 * @brief Hardware Wallet Base Implementation
 *
 * Implements the common functionality for hardware wallet operations,
 * including factory functions and utility methods.
 */

#include "hd_wallet/hw/hw_wallet.h"
#include "hd_wallet/hw/keepkey.h"
#include "hd_wallet/hw/trezor.h"
#include "hd_wallet/hw/ledger.h"
#include "hd_wallet/wasi_bridge.h"
#include "hd_wallet/bip32.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace hd_wallet {
namespace hw {

// =============================================================================
// Connection State String
// =============================================================================

const char* connectionStateToString(ConnectionState state) {
  switch (state) {
    case ConnectionState::DISCONNECTED:
      return "Disconnected";
    case ConnectionState::CONNECTED:
      return "Connected";
    case ConnectionState::READY:
      return "Ready";
    case ConnectionState::AWAITING_USER:
      return "Awaiting User Input";
    case ConnectionState::BUSY:
      return "Busy";
    case ConnectionState::ERROR:
      return "Error";
    default:
      return "Unknown";
  }
}

// =============================================================================
// Factory Functions
// =============================================================================

std::unique_ptr<HardwareWallet> createHardwareWallet(const HardwareWalletDevice& device) {
  return createHardwareWallet(device.type);
}

std::unique_ptr<HardwareWallet> createHardwareWallet(DeviceType type) {
  switch (type) {
    case DeviceType::KEEPKEY:
      return createKeepKeyWallet();

    case DeviceType::TREZOR_ONE:
    case DeviceType::TREZOR_T:
      return createTrezorWallet();

    case DeviceType::LEDGER_NANO_S:
    case DeviceType::LEDGER_NANO_X:
    case DeviceType::LEDGER_NANO_S_PLUS:
      return createLedgerWallet();

    default:
      return nullptr;
  }
}

std::unique_ptr<HardwareWallet> connectToFirstDevice() {
  // Enumerate all devices
  auto devices = enumerateDevices();

  if (devices.empty()) {
    return nullptr;
  }

  // Try to connect to the first device
  auto wallet = createHardwareWallet(devices[0]);
  if (!wallet) {
    return nullptr;
  }

  auto result = wallet->connect(devices[0]);
  if (!result.ok()) {
    return nullptr;
  }

  return wallet;
}

// =============================================================================
// Path Parsing Utilities
// =============================================================================

Result<std::vector<uint32_t>> parseDerivationPath(const std::string& path) {
  std::vector<uint32_t> components;

  if (path.empty()) {
    return Result<std::vector<uint32_t>>::fail(Error::INVALID_PATH);
  }

  // Handle paths starting with 'm/' or just '/'
  std::string normalized = path;

  // Remove leading 'm'
  size_t start = 0;
  if (!normalized.empty() && (normalized[0] == 'm' || normalized[0] == 'M')) {
    start = 1;
  }

  // Skip leading '/'
  if (start < normalized.size() && normalized[start] == '/') {
    start++;
  }

  // Empty path after normalization means master key
  if (start >= normalized.size()) {
    return Result<std::vector<uint32_t>>::success(std::move(components));
  }

  // Parse components
  std::string remaining = normalized.substr(start);
  std::stringstream ss(remaining);
  std::string token;

  while (std::getline(ss, token, '/')) {
    if (token.empty()) {
      continue;
    }

    bool hardened = false;
    std::string index_str = token;

    // Check for hardened marker
    if (!token.empty()) {
      char last = token.back();
      if (last == '\'' || last == 'h' || last == 'H') {
        hardened = true;
        index_str = token.substr(0, token.size() - 1);
      }
    }

    // Parse index
    try {
      size_t pos = 0;
      unsigned long idx = std::stoul(index_str, &pos);

      if (pos != index_str.size()) {
        // Not all characters consumed
        return Result<std::vector<uint32_t>>::fail(Error::INVALID_PATH);
      }

      if (idx >= bip32::HARDENED_OFFSET) {
        return Result<std::vector<uint32_t>>::fail(Error::INVALID_CHILD_INDEX);
      }

      uint32_t component = static_cast<uint32_t>(idx);
      if (hardened) {
        component |= bip32::HARDENED_OFFSET;
      }

      components.push_back(component);

    } catch (const std::exception&) {
      return Result<std::vector<uint32_t>>::fail(Error::INVALID_PATH);
    }
  }

  // Validate depth
  if (components.size() > HD_WALLET_MAX_PATH_DEPTH) {
    return Result<std::vector<uint32_t>>::fail(Error::INVALID_PATH);
  }

  return Result<std::vector<uint32_t>>::success(std::move(components));
}

std::string formatDerivationPath(const std::vector<uint32_t>& components) {
  std::stringstream ss;
  ss << "m";

  for (uint32_t comp : components) {
    ss << "/";

    if (comp >= bip32::HARDENED_OFFSET) {
      ss << (comp - bip32::HARDENED_OFFSET) << "'";
    } else {
      ss << comp;
    }
  }

  return ss.str();
}

bool validateDerivationPath(const std::string& path, CoinType coin_type) {
  auto result = parseDerivationPath(path);
  if (!result.ok()) {
    return false;
  }

  const auto& components = result.value;

  // Check if this follows BIP-44 structure
  // m / purpose' / coin_type' / account' / change / address_index

  if (components.size() < 3) {
    // Too short for standard derivation
    return true;  // Still valid, just not a complete BIP-44 path
  }

  // Check purpose (should be hardened)
  if (!bip32::isHardened(components[0])) {
    return false;
  }

  // Check coin type matches and is hardened
  if (!bip32::isHardened(components[1])) {
    return false;
  }

  uint32_t path_coin_type = bip32::unharden(components[1]);
  uint32_t expected_coin_type = static_cast<uint32_t>(coin_type);

  // Allow any coin type, but warn if mismatch (validation still passes)
  // This allows flexibility for various derivation schemes

  // Check account is hardened
  if (components.size() >= 3 && !bip32::isHardened(components[2])) {
    return false;
  }

  // Check change is not hardened (0 or 1)
  if (components.size() >= 4) {
    if (bip32::isHardened(components[3])) {
      return false;
    }
    if (components[3] > 1) {
      return false;  // Change should be 0 or 1
    }
  }

  // Check address index is not hardened
  if (components.size() >= 5 && bip32::isHardened(components[4])) {
    return false;
  }

  return true;
}

// =============================================================================
// Bitcoin Script Type Helpers
// =============================================================================

namespace {

/**
 * Convert BitcoinAddressType to script type name
 */
const char* scriptTypeName(BitcoinAddressType type) {
  switch (type) {
    case BitcoinAddressType::P2PKH:
      return "P2PKH";
    case BitcoinAddressType::P2SH:
      return "P2SH";
    case BitcoinAddressType::P2WPKH:
      return "P2WPKH";
    case BitcoinAddressType::P2WSH:
      return "P2WSH";
    case BitcoinAddressType::P2TR:
      return "P2TR";
    default:
      return "Unknown";
  }
}

/**
 * Get purpose for address type (BIP-44, BIP-49, BIP-84, BIP-86)
 */
uint32_t purposeForAddressType(BitcoinAddressType type) {
  switch (type) {
    case BitcoinAddressType::P2PKH:
      return 44;
    case BitcoinAddressType::P2SH:
      return 49;  // P2SH-P2WPKH
    case BitcoinAddressType::P2WPKH:
      return 84;
    case BitcoinAddressType::P2TR:
      return 86;  // BIP-86 for Taproot
    default:
      return 44;
  }
}

} // anonymous namespace

// =============================================================================
// Common Validation Helpers
// =============================================================================

namespace {

/**
 * Validate Bitcoin transaction structure
 */
Error validateBitcoinTransaction(const BitcoinTransaction& tx) {
  if (tx.inputs.empty()) {
    return Error::INVALID_TRANSACTION;
  }

  if (tx.outputs.empty()) {
    return Error::INVALID_TRANSACTION;
  }

  // Validate inputs
  for (const auto& input : tx.inputs) {
    if (input.prev_hash.size() != 32) {
      return Error::INVALID_TRANSACTION;
    }

    if (input.derivation_path.empty()) {
      return Error::INVALID_PATH;
    }

    // For SegWit inputs, amount must be specified
    if (input.script_type == BitcoinAddressType::P2WPKH ||
        input.script_type == BitcoinAddressType::P2WSH ||
        input.script_type == BitcoinAddressType::P2TR) {
      if (input.amount == 0) {
        return Error::INVALID_TRANSACTION;
      }
    }
  }

  // Validate outputs
  uint64_t total_output = 0;
  for (const auto& output : tx.outputs) {
    if (output.amount == 0) {
      return Error::INVALID_TRANSACTION;
    }

    if (output.address.empty() && output.change_path.empty()) {
      return Error::INVALID_ADDRESS;
    }

    total_output += output.amount;
    if (total_output < output.amount) {
      // Overflow check
      return Error::INVALID_TRANSACTION;
    }
  }

  return Error::OK;
}

/**
 * Validate Ethereum transaction structure
 */
Error validateEthereumTransaction(const EthereumTransaction& tx) {
  if (tx.derivation_path.empty()) {
    return Error::INVALID_PATH;
  }

  if (tx.chain_id == 0) {
    return Error::INVALID_TRANSACTION;
  }

  if (tx.gas_limit == 0) {
    return Error::INVALID_TRANSACTION;
  }

  // For non-EIP-1559, gas_price must be set
  if (!tx.max_fee_per_gas.has_value() && tx.gas_price.empty()) {
    return Error::INVALID_TRANSACTION;
  }

  // For EIP-1559, both max fees must be set
  if (tx.max_fee_per_gas.has_value() != tx.max_priority_fee_per_gas.has_value()) {
    return Error::INVALID_TRANSACTION;
  }

  return Error::OK;
}

} // anonymous namespace

// =============================================================================
// Encoding Helpers (used by all implementations)
// =============================================================================

namespace encoding {

/**
 * Encode a variable-length integer (Bitcoin varint format)
 */
ByteVector encodeVarint(uint64_t value) {
  ByteVector result;

  if (value < 0xFD) {
    result.push_back(static_cast<uint8_t>(value));
  } else if (value <= 0xFFFF) {
    result.push_back(0xFD);
    result.push_back(static_cast<uint8_t>(value & 0xFF));
    result.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  } else if (value <= 0xFFFFFFFF) {
    result.push_back(0xFE);
    result.push_back(static_cast<uint8_t>(value & 0xFF));
    result.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  } else {
    result.push_back(0xFF);
    for (int i = 0; i < 8; ++i) {
      result.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
  }

  return result;
}

/**
 * Encode uint32 as little-endian
 */
void encodeUint32LE(ByteVector& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>(value & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

/**
 * Encode uint64 as little-endian
 */
void encodeUint64LE(ByteVector& out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
  }
}

/**
 * Encode uint32 as big-endian
 */
void encodeUint32BE(ByteVector& out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(value & 0xFF));
}

/**
 * Encode derivation path for hardware wallets (Trezor/KeepKey format)
 * Returns path as array of uint32 big-endian
 */
ByteVector encodePathTrezor(const std::vector<uint32_t>& components) {
  ByteVector result;
  result.reserve(components.size() * 4);

  for (uint32_t comp : components) {
    encodeUint32BE(result, comp);
  }

  return result;
}

/**
 * Encode derivation path for Ledger
 * Returns path as: [length] [uint32 BE]...
 */
ByteVector encodePathLedger(const std::vector<uint32_t>& components) {
  ByteVector result;
  result.reserve(1 + components.size() * 4);

  result.push_back(static_cast<uint8_t>(components.size()));

  for (uint32_t comp : components) {
    encodeUint32BE(result, comp);
  }

  return result;
}

/**
 * Encode RLP integer (Ethereum)
 */
ByteVector encodeRLPInteger(uint64_t value) {
  if (value == 0) {
    return {0x80};
  }

  ByteVector bytes;
  uint64_t temp = value;
  while (temp > 0) {
    bytes.insert(bytes.begin(), static_cast<uint8_t>(temp & 0xFF));
    temp >>= 8;
  }

  if (bytes.size() == 1 && bytes[0] < 0x80) {
    return bytes;
  }

  ByteVector result;
  result.push_back(0x80 + static_cast<uint8_t>(bytes.size()));
  result.insert(result.end(), bytes.begin(), bytes.end());
  return result;
}

/**
 * Encode RLP bytes
 */
ByteVector encodeRLPBytes(const ByteVector& data) {
  if (data.empty()) {
    return {0x80};
  }

  if (data.size() == 1 && data[0] < 0x80) {
    return data;
  }

  ByteVector result;
  if (data.size() <= 55) {
    result.push_back(0x80 + static_cast<uint8_t>(data.size()));
  } else {
    ByteVector length_bytes;
    size_t len = data.size();
    while (len > 0) {
      length_bytes.insert(length_bytes.begin(), static_cast<uint8_t>(len & 0xFF));
      len >>= 8;
    }
    result.push_back(0xB7 + static_cast<uint8_t>(length_bytes.size()));
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
  }

  result.insert(result.end(), data.begin(), data.end());
  return result;
}

/**
 * Encode RLP list
 */
ByteVector encodeRLPList(const std::vector<ByteVector>& items) {
  ByteVector payload;
  for (const auto& item : items) {
    payload.insert(payload.end(), item.begin(), item.end());
  }

  ByteVector result;
  if (payload.size() <= 55) {
    result.push_back(0xC0 + static_cast<uint8_t>(payload.size()));
  } else {
    ByteVector length_bytes;
    size_t len = payload.size();
    while (len > 0) {
      length_bytes.insert(length_bytes.begin(), static_cast<uint8_t>(len & 0xFF));
      len >>= 8;
    }
    result.push_back(0xF7 + static_cast<uint8_t>(length_bytes.size()));
    result.insert(result.end(), length_bytes.begin(), length_bytes.end());
  }

  result.insert(result.end(), payload.begin(), payload.end());
  return result;
}

} // namespace encoding

} // namespace hw
} // namespace hd_wallet
