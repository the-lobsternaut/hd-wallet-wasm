/**
 * @file transaction.cpp
 * @brief Base Transaction Implementation
 *
 * Implementation of common transaction utilities, serialization helpers,
 * and hash calculation functions.
 */

#include "hd_wallet/tx/transaction.h"
#include "hd_wallet/config.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/sha.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/keccak.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#endif

namespace hd_wallet {
namespace tx {

// =============================================================================
// VarInt Encoding/Decoding (Bitcoin CompactSize)
// =============================================================================

ByteVector encodeVarInt(uint64_t value) {
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

std::optional<uint64_t> decodeVarInt(const ByteVector& data, size_t& offset) {
  if (offset >= data.size()) {
    return std::nullopt;
  }

  uint8_t first = data[offset++];

  if (first < 0xFD) {
    return static_cast<uint64_t>(first);
  }

  if (first == 0xFD) {
    if (offset + 2 > data.size()) {
      return std::nullopt;
    }
    uint64_t value = static_cast<uint64_t>(data[offset]) |
                     (static_cast<uint64_t>(data[offset + 1]) << 8);
    offset += 2;
    return value;
  }

  if (first == 0xFE) {
    if (offset + 4 > data.size()) {
      return std::nullopt;
    }
    uint64_t value = static_cast<uint64_t>(data[offset]) |
                     (static_cast<uint64_t>(data[offset + 1]) << 8) |
                     (static_cast<uint64_t>(data[offset + 2]) << 16) |
                     (static_cast<uint64_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
  }

  // first == 0xFF
  if (offset + 8 > data.size()) {
    return std::nullopt;
  }

  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<uint64_t>(data[offset + i]) << (i * 8);
  }
  offset += 8;
  return value;
}

// =============================================================================
// Hash Functions
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

Bytes32 sha256(const ByteVector& data) {
  return sha256(data.data(), data.size());
}

Bytes32 sha256(const uint8_t* data, size_t length) {
  Bytes32 hash;
  CryptoPP::SHA256 hasher;
  hasher.CalculateDigest(hash.data(), data, length);
  return hash;
}

Bytes32 doubleSha256(const ByteVector& data) {
  return doubleSha256(data.data(), data.size());
}

Bytes32 doubleSha256(const uint8_t* data, size_t length) {
  Bytes32 hash1;
  CryptoPP::SHA256 hasher;
  hasher.CalculateDigest(hash1.data(), data, length);

  Bytes32 hash2;
  hasher.CalculateDigest(hash2.data(), hash1.data(), hash1.size());

  return hash2;
}

std::array<uint8_t, 20> hash160(const ByteVector& data) {
  return hash160(data.data(), data.size());
}

std::array<uint8_t, 20> hash160(const uint8_t* data, size_t length) {
  // SHA-256 first
  Bytes32 sha256Hash;
  CryptoPP::SHA256 sha256Hasher;
  sha256Hasher.CalculateDigest(sha256Hash.data(), data, length);

  // Then RIPEMD-160
  std::array<uint8_t, 20> hash;
  CryptoPP::RIPEMD160 ripemd160Hasher;
  ripemd160Hasher.CalculateDigest(hash.data(), sha256Hash.data(), sha256Hash.size());

  return hash;
}

Bytes32 keccak256(const ByteVector& data) {
  return keccak256(data.data(), data.size());
}

Bytes32 keccak256(const uint8_t* data, size_t length) {
  Bytes32 hash;
  CryptoPP::Keccak_256 hasher;
  hasher.CalculateDigest(hash.data(), data, length);
  return hash;
}

#else
// Fallback implementations if Crypto++ is not available
// These should be replaced with actual implementations

Bytes32 sha256(const ByteVector& data) {
  return sha256(data.data(), data.size());
}

Bytes32 sha256(const uint8_t* data, size_t length) {
  (void)data;
  (void)length;
  throw std::runtime_error("SHA-256 not available without Crypto++");
}

Bytes32 doubleSha256(const ByteVector& data) {
  return doubleSha256(data.data(), data.size());
}

Bytes32 doubleSha256(const uint8_t* data, size_t length) {
  (void)data;
  (void)length;
  throw std::runtime_error("Double SHA-256 not available without Crypto++");
}

std::array<uint8_t, 20> hash160(const ByteVector& data) {
  return hash160(data.data(), data.size());
}

std::array<uint8_t, 20> hash160(const uint8_t* data, size_t length) {
  (void)data;
  (void)length;
  throw std::runtime_error("HASH160 not available without Crypto++");
}

Bytes32 keccak256(const ByteVector& data) {
  return keccak256(data.data(), data.size());
}

Bytes32 keccak256(const uint8_t* data, size_t length) {
  (void)data;
  (void)length;
  throw std::runtime_error("Keccak-256 not available without Crypto++");
}

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Hex Encoding/Decoding
// =============================================================================

static const char HEX_CHARS[] = "0123456789abcdef";

std::string bytesToHex(const ByteVector& data) {
  return bytesToHex(data.data(), data.size());
}

std::string bytesToHex(const uint8_t* data, size_t length) {
  std::string result;
  result.reserve(length * 2);

  for (size_t i = 0; i < length; ++i) {
    result.push_back(HEX_CHARS[(data[i] >> 4) & 0x0F]);
    result.push_back(HEX_CHARS[data[i] & 0x0F]);
  }

  return result;
}

static int hexCharToInt(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

Result<ByteVector> hexToBytes(const std::string& hex) {
  std::string input = hex;

  // Remove 0x prefix if present
  if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
    input = input.substr(2);
  }

  // Must be even length
  if (input.size() % 2 != 0) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  ByteVector result;
  result.reserve(input.size() / 2);

  for (size_t i = 0; i < input.size(); i += 2) {
    int high = hexCharToInt(input[i]);
    int low = hexCharToInt(input[i + 1]);

    if (high < 0 || low < 0) {
      return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }

    result.push_back(static_cast<uint8_t>((high << 4) | low));
  }

  return Result<ByteVector>::success(std::move(result));
}

// =============================================================================
// Transaction Base Class
// =============================================================================

Result<std::string> Transaction::serializeHex() const {
  auto serialized = serialize();
  if (!serialized.ok()) {
    return Result<std::string>::fail(serialized.error);
  }
  return Result<std::string>::success(bytesToHex(serialized.value));
}

} // namespace tx
} // namespace hd_wallet
