/**
 * @file transaction.h
 * @brief Base Transaction Interface
 *
 * Abstract transaction interface and common utilities for building and signing
 * transactions across different blockchain protocols.
 *
 * Features:
 * - Abstract Transaction base class
 * - Serialization helpers (VarInt, CompactSize)
 * - Hash calculation utilities
 * - Common transaction types and enums
 */

#ifndef HD_WALLET_TX_TRANSACTION_H
#define HD_WALLET_TX_TRANSACTION_H

#include "../config.h"
#include "../types.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hd_wallet {
namespace tx {

// =============================================================================
// Constants
// =============================================================================

/// Maximum transaction size (for sanity checks)
constexpr size_t MAX_TX_SIZE = 4 * 1024 * 1024;  // 4 MB

/// Maximum number of inputs/outputs
constexpr size_t MAX_TX_INPUTS = 10000;
constexpr size_t MAX_TX_OUTPUTS = 10000;

// =============================================================================
// Common Types
// =============================================================================

/**
 * Transaction status
 */
enum class TxStatus : uint8_t {
  /// Transaction not yet built
  UNBUILT = 0,

  /// Transaction built but not signed
  UNSIGNED = 1,

  /// Transaction partially signed (multisig)
  PARTIALLY_SIGNED = 2,

  /// Transaction fully signed
  SIGNED = 3,

  /// Transaction serialized and ready to broadcast
  FINALIZED = 4
};

/**
 * Hash type for signatures
 */
enum class SigHashType : uint8_t {
  /// Sign all inputs and outputs
  ALL = 0x01,

  /// Sign all inputs, no outputs
  NONE = 0x02,

  /// Sign all inputs, only the output with same index
  SINGLE = 0x03,

  /// Only sign own input (can be combined with above)
  ANYONECANPAY = 0x80,

  // Combined types
  ALL_ANYONECANPAY = 0x81,
  NONE_ANYONECANPAY = 0x82,
  SINGLE_ANYONECANPAY = 0x83
};

// =============================================================================
// Serialization Helpers
// =============================================================================

/**
 * Encode a variable-length integer (Bitcoin CompactSize)
 *
 * @param value Value to encode
 * @return Encoded bytes
 */
ByteVector encodeVarInt(uint64_t value);

/**
 * Decode a variable-length integer
 *
 * @param data Data to decode from
 * @param offset Starting offset (updated on success)
 * @return Decoded value, or nullopt on error
 */
std::optional<uint64_t> decodeVarInt(const ByteVector& data, size_t& offset);

/**
 * Encode a value as little-endian bytes
 */
template<typename T>
ByteVector encodeLE(T value) {
  ByteVector result(sizeof(T));
  for (size_t i = 0; i < sizeof(T); ++i) {
    result[i] = static_cast<uint8_t>(value >> (i * 8));
  }
  return result;
}

/**
 * Decode a little-endian value
 */
template<typename T>
std::optional<T> decodeLE(const ByteVector& data, size_t& offset) {
  if (offset + sizeof(T) > data.size()) {
    return std::nullopt;
  }
  T value = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    value |= static_cast<T>(data[offset + i]) << (i * 8);
  }
  offset += sizeof(T);
  return value;
}

/**
 * Encode a value as big-endian bytes
 */
template<typename T>
ByteVector encodeBE(T value) {
  ByteVector result(sizeof(T));
  for (size_t i = 0; i < sizeof(T); ++i) {
    result[sizeof(T) - 1 - i] = static_cast<uint8_t>(value >> (i * 8));
  }
  return result;
}

/**
 * Decode a big-endian value
 */
template<typename T>
std::optional<T> decodeBE(const ByteVector& data, size_t& offset) {
  if (offset + sizeof(T) > data.size()) {
    return std::nullopt;
  }
  T value = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    value |= static_cast<T>(data[offset + i]) << ((sizeof(T) - 1 - i) * 8);
  }
  offset += sizeof(T);
  return value;
}

/**
 * Append bytes to a vector
 */
inline void appendBytes(ByteVector& dest, const ByteVector& src) {
  dest.insert(dest.end(), src.begin(), src.end());
}

/**
 * Append bytes from an array to a vector
 */
template<size_t N>
inline void appendBytes(ByteVector& dest, const std::array<uint8_t, N>& src) {
  dest.insert(dest.end(), src.begin(), src.end());
}

/**
 * Append a single byte
 */
inline void appendByte(ByteVector& dest, uint8_t byte) {
  dest.push_back(byte);
}

/**
 * Reverse bytes (for hash display)
 */
inline ByteVector reverseBytes(const ByteVector& data) {
  return ByteVector(data.rbegin(), data.rend());
}

template<size_t N>
inline std::array<uint8_t, N> reverseBytes(const std::array<uint8_t, N>& data) {
  std::array<uint8_t, N> result;
  std::reverse_copy(data.begin(), data.end(), result.begin());
  return result;
}

// =============================================================================
// Hash Utilities
// =============================================================================

/**
 * Calculate SHA-256 hash
 * @param data Data to hash
 * @return 32-byte hash
 */
Bytes32 sha256(const ByteVector& data);
Bytes32 sha256(const uint8_t* data, size_t length);

/**
 * Calculate double SHA-256 hash (Bitcoin standard)
 * @param data Data to hash
 * @return 32-byte hash
 */
Bytes32 doubleSha256(const ByteVector& data);
Bytes32 doubleSha256(const uint8_t* data, size_t length);

/**
 * Calculate HASH160 (RIPEMD-160(SHA-256(x)))
 * @param data Data to hash
 * @return 20-byte hash
 */
std::array<uint8_t, 20> hash160(const ByteVector& data);
std::array<uint8_t, 20> hash160(const uint8_t* data, size_t length);

/**
 * Calculate Keccak-256 hash (Ethereum)
 * @param data Data to hash
 * @return 32-byte hash
 */
Bytes32 keccak256(const ByteVector& data);
Bytes32 keccak256(const uint8_t* data, size_t length);

// =============================================================================
// Abstract Transaction Base Class
// =============================================================================

/**
 * Abstract base class for blockchain transactions
 *
 * Provides common interface for building, signing, and serializing
 * transactions across different blockchain protocols.
 */
class Transaction {
public:
  virtual ~Transaction() = default;

  // ----- Status -----

  /**
   * Get transaction status
   */
  virtual TxStatus status() const = 0;

  /**
   * Check if transaction is signed
   */
  bool isSigned() const {
    return status() == TxStatus::SIGNED || status() == TxStatus::FINALIZED;
  }

  /**
   * Check if transaction is ready to broadcast
   */
  bool isFinalized() const {
    return status() == TxStatus::FINALIZED;
  }

  // ----- Hashing -----

  /**
   * Calculate transaction hash/ID
   * @return 32-byte transaction hash
   */
  virtual Result<Bytes32> hash() const = 0;

  /**
   * Get transaction ID as hex string
   * @return Transaction ID (format depends on chain)
   */
  virtual Result<std::string> txid() const = 0;

  // ----- Size -----

  /**
   * Get serialized transaction size in bytes
   */
  virtual size_t size() const = 0;

  /**
   * Get virtual size (for fee calculation)
   * For non-SegWit transactions, this equals size()
   */
  virtual size_t virtualSize() const {
    return size();
  }

  /**
   * Get weight (for SegWit transactions)
   */
  virtual size_t weight() const {
    return size() * 4;
  }

  // ----- Serialization -----

  /**
   * Serialize transaction to bytes
   * @return Serialized transaction
   */
  virtual Result<ByteVector> serialize() const = 0;

  /**
   * Serialize transaction to hex string
   * @return Hex-encoded transaction
   */
  virtual Result<std::string> serializeHex() const;

  // ----- Signing -----

  /**
   * Sign the transaction
   * @param privateKey 32-byte private key
   * @param inputIndex Index of input to sign (-1 for all)
   * @return Error code
   */
  virtual Error sign(const Bytes32& privateKey, int inputIndex = -1) = 0;

  /**
   * Verify transaction signature(s)
   * @return true if all signatures are valid
   */
  virtual bool verify() const = 0;

  // ----- Validation -----

  /**
   * Validate transaction structure and values
   * @return Error::OK if valid, specific error otherwise
   */
  virtual Error validate() const = 0;

  // ----- Cloning -----

  /**
   * Create a deep copy of the transaction
   */
  virtual std::unique_ptr<Transaction> clone() const = 0;

protected:
  Transaction() = default;
  Transaction(const Transaction&) = default;
  Transaction& operator=(const Transaction&) = default;
  Transaction(Transaction&&) = default;
  Transaction& operator=(Transaction&&) = default;
};

// =============================================================================
// Hex Encoding Utilities
// =============================================================================

/**
 * Convert bytes to hex string
 */
std::string bytesToHex(const ByteVector& data);
std::string bytesToHex(const uint8_t* data, size_t length);

template<size_t N>
std::string bytesToHex(const std::array<uint8_t, N>& data) {
  return bytesToHex(data.data(), N);
}

/**
 * Convert hex string to bytes
 */
Result<ByteVector> hexToBytes(const std::string& hex);

} // namespace tx
} // namespace hd_wallet

#endif // HD_WALLET_TX_TRANSACTION_H
