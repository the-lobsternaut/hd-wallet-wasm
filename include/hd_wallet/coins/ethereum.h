/**
 * @file ethereum.h
 * @brief Ethereum Support
 *
 * Provides Ethereum address generation, validation, and message signing.
 *
 * Features:
 * - Address generation from public key using Keccak256
 * - EIP-55 checksum addresses
 * - EIP-191 personal message signing
 * - EIP-712 typed data signing (basic support)
 * - Signature verification and recovery
 */

#ifndef HD_WALLET_ETHEREUM_H
#define HD_WALLET_ETHEREUM_H

#include "coin.h"

#include <map>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Ethereum Address Generation
// =============================================================================

/**
 * Generate Ethereum address from public key
 *
 * Algorithm:
 * 1. If compressed, decompress to 65 bytes
 * 2. Take last 64 bytes (remove 0x04 prefix if present)
 * 3. Keccak256 hash the 64 bytes
 * 4. Take last 20 bytes of hash
 * 5. Hex encode with 0x prefix
 * 6. Apply EIP-55 checksum
 *
 * @param public_key Compressed (33-byte) or uncompressed (64/65-byte) public key
 * @return 42-character checksummed address (0x...)
 */
Result<std::string> ethereumAddress(const ByteVector& public_key);

/**
 * Generate address from compressed public key
 */
Result<std::string> ethereumAddress(const Bytes33& public_key);

/**
 * Generate address from uncompressed public key (with 04 prefix)
 */
Result<std::string> ethereumAddress(const Bytes65& public_key);

// =============================================================================
// EIP-55 Checksum
// =============================================================================

/**
 * Apply EIP-55 checksum to address
 *
 * The checksum is mixed-case encoding:
 * - If the ith bit of the hash of the lowercase address is 1, uppercase the character
 * - Otherwise, lowercase it
 *
 * @param address Lowercase address (with or without 0x prefix)
 * @return Checksummed address with 0x prefix
 */
std::string applyEIP55Checksum(const std::string& address);

/**
 * Verify EIP-55 checksum
 * @param address Address to verify (must have 0x prefix)
 * @return true if checksum is valid
 */
bool verifyEIP55Checksum(const std::string& address);

/**
 * Normalize Ethereum address (lowercase with 0x prefix)
 */
std::string normalizeEthereumAddress(const std::string& address);

// =============================================================================
// Ethereum Address Validation
// =============================================================================

/**
 * Validate Ethereum address
 *
 * Checks:
 * - Length is 42 characters (with 0x prefix) or 40 (without)
 * - Starts with 0x (if 42 chars)
 * - All characters are valid hex
 * - If mixed-case, validates EIP-55 checksum
 *
 * @param address Address to validate
 * @return Error::OK if valid
 */
Error validateEthereumAddress(const std::string& address);

/**
 * Check if address is a contract (zero address or has code)
 * Note: This only checks for special addresses locally,
 * actual contract checking requires network access
 */
bool isZeroAddress(const std::string& address);

// =============================================================================
// EIP-191: Personal Message Signing
// =============================================================================

/**
 * Hash message according to EIP-191 personal_sign
 *
 * Format: "\x19Ethereum Signed Message:\n" + len(message) + message
 *
 * @param message Message to hash
 * @return 32-byte Keccak256 hash
 */
Bytes32 hashEIP191Message(const std::string& message);
Bytes32 hashEIP191Message(const ByteVector& message);

/**
 * Sign a message using EIP-191 personal_sign format
 *
 * @param message Message to sign
 * @param private_key 32-byte private key
 * @return 65-byte signature (r[32] || s[32] || v[1])
 */
Result<ByteVector> signEIP191Message(const std::string& message, const Bytes32& private_key);
Result<ByteVector> signEIP191Message(const ByteVector& message, const Bytes32& private_key);

/**
 * Verify an EIP-191 signed message
 *
 * @param message Original message
 * @param signature 65-byte signature
 * @param address Expected signer address
 * @return true if signature is valid
 */
Result<bool> verifyEIP191Message(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
);

/**
 * Recover signer address from EIP-191 signed message
 *
 * @param message Original message
 * @param signature 65-byte signature
 * @return Recovered address (checksummed)
 */
Result<std::string> recoverEIP191Signer(const std::string& message, const ByteVector& signature);

// =============================================================================
// EIP-712: Typed Data Signing
// =============================================================================

/**
 * EIP-712 type definition
 */
struct EIP712Type {
  std::string name;
  std::string type;
};

/**
 * EIP-712 domain separator
 */
struct EIP712Domain {
  std::string name;
  std::string version;
  uint64_t chainId;
  std::string verifyingContract;
  std::string salt;  // Optional, hex-encoded 32 bytes

  /// Compute domain separator hash
  Bytes32 hash() const;

  /// Get domain type hash
  static Bytes32 typeHash();
};

/**
 * Compute EIP-712 struct hash
 *
 * @param type_hash Hash of the type string (e.g., "Mail(address from,address to,string contents)")
 * @param encoded_data Encoded struct data (concatenated hashes of members)
 * @return Keccak256 hash
 */
Bytes32 hashEIP712Struct(const Bytes32& type_hash, const ByteVector& encoded_data);

/**
 * Compute EIP-712 type hash
 *
 * @param type_string Type string (e.g., "Mail(address from,address to,string contents)")
 * @return Keccak256 hash
 */
Bytes32 hashEIP712Type(const std::string& type_string);

/**
 * Encode EIP-712 typed data for signing
 *
 * Format: "\x19\x01" + domainSeparator + hashStruct(message)
 *
 * @param domain Domain separator
 * @param struct_hash Hash of the message struct
 * @return 32-byte hash ready for signing
 */
Bytes32 encodeEIP712(const EIP712Domain& domain, const Bytes32& struct_hash);

/**
 * Sign EIP-712 typed data
 *
 * @param domain Domain separator
 * @param struct_hash Hash of the message struct
 * @param private_key 32-byte private key
 * @return 65-byte signature
 */
Result<ByteVector> signEIP712(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const Bytes32& private_key
);

/**
 * Verify EIP-712 typed data signature
 *
 * @param domain Domain separator
 * @param struct_hash Hash of the message struct
 * @param signature 65-byte signature
 * @param address Expected signer address
 * @return true if signature is valid
 */
Result<bool> verifyEIP712(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const ByteVector& signature,
  const std::string& address
);

/**
 * Recover signer from EIP-712 signature
 */
Result<std::string> recoverEIP712Signer(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const ByteVector& signature
);

// =============================================================================
// Ethereum Signature Utilities
// =============================================================================

/**
 * Convert signature v value between different formats
 *
 * Ethereum uses different v values:
 * - 0, 1: Raw recovery ID
 * - 27, 28: Original Ethereum format
 * - 35 + chainId * 2 + recovery: EIP-155 format
 */
uint8_t normalizeV(uint8_t v, uint64_t chainId = 0);

/**
 * Encode signature for Ethereum transactions
 * @param signature 65-byte signature
 * @param chainId Chain ID for EIP-155
 * @return Encoded v, r, s values
 */
struct EncodedSignature {
  Bytes32 r;
  Bytes32 s;
  uint64_t v;
};

EncodedSignature encodeSignature(const ByteVector& signature, uint64_t chainId = 0);

/**
 * Sign a raw hash (Keccak256)
 * @param hash 32-byte hash
 * @param private_key 32-byte private key
 * @return 65-byte signature
 */
Result<ByteVector> signHash(const Bytes32& hash, const Bytes32& private_key);

/**
 * Recover address from signature on raw hash
 * @param hash 32-byte hash
 * @param signature 65-byte signature
 * @return Recovered address
 */
Result<std::string> recoverAddress(const Bytes32& hash, const ByteVector& signature);

// =============================================================================
// Ethereum Coin Implementation
// =============================================================================

/**
 * Ethereum coin implementation
 */
class Ethereum : public Coin {
public:
  explicit Ethereum(Network network = Network::MAINNET);

  // ----- Identification -----
  CoinType coinType() const override { return CoinType::ETHEREUM; }
  const char* name() const override { return "Ethereum"; }
  const char* symbol() const override { return "ETH"; }
  Curve curve() const override { return Curve::SECP256K1; }

  // ----- Network -----
  Network network() const override { return network_; }
  void setNetwork(Network net) override { network_ = net; }

  /// Get chain ID
  uint64_t chainId() const { return chain_id_; }
  void setChainId(uint64_t id) { chain_id_ = id; }

  // ----- Address Generation -----
  Result<std::string> addressFromPublicKey(const Bytes33& public_key) const override;
  Result<std::string> addressFromPublicKeyUncompressed(const Bytes65& public_key) const override;

  // ----- Address Validation -----
  Error validateAddress(const std::string& address) const override;
  Result<DecodedAddress> decodeAddress(const std::string& address) const override;

  // ----- Message Signing (EIP-191) -----
  Result<ByteVector> signMessage(const ByteVector& message, const Bytes32& private_key) const override;
  Result<bool> verifyMessage(
    const ByteVector& message,
    const ByteVector& signature,
    const ByteVector& public_key
  ) const override;

  /// Verify against address instead of public key
  Result<bool> verifyMessageByAddress(
    const ByteVector& message,
    const ByteVector& signature,
    const std::string& address
  ) const;

  // ----- EIP-712 Signing -----
  Result<ByteVector> signTypedData(
    const EIP712Domain& domain,
    const Bytes32& struct_hash,
    const Bytes32& private_key
  ) const;

  // ----- Derivation Path -----
  std::string getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const override;

private:
  Network network_;
  uint64_t chain_id_;
};

// =============================================================================
// Chain IDs
// =============================================================================

namespace chain_ids {
  constexpr uint64_t MAINNET = 1;
  constexpr uint64_t GOERLI = 5;
  constexpr uint64_t SEPOLIA = 11155111;
  constexpr uint64_t POLYGON = 137;
  constexpr uint64_t POLYGON_MUMBAI = 80001;
  constexpr uint64_t ARBITRUM = 42161;
  constexpr uint64_t OPTIMISM = 10;
  constexpr uint64_t BSC = 56;
  constexpr uint64_t AVALANCHE = 43114;
  constexpr uint64_t FANTOM = 250;
}

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_validate_address(const char* address);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_checksum_address(
  const char* address,
  char* checksummed_out,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_verify_checksum(const char* address);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const char* address
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_recover_address(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_hash_message(
  const uint8_t* message,
  size_t message_len,
  uint8_t* hash_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_sign_typed_data(
  const char* domain_name,
  const char* domain_version,
  uint64_t chain_id,
  const char* verifying_contract,
  const uint8_t* struct_hash,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_ETHEREUM_H
