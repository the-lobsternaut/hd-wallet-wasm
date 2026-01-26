/**
 * @file polkadot.h
 * @brief Polkadot/Substrate Support
 *
 * Provides Polkadot and Substrate-based blockchain address generation and signing.
 *
 * Features:
 * - SS58 address encoding with configurable network prefix
 * - Address validation for any Substrate chain
 * - Message signing/verification using Sr25519 or Ed25519
 * - Support for multiple Substrate networks
 *
 * Supported networks:
 * - Polkadot (prefix 0)
 * - Kusama (prefix 2)
 * - Westend (prefix 42)
 * - Any Substrate chain with custom prefix
 *
 * Note: This implementation uses Ed25519 as the default curve.
 * Sr25519 (Schnorrkel) requires additional dependencies.
 */

#ifndef HD_WALLET_POLKADOT_H
#define HD_WALLET_POLKADOT_H

#include "coin.h"

namespace hd_wallet {
namespace coins {

// =============================================================================
// Substrate Network Configuration
// =============================================================================

/**
 * Substrate network parameters
 */
struct SubstrateNetworkParams {
  /// Network name
  const char* name;

  /// Network symbol
  const char* symbol;

  /// SS58 address prefix (0-16383)
  uint16_t ss58_prefix;

  /// Decimals for the native token
  uint8_t decimals;

  /// Whether to use Sr25519 (true) or Ed25519 (false)
  bool use_sr25519;
};

/// Polkadot mainnet parameters
extern const SubstrateNetworkParams POLKADOT;

/// Kusama parameters
extern const SubstrateNetworkParams KUSAMA;

/// Westend testnet parameters
extern const SubstrateNetworkParams WESTEND;

/// Substrate generic (prefix 42)
extern const SubstrateNetworkParams SUBSTRATE_GENERIC;

/// Acala parameters
extern const SubstrateNetworkParams ACALA;

/// Moonbeam parameters
extern const SubstrateNetworkParams MOONBEAM;

/// Astar parameters
extern const SubstrateNetworkParams ASTAR;

// =============================================================================
// SS58 Address Encoding
// =============================================================================

/**
 * Encode public key as SS58 address
 *
 * SS58 is a modified Base58 encoding designed for Substrate.
 * Format: prefix + account_id + checksum
 *
 * Checksum: First 2 bytes of Blake2b-512("SS58PRE" + prefix + account_id)
 *
 * @param public_key 32-byte Ed25519 or Sr25519 public key
 * @param network_prefix SS58 network prefix (0-16383)
 * @return SS58-encoded address
 */
Result<std::string> ss58Encode(const Bytes32& public_key, uint16_t network_prefix = 0);

/**
 * Encode using network parameters
 */
Result<std::string> ss58Encode(const Bytes32& public_key, const SubstrateNetworkParams& params);

/**
 * Decode SS58 address to public key (Polkadot-specific, returns Bytes32)
 *
 * @param address SS58-encoded address
 * @return Pair of (network_prefix, public_key)
 */
Result<std::pair<uint16_t, Bytes32>> ss58DecodeBytes32(const std::string& address);

/**
 * Convert address between Substrate networks
 *
 * @param address Original SS58 address
 * @param new_prefix New network prefix
 * @return Address with new prefix
 */
Result<std::string> convertSS58Prefix(const std::string& address, uint16_t new_prefix);

// =============================================================================
// SS58 Address Validation
// =============================================================================

/**
 * Validate SS58 address
 *
 * Checks:
 * - Valid SS58 Base58 encoding
 * - Valid prefix
 * - Valid checksum
 * - Public key length is 32 bytes
 *
 * @param address Address to validate
 * @param expected_prefix Expected prefix (-1 = any valid prefix)
 * @return Error::OK if valid
 */
Error validateSS58Address(const std::string& address, int32_t expected_prefix = -1);

/**
 * Extract network prefix from SS58 address
 * @param address SS58-encoded address
 * @return Network prefix
 */
Result<uint16_t> extractSS58Prefix(const std::string& address);

/**
 * Check if address belongs to a specific network
 */
bool isSubstrateNetworkAddress(const std::string& address, const SubstrateNetworkParams& params);

/**
 * Get network info from prefix
 */
const SubstrateNetworkParams* getSubstrateNetworkByPrefix(uint16_t prefix);

// =============================================================================
// Polkadot Message Signing
// =============================================================================

/**
 * Sign a message using Ed25519
 *
 * Polkadot message format: "<Bytes>" + message + "</Bytes>"
 * (Substrate's wrapped message format)
 *
 * @param message Message to sign
 * @param private_key 32-byte Ed25519 private key
 * @return 64-byte Ed25519 signature
 */
Result<ByteVector> signPolkadotMessage(const std::string& message, const Bytes32& private_key);

/**
 * Sign raw bytes (no wrapping)
 */
Result<ByteVector> signPolkadotMessageRaw(const ByteVector& message, const Bytes32& private_key);

/**
 * Verify a Polkadot message signature
 *
 * @param message Original message (will be wrapped)
 * @param signature 64-byte Ed25519 signature
 * @param public_key 32-byte Ed25519 public key
 * @return true if signature is valid
 */
Result<bool> verifyPolkadotMessage(
  const std::string& message,
  const ByteVector& signature,
  const Bytes32& public_key
);

/**
 * Verify signature against SS58 address
 */
Result<bool> verifyPolkadotMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
);

/**
 * Verify raw bytes signature
 */
Result<bool> verifyPolkadotMessageRaw(
  const ByteVector& message,
  const ByteVector& signature,
  const Bytes32& public_key
);

// =============================================================================
// Polkadot Transaction Signing
// =============================================================================

/**
 * Sign an extrinsic payload
 *
 * The payload is hashed with BLAKE2b-256 if longer than 256 bytes.
 *
 * @param payload Extrinsic payload bytes
 * @param private_key 32-byte Ed25519 private key
 * @return 64-byte signature
 */
Result<ByteVector> signExtrinsic(const ByteVector& payload, const Bytes32& private_key);

/**
 * Verify extrinsic signature
 */
Result<bool> verifyExtrinsicSignature(
  const ByteVector& payload,
  const ByteVector& signature,
  const Bytes32& public_key
);

/**
 * Hash payload for signing (BLAKE2b-256 if > 256 bytes)
 */
Bytes32 hashPayloadForSigning(const ByteVector& payload);

// =============================================================================
// Multi-Address Support
// =============================================================================

/**
 * MultiAddress type enum (for Substrate runtime calls)
 */
enum class MultiAddressType : uint8_t {
  Id = 0,      // AccountId32
  Index = 1,   // AccountIndex
  Raw = 2,     // Raw bytes
  Address32 = 3,
  Address20 = 4
};

/**
 * Encode address as MultiAddress (scale-encoded)
 * @param address SS58 address
 * @return SCALE-encoded MultiAddress
 */
Result<ByteVector> encodeMultiAddress(const std::string& address);

/**
 * Encode public key as MultiAddress::Id
 */
ByteVector encodeMultiAddressId(const Bytes32& public_key);

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Derive Ed25519 keypair from seed
 */
Result<std::pair<Bytes32, Bytes32>> deriveSubstrateKeypair(const Bytes32& seed);

/**
 * Derive public key from private key
 */
Result<Bytes32> deriveSubstratePublicKey(const Bytes32& private_key);

/**
 * Derive address using path format //hard/soft
 * Note: This is Substrate's special derivation, not BIP-44
 *
 * @param seed 32-byte master seed
 * @param path Derivation path (e.g., "//polkadot//staking/0")
 * @return Derived keypair
 */
Result<std::pair<Bytes32, Bytes32>> deriveSubstratePath(
  const Bytes32& seed,
  const std::string& path
);

// =============================================================================
// Polkadot Coin Implementation
// =============================================================================

/**
 * Polkadot coin implementation
 */
class Polkadot : public Coin {
public:
  explicit Polkadot(const SubstrateNetworkParams& params = POLKADOT);
  explicit Polkadot(uint16_t ss58_prefix);

  // ----- Identification -----
  CoinType coinType() const override { return CoinType::POLKADOT; }
  const char* name() const override { return params_.name; }
  const char* symbol() const override { return params_.symbol; }
  Curve curve() const override { return Curve::ED25519; }

  // ----- Network -----
  Network network() const override { return network_; }
  void setNetwork(Network net) override { network_ = net; }

  /// Get network parameters
  const SubstrateNetworkParams& params() const { return params_; }

  /// Set SS58 prefix
  void setSS58Prefix(uint16_t prefix) { params_.ss58_prefix = prefix; }
  uint16_t ss58Prefix() const { return params_.ss58_prefix; }

  // ----- Address Generation -----

  /**
   * Generate address from Ed25519 public key
   * Note: For Polkadot, this expects a 32-byte Ed25519 key stored in Bytes33
   *       (first byte may be ignored)
   */
  Result<std::string> addressFromPublicKey(const Bytes33& public_key) const override;

  /**
   * Generate address from 32-byte Ed25519 public key
   */
  Result<std::string> addressFromEd25519PublicKey(const Bytes32& public_key) const;

  // ----- Address Validation -----
  Error validateAddress(const std::string& address) const override;
  Result<DecodedAddress> decodeAddress(const std::string& address) const override;

  // ----- Message Signing -----
  Result<ByteVector> signMessage(const ByteVector& message, const Bytes32& private_key) const override;
  Result<bool> verifyMessage(
    const ByteVector& message,
    const ByteVector& signature,
    const ByteVector& public_key
  ) const override;

  /// Sign with message wrapping
  Result<ByteVector> signMessageWrapped(const std::string& message, const Bytes32& private_key) const;

  /// Verify with message wrapping
  Result<bool> verifyMessageWrapped(
    const std::string& message,
    const ByteVector& signature,
    const Bytes32& public_key
  ) const;

  // ----- Derivation Path -----
  std::string getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const override;

private:
  Network network_;
  SubstrateNetworkParams params_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  uint16_t ss58_prefix,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_validate_address(
  const char* address,
  int32_t expected_prefix
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_decode_address(
  const char* address,
  uint16_t* prefix_out,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_convert_prefix(
  const char* address,
  uint16_t new_prefix,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_sign_extrinsic(
  const uint8_t* payload,
  size_t payload_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_derive_pubkey(
  const uint8_t* private_key,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ss58_encode(
  const uint8_t* public_key,
  size_t pubkey_len,
  uint16_t prefix,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ss58_decode(
  const char* address,
  uint16_t* prefix_out,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_POLKADOT_H
