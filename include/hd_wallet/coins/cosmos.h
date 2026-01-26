/**
 * @file cosmos.h
 * @brief Cosmos/Tendermint Support
 *
 * Provides Cosmos SDK-based blockchain address generation and signing.
 *
 * Features:
 * - Bech32 address generation with configurable prefix
 * - Address validation for any Cosmos chain
 * - Amino signing (legacy)
 * - Direct (protobuf) signing
 *
 * Supported chains:
 * - Cosmos Hub (cosmos1...)
 * - Osmosis (osmo1...)
 * - Terra (terra1...)
 * - Juno (juno1...)
 * - And any Cosmos SDK-based chain
 */

#ifndef HD_WALLET_COSMOS_H
#define HD_WALLET_COSMOS_H

#include "coin.h"

namespace hd_wallet {
namespace coins {

// =============================================================================
// Cosmos Chain Configuration
// =============================================================================

/**
 * Cosmos chain parameters
 */
struct CosmosChainParams {
  /// Chain name (e.g., "cosmoshub-4")
  const char* chain_id;

  /// Address prefix (e.g., "cosmos")
  const char* bech32_prefix;

  /// Validator address prefix (e.g., "cosmosvaloper")
  const char* bech32_prefix_valoper;

  /// Account public key prefix (e.g., "cosmospub")
  const char* bech32_prefix_pub;

  /// Validator public key prefix
  const char* bech32_prefix_valoperpub;

  /// Coin denomination (e.g., "uatom")
  const char* denom;

  /// SLIP-44 coin type
  uint32_t coin_type;

  /// Default gas price
  uint64_t default_gas_price;
};

/// Cosmos Hub mainnet parameters
extern const CosmosChainParams COSMOS_HUB;

/// Osmosis mainnet parameters
extern const CosmosChainParams OSMOSIS;

/// Terra mainnet parameters
extern const CosmosChainParams TERRA;

/// Juno mainnet parameters
extern const CosmosChainParams JUNO;

/// Secret Network parameters
extern const CosmosChainParams SECRET;

/// Celestia parameters
extern const CosmosChainParams CELESTIA;

// =============================================================================
// Cosmos Address Generation
// =============================================================================

/**
 * Generate Cosmos address from public key
 *
 * Algorithm:
 * 1. SHA256 hash of public key
 * 2. RIPEMD160 hash of SHA256 result
 * 3. Bech32 encode with prefix
 *
 * @param public_key Compressed (33-byte) secp256k1 public key
 * @param prefix Bech32 prefix (e.g., "cosmos")
 * @return Bech32 address string
 */
Result<std::string> cosmosAddress(const Bytes33& public_key, const std::string& prefix = "cosmos");

/**
 * Generate Cosmos address using chain parameters
 */
Result<std::string> cosmosAddress(const Bytes33& public_key, const CosmosChainParams& params);

/**
 * Generate validator operator address
 * Uses the valoper prefix instead of account prefix
 */
Result<std::string> cosmosValoperAddress(const Bytes33& public_key, const std::string& prefix = "cosmosvaloper");

/**
 * Convert between address formats (e.g., cosmos -> osmo)
 *
 * @param address Original address
 * @param new_prefix New prefix to use
 * @return Address with new prefix
 */
Result<std::string> convertCosmosPrefix(const std::string& address, const std::string& new_prefix);

// =============================================================================
// Cosmos Address Validation
// =============================================================================

/**
 * Validate Cosmos address
 *
 * Checks:
 * - Valid Bech32 encoding
 * - Prefix matches expected (if provided)
 * - Data length is 20 bytes (standard address)
 *
 * @param address Address to validate
 * @param expected_prefix Expected prefix (empty = any valid Cosmos prefix)
 * @return Error::OK if valid
 */
Error validateCosmosAddress(const std::string& address, const std::string& expected_prefix = "");

/**
 * Extract prefix from Cosmos address
 * @param address Address string
 * @return Prefix (e.g., "cosmos", "osmo")
 */
Result<std::string> extractCosmosPrefix(const std::string& address);

/**
 * Check if address belongs to a specific chain
 */
bool isCosmosChainAddress(const std::string& address, const CosmosChainParams& params);

// =============================================================================
// Amino Signing (Legacy)
// =============================================================================

/**
 * Sign document using Amino encoding
 *
 * Amino is the legacy encoding format used by Cosmos SDK before v0.40.
 * The signature is created by:
 * 1. Serialize document to Amino JSON
 * 2. SHA256 hash the JSON
 * 3. Sign with secp256k1
 *
 * @param sign_doc Amino-encoded sign document (JSON bytes)
 * @param private_key 32-byte private key
 * @return 64-byte signature (r || s)
 */
Result<ByteVector> signAmino(const ByteVector& sign_doc, const Bytes32& private_key);

/**
 * Sign a standard Amino transaction
 *
 * @param chain_id Chain ID string
 * @param account_number Account number
 * @param sequence Sequence number
 * @param fee Fee object (JSON)
 * @param msgs Array of messages (JSON)
 * @param memo Transaction memo
 * @param private_key 32-byte private key
 * @return 64-byte signature
 */
Result<ByteVector> signAminoTransaction(
  const std::string& chain_id,
  uint64_t account_number,
  uint64_t sequence,
  const std::string& fee_json,
  const std::string& msgs_json,
  const std::string& memo,
  const Bytes32& private_key
);

/**
 * Create Amino sign document
 * Returns canonical JSON bytes ready for signing
 */
ByteVector createAminoSignDoc(
  const std::string& chain_id,
  uint64_t account_number,
  uint64_t sequence,
  const std::string& fee_json,
  const std::string& msgs_json,
  const std::string& memo
);

/**
 * Verify Amino signature
 *
 * @param sign_doc Amino-encoded sign document
 * @param signature 64-byte signature
 * @param public_key 33-byte compressed public key
 * @return true if signature is valid
 */
Result<bool> verifyAminoSignature(
  const ByteVector& sign_doc,
  const ByteVector& signature,
  const Bytes33& public_key
);

// =============================================================================
// Direct Signing (Protobuf)
// =============================================================================

/**
 * Sign document using Direct (protobuf) encoding
 *
 * Direct signing is the modern signing mode introduced in Cosmos SDK v0.40.
 * The signature is created by:
 * 1. Hash the SignDoc protobuf bytes with SHA256
 * 2. Sign with secp256k1
 *
 * @param sign_doc_bytes Protobuf-encoded SignDoc
 * @param private_key 32-byte private key
 * @return 64-byte signature (r || s)
 */
Result<ByteVector> signDirect(const ByteVector& sign_doc_bytes, const Bytes32& private_key);

/**
 * Create Direct sign document bytes
 *
 * @param body_bytes Protobuf-encoded TxBody
 * @param auth_info_bytes Protobuf-encoded AuthInfo
 * @param chain_id Chain ID string
 * @param account_number Account number
 * @return SignDoc protobuf bytes
 */
ByteVector createDirectSignDoc(
  const ByteVector& body_bytes,
  const ByteVector& auth_info_bytes,
  const std::string& chain_id,
  uint64_t account_number
);

/**
 * Verify Direct signature
 *
 * @param sign_doc_bytes Protobuf-encoded SignDoc
 * @param signature 64-byte signature
 * @param public_key 33-byte compressed public key
 * @return true if signature is valid
 */
Result<bool> verifyDirectSignature(
  const ByteVector& sign_doc_bytes,
  const ByteVector& signature,
  const Bytes33& public_key
);

// =============================================================================
// Arbitrary Message Signing
// =============================================================================

/**
 * Sign arbitrary data according to ADR-036
 * https://github.com/cosmos/cosmos-sdk/blob/main/docs/architecture/adr-036-arbitrary-signature.md
 *
 * @param signer Signer address
 * @param data Data to sign
 * @param private_key 32-byte private key
 * @return Signature bytes
 */
Result<ByteVector> signArbitrary(
  const std::string& signer,
  const ByteVector& data,
  const Bytes32& private_key
);

/**
 * Verify ADR-036 arbitrary signature
 */
Result<bool> verifyArbitrary(
  const std::string& signer,
  const ByteVector& data,
  const ByteVector& signature,
  const Bytes33& public_key
);

// =============================================================================
// Public Key Encoding
// =============================================================================

/**
 * Encode secp256k1 public key for Cosmos
 * Returns the Amino-encoded public key type
 */
ByteVector encodeCosmosPublicKey(const Bytes33& public_key);

/**
 * Get Bech32 encoded public key
 */
std::string cosmosPublicKeyBech32(const Bytes33& public_key, const std::string& prefix = "cosmospub");

// =============================================================================
// Cosmos Coin Implementation
// =============================================================================

/**
 * Cosmos coin implementation
 */
class Cosmos : public Coin {
public:
  explicit Cosmos(const CosmosChainParams& params = COSMOS_HUB);
  explicit Cosmos(const std::string& prefix, uint32_t coin_type = 118);

  // ----- Identification -----
  CoinType coinType() const override { return CoinType::COSMOS; }
  const char* name() const override { return "Cosmos"; }
  const char* symbol() const override { return "ATOM"; }
  Curve curve() const override { return Curve::SECP256K1; }

  // ----- Network -----
  Network network() const override { return network_; }
  void setNetwork(Network net) override { network_ = net; }

  /// Get chain parameters
  const CosmosChainParams& params() const { return params_; }

  /// Set address prefix
  void setPrefix(const std::string& prefix) { prefix_ = prefix; }
  const std::string& prefix() const { return prefix_; }

  // ----- Address Generation -----
  Result<std::string> addressFromPublicKey(const Bytes33& public_key) const override;

  /// Generate validator operator address
  Result<std::string> valoperAddressFromPublicKey(const Bytes33& public_key) const;

  // ----- Address Validation -----
  Error validateAddress(const std::string& address) const override;
  Result<DecodedAddress> decodeAddress(const std::string& address) const override;

  // ----- Message Signing (ADR-036) -----
  Result<ByteVector> signMessage(const ByteVector& message, const Bytes32& private_key) const override;
  Result<bool> verifyMessage(
    const ByteVector& message,
    const ByteVector& signature,
    const ByteVector& public_key
  ) const override;

  // ----- Transaction Signing -----
  Result<ByteVector> signAminoTx(const ByteVector& sign_doc, const Bytes32& private_key) const;
  Result<ByteVector> signDirectTx(const ByteVector& sign_doc_bytes, const Bytes32& private_key) const;

  // ----- Derivation Path -----
  std::string getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const override;

private:
  Network network_;
  CosmosChainParams params_;
  std::string prefix_;
  uint32_t slip44_coin_type_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  const char* prefix,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_validate_address(
  const char* address,
  const char* expected_prefix
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_convert_prefix(
  const char* address,
  const char* new_prefix,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_amino(
  const uint8_t* sign_doc,
  size_t sign_doc_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_direct(
  const uint8_t* sign_doc_bytes,
  size_t sign_doc_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_verify_signature(
  const uint8_t* sign_doc,
  size_t sign_doc_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_arbitrary(
  const char* signer,
  const uint8_t* data,
  size_t data_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_COSMOS_H
