/**
 * @file solana.h
 * @brief Solana Support
 *
 * Provides Solana address generation, validation, and message signing.
 *
 * Features:
 * - Base58 address from Ed25519 public key
 * - Address validation
 * - Message signing/verification using Ed25519
 * - Program Derived Addresses (PDA) generation
 *
 * Note: Solana uses Ed25519 curve (not secp256k1)
 */

#ifndef HD_WALLET_SOLANA_H
#define HD_WALLET_SOLANA_H

#include "coin.h"

namespace hd_wallet {
namespace coins {

// =============================================================================
// Solana Address Generation
// =============================================================================

/**
 * Generate Solana address from Ed25519 public key
 *
 * Solana addresses are simply the Base58-encoded public key.
 *
 * @param public_key 32-byte Ed25519 public key
 * @return Base58-encoded address (32-44 characters)
 */
Result<std::string> solanaAddress(const Bytes32& public_key);

/**
 * Get public key bytes from Solana address
 * @param address Base58-encoded address
 * @return 32-byte public key
 */
Result<Bytes32> solanaAddressToPublicKey(const std::string& address);

// =============================================================================
// Solana Address Validation
// =============================================================================

/**
 * Validate Solana address
 *
 * Checks:
 * - Valid Base58 encoding
 * - Decodes to 32 bytes
 * - Is on the Ed25519 curve (if verify_curve is true)
 *
 * @param address Address to validate
 * @param verify_curve Whether to verify the point is on curve (default: false)
 * @return Error::OK if valid
 */
Error validateSolanaAddress(const std::string& address, bool verify_curve = false);

/**
 * Check if address is a system program address
 */
bool isSolanaSystemProgram(const std::string& address);

/**
 * Check if address is a token program address
 */
bool isSolanaTokenProgram(const std::string& address);

// =============================================================================
// Solana Program Derived Addresses (PDA)
// =============================================================================

/**
 * Find Program Derived Address
 *
 * PDAs are addresses that are derived from a program ID and seeds,
 * guaranteed to not have a corresponding private key.
 *
 * Algorithm:
 * 1. Concatenate seeds + program_id + "ProgramDerivedAddress"
 * 2. SHA256 hash
 * 3. Check if point is not on curve
 * 4. If on curve, try with bump seed (255 down to 0)
 *
 * @param program_id 32-byte program ID
 * @param seeds Vector of seed bytes
 * @return Pair of (address, bump seed)
 */
Result<std::pair<std::string, uint8_t>> findProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
);

/**
 * Create Program Derived Address with known bump
 *
 * @param program_id 32-byte program ID
 * @param seeds Vector of seed bytes (including bump as last seed)
 * @return PDA address
 */
Result<std::string> createProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
);

/**
 * Derive Associated Token Address
 *
 * Gets the associated token account address for a wallet and mint.
 *
 * @param wallet_address Wallet address (Base58)
 * @param mint_address Token mint address (Base58)
 * @return Associated token account address
 */
Result<std::string> getAssociatedTokenAddress(
  const std::string& wallet_address,
  const std::string& mint_address
);

// =============================================================================
// Solana Message Signing
// =============================================================================

/**
 * Sign a message using Ed25519
 *
 * @param message Message bytes to sign
 * @param private_key 32-byte Ed25519 private key (seed)
 * @return 64-byte Ed25519 signature
 */
Result<ByteVector> signSolanaMessage(const ByteVector& message, const Bytes32& private_key);

/**
 * Sign a message string
 */
Result<ByteVector> signSolanaMessage(const std::string& message, const Bytes32& private_key);

/**
 * Verify a Solana message signature
 *
 * @param message Original message
 * @param signature 64-byte Ed25519 signature
 * @param public_key 32-byte Ed25519 public key
 * @return true if signature is valid
 */
Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const Bytes32& public_key
);

/**
 * Verify signature against address
 */
Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const std::string& address
);

// =============================================================================
// Solana Off-Chain Message Signing (SIP-018 Style)
// =============================================================================

/**
 * Sign an off-chain message with domain prefix
 *
 * Format: "\x00solana offchain\n" + message
 *
 * @param message Message to sign
 * @param private_key 32-byte Ed25519 private key
 * @return 64-byte signature
 */
Result<ByteVector> signOffChainMessage(const std::string& message, const Bytes32& private_key);

/**
 * Verify off-chain message signature
 */
Result<bool> verifyOffChainMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
);

// =============================================================================
// Solana Transaction Signing
// =============================================================================

/**
 * Sign a transaction message
 *
 * Solana transactions are signed by hashing the message with SHA256
 * and then signing with Ed25519.
 *
 * @param message_bytes Serialized transaction message
 * @param private_key 32-byte Ed25519 private key
 * @return 64-byte signature
 */
Result<ByteVector> signTransaction(const ByteVector& message_bytes, const Bytes32& private_key);

/**
 * Verify transaction signature
 */
Result<bool> verifyTransactionSignature(
  const ByteVector& message_bytes,
  const ByteVector& signature,
  const Bytes32& public_key
);

// =============================================================================
// Solana Key Derivation
// =============================================================================

/**
 * Derive Ed25519 keypair from seed
 *
 * Solana uses the raw seed as the private key and derives
 * the public key using standard Ed25519 derivation.
 *
 * @param seed 32-byte seed
 * @return Pair of (private_key, public_key)
 */
Result<std::pair<Bytes32, Bytes32>> deriveKeypair(const Bytes32& seed);

/**
 * Derive Ed25519 public key from private key
 * @param private_key 32-byte Ed25519 private key (seed)
 * @return 32-byte public key
 */
Result<Bytes32> derivePublicKey(const Bytes32& private_key);

// =============================================================================
// Solana Coin Implementation
// =============================================================================

/**
 * Solana coin implementation
 */
class Solana : public Coin {
public:
  explicit Solana(Network network = Network::MAINNET);

  // ----- Identification -----
  CoinType coinType() const override { return CoinType::SOLANA; }
  const char* name() const override { return "Solana"; }
  const char* symbol() const override { return "SOL"; }
  Curve curve() const override { return Curve::ED25519; }

  // ----- Network -----
  Network network() const override { return network_; }
  void setNetwork(Network net) override { network_ = net; }

  // ----- Address Generation -----

  /**
   * Generate address from Ed25519 public key
   * Note: For Solana, the public key IS the address (Base58 encoded)
   *
   * @param public_key This should be a 32-byte Ed25519 public key stored in Bytes33
   *                   (first byte ignored for Ed25519)
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

  // ----- Derivation Path -----
  std::string getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const override;

private:
  Network network_;
};

// =============================================================================
// Well-Known Solana Addresses
// =============================================================================

namespace solana_addresses {
  /// System Program
  extern const char* SYSTEM_PROGRAM;

  /// Token Program
  extern const char* TOKEN_PROGRAM;

  /// Token 2022 Program
  extern const char* TOKEN_2022_PROGRAM;

  /// Associated Token Program
  extern const char* ASSOCIATED_TOKEN_PROGRAM;

  /// Memo Program
  extern const char* MEMO_PROGRAM;

  /// Rent Sysvar
  extern const char* RENT_SYSVAR;

  /// Clock Sysvar
  extern const char* CLOCK_SYSVAR;

  /// Stake Program
  extern const char* STAKE_PROGRAM;

  /// Vote Program
  extern const char* VOTE_PROGRAM;
}

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_validate_address(const char* address);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address_to_pubkey(
  const char* address,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_derive_pubkey(
  const uint8_t* private_key,
  uint8_t* pubkey_out,
  size_t pubkey_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_find_pda(
  const uint8_t* program_id,
  const uint8_t* seeds,
  size_t seeds_len,
  const size_t* seed_lengths,
  size_t num_seeds,
  char* address_out,
  size_t address_size,
  uint8_t* bump_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_get_associated_token_address(
  const char* wallet_address,
  const char* mint_address,
  char* address_out,
  size_t address_size
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_SOLANA_H
