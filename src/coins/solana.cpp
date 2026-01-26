/**
 * @file solana.cpp
 * @brief Solana Support Implementation
 */

#include "hd_wallet/coins/solana.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Well-Known Solana Addresses
// =============================================================================

namespace solana_addresses {
  const char* SYSTEM_PROGRAM = "11111111111111111111111111111111";
  const char* TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
  const char* TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
  const char* ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
  const char* MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
  const char* RENT_SYSVAR = "SysvarRent111111111111111111111111111111111";
  const char* CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111";
  const char* STAKE_PROGRAM = "Stake11111111111111111111111111111111111111";
  const char* VOTE_PROGRAM = "Vote111111111111111111111111111111111111111";
}

// =============================================================================
// Solana Address Generation
// =============================================================================

Result<std::string> solanaAddress(const Bytes32& public_key) {
  // Solana addresses are simply Base58-encoded public keys
  ByteVector pubkey(public_key.begin(), public_key.end());
  return Result<std::string>::success(base58Encode(pubkey));
}

Result<Bytes32> solanaAddressToPublicKey(const std::string& address) {
  auto decoded = base58Decode(address);
  if (!decoded.ok()) {
    return Result<Bytes32>::fail(decoded.error);
  }

  if (decoded.value.size() != 32) {
    return Result<Bytes32>::fail(Error::INVALID_ADDRESS);
  }

  Bytes32 result;
  std::copy(decoded.value.begin(), decoded.value.end(), result.begin());
  return Result<Bytes32>::success(std::move(result));
}

// =============================================================================
// Solana Address Validation
// =============================================================================

Error validateSolanaAddress(const std::string& address, bool verify_curve) {
  // Decode from Base58
  auto decoded = base58Decode(address);
  if (!decoded.ok()) {
    return Error::INVALID_ADDRESS;
  }

  // Must be 32 bytes
  if (decoded.value.size() != 32) {
    return Error::INVALID_ADDRESS;
  }

  // Optionally verify it's on the Ed25519 curve
  if (verify_curve) {
    // For Ed25519, not all 32-byte values are valid public keys
    // A full implementation would verify the point is on curve
    // For now, we just check basic validity
    try {
      CryptoPP::ed25519::Verifier verifier(decoded.value.data());
      // If we can create a verifier, the key is valid
    } catch (...) {
      return Error::INVALID_PUBLIC_KEY;
    }
  }

  return Error::OK;
}

bool isSolanaSystemProgram(const std::string& address) {
  return address == solana_addresses::SYSTEM_PROGRAM;
}

bool isSolanaTokenProgram(const std::string& address) {
  return address == solana_addresses::TOKEN_PROGRAM ||
         address == solana_addresses::TOKEN_2022_PROGRAM;
}

// =============================================================================
// Solana Program Derived Addresses (PDA)
// =============================================================================

namespace {

// Check if a point is NOT on the Ed25519 curve
// PDAs must NOT be valid public keys
bool isOffCurve(const uint8_t* bytes) {
  try {
    CryptoPP::ed25519::Verifier verifier(bytes);
    return false;  // On curve
  } catch (...) {
    return true;  // Off curve (valid PDA)
  }
}

}  // namespace

Result<std::pair<std::string, uint8_t>> findProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
) {
  // Try bump seeds from 255 down to 0
  for (int bump = 255; bump >= 0; bump--) {
    // Create seeds with bump
    std::vector<ByteVector> seeds_with_bump = seeds;
    seeds_with_bump.push_back({static_cast<uint8_t>(bump)});

    auto result = createProgramAddress(program_id, seeds_with_bump);
    if (result.ok()) {
      return Result<std::pair<std::string, uint8_t>>::success(
        std::make_pair(result.value, static_cast<uint8_t>(bump))
      );
    }
  }

  return Result<std::pair<std::string, uint8_t>>::fail(Error::KEY_DERIVATION_FAILED);
}

Result<std::string> createProgramAddress(
  const Bytes32& program_id,
  const std::vector<ByteVector>& seeds
) {
  // Concatenate: seeds + program_id + "ProgramDerivedAddress"
  ByteVector data;

  // Add seeds
  for (const auto& seed : seeds) {
    if (seed.size() > 32) {
      return Result<std::string>::fail(Error::INVALID_ARGUMENT);
    }
    data.insert(data.end(), seed.begin(), seed.end());
  }

  // Add program_id
  data.insert(data.end(), program_id.begin(), program_id.end());

  // Add marker
  const char* marker = "ProgramDerivedAddress";
  data.insert(data.end(), marker, marker + 21);

  // SHA256 hash
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), data.data(), data.size());

  // Verify it's off curve (valid PDA)
  if (!isOffCurve(hash.data())) {
    return Result<std::string>::fail(Error::INVALID_ADDRESS);
  }

  // Encode as address
  return solanaAddress(hash);
}

Result<std::string> getAssociatedTokenAddress(
  const std::string& wallet_address,
  const std::string& mint_address
) {
  // Decode addresses
  auto wallet = solanaAddressToPublicKey(wallet_address);
  if (!wallet.ok()) return Result<std::string>::fail(wallet.error);

  auto mint = solanaAddressToPublicKey(mint_address);
  if (!mint.ok()) return Result<std::string>::fail(mint.error);

  auto token_program = solanaAddressToPublicKey(solana_addresses::TOKEN_PROGRAM);
  if (!token_program.ok()) return Result<std::string>::fail(token_program.error);

  auto ata_program = solanaAddressToPublicKey(solana_addresses::ASSOCIATED_TOKEN_PROGRAM);
  if (!ata_program.ok()) return Result<std::string>::fail(ata_program.error);

  // Seeds: [wallet, token_program, mint]
  std::vector<ByteVector> seeds = {
    ByteVector(wallet.value.begin(), wallet.value.end()),
    ByteVector(token_program.value.begin(), token_program.value.end()),
    ByteVector(mint.value.begin(), mint.value.end())
  };

  auto result = findProgramAddress(ata_program.value, seeds);
  if (!result.ok()) return Result<std::string>::fail(result.error);

  return Result<std::string>::success(std::move(result.value.first));
}

// =============================================================================
// Solana Message Signing
// =============================================================================

Result<ByteVector> signSolanaMessage(const ByteVector& message, const Bytes32& private_key) {
  auto sig = ed25519Sign(message, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  return Result<ByteVector>::success(ByteVector(sig.value.data.begin(), sig.value.data.end()));
}

Result<ByteVector> signSolanaMessage(const std::string& message, const Bytes32& private_key) {
  ByteVector msg(message.begin(), message.end());
  return signSolanaMessage(msg, private_key);
}

Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  Ed25519Signature sig;
  std::copy(signature.begin(), signature.end(), sig.data.begin());

  return ed25519Verify(message, sig, public_key);
}

Result<bool> verifySolanaMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const std::string& address
) {
  auto pubkey = solanaAddressToPublicKey(address);
  if (!pubkey.ok()) {
    return Result<bool>::fail(pubkey.error);
  }

  return verifySolanaMessage(message, signature, pubkey.value);
}

// =============================================================================
// Solana Off-Chain Message Signing
// =============================================================================

Result<ByteVector> signOffChainMessage(const std::string& message, const Bytes32& private_key) {
  // Format: "\x00solana offchain\n" + message
  ByteVector to_sign;
  const char* prefix = "\x00solana offchain\n";
  to_sign.insert(to_sign.end(), prefix, prefix + 18);
  to_sign.insert(to_sign.end(), message.begin(), message.end());

  return signSolanaMessage(to_sign, private_key);
}

Result<bool> verifyOffChainMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
) {
  ByteVector to_verify;
  const char* prefix = "\x00solana offchain\n";
  to_verify.insert(to_verify.end(), prefix, prefix + 18);
  to_verify.insert(to_verify.end(), message.begin(), message.end());

  return verifySolanaMessage(to_verify, signature, address);
}

// =============================================================================
// Solana Transaction Signing
// =============================================================================

Result<ByteVector> signTransaction(const ByteVector& message_bytes, const Bytes32& private_key) {
  // For Solana transactions, we sign the message bytes directly
  // (they're already the serialized message that's signed)
  return signSolanaMessage(message_bytes, private_key);
}

Result<bool> verifyTransactionSignature(
  const ByteVector& message_bytes,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  return verifySolanaMessage(message_bytes, signature, public_key);
}

// =============================================================================
// Solana Key Derivation
// =============================================================================

Result<std::pair<Bytes32, Bytes32>> deriveKeypair(const Bytes32& seed) {
  // For Ed25519, the seed IS the private key
  // Derive public key from it
  auto pubkey = derivePublicKey(seed);
  if (!pubkey.ok()) {
    return Result<std::pair<Bytes32, Bytes32>>::fail(pubkey.error);
  }

  return Result<std::pair<Bytes32, Bytes32>>::success(
    std::make_pair(seed, pubkey.value)
  );
}

Result<Bytes32> derivePublicKey(const Bytes32& private_key) {
  return ed25519PublicKey(private_key);
}

// =============================================================================
// Solana Coin Implementation
// =============================================================================

Solana::Solana(Network network)
  : network_(network) {
}

Result<std::string> Solana::addressFromPublicKey(const Bytes33& public_key) const {
  // For Solana, we expect a 32-byte Ed25519 key
  // If Bytes33 is used, take the first 32 bytes (or last 32 if first is padding)

  // Check if first byte looks like a padding byte
  Bytes32 ed_pubkey;
  if (public_key[0] == 0x00 || public_key[0] == 0x01) {
    // Assume first byte is padding/prefix, use bytes 1-32
    std::copy(public_key.begin() + 1, public_key.end(), ed_pubkey.begin());
  } else {
    // Use first 32 bytes
    std::copy(public_key.begin(), public_key.begin() + 32, ed_pubkey.begin());
  }

  return addressFromEd25519PublicKey(ed_pubkey);
}

Result<std::string> Solana::addressFromEd25519PublicKey(const Bytes32& public_key) const {
  return solanaAddress(public_key);
}

Error Solana::validateAddress(const std::string& address) const {
  return validateSolanaAddress(address, false);
}

Result<DecodedAddress> Solana::decodeAddress(const std::string& address) const {
  auto pubkey = solanaAddressToPublicKey(address);
  if (!pubkey.ok()) {
    return Result<DecodedAddress>::fail(pubkey.error);
  }

  DecodedAddress result;
  result.address = address;
  result.network = network_;
  result.version = 0;
  result.data = ByteVector(pubkey.value.begin(), pubkey.value.end());

  return Result<DecodedAddress>::success(std::move(result));
}

Result<ByteVector> Solana::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  return signSolanaMessage(message, private_key);
}

Result<bool> Solana::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  if (public_key.size() != 32) {
    return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
  }

  Bytes32 pubkey;
  std::copy(public_key.begin(), public_key.end(), pubkey.begin());

  return verifySolanaMessage(message, signature, pubkey);
}

std::string Solana::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  // Solana uses a different derivation path: m/44'/501'/account'/change'
  // Note: All levels are hardened for Ed25519
  std::ostringstream path;
  path << "m/44'/501'/" << account << "'/" << change << "'";
  return path.str();
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 32 || !address_out || address_size < 44) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  auto result = solanaAddress(pubkey);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_validate_address(const char* address) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(validateSolanaAddress(address, false));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_address_to_pubkey(
  const char* address,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!address || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = solanaAddressToPublicKey(address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(message, message + message_len);
  auto result = signSolanaMessage(msg, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
) {
  if (!message || !signature || signature_len != 64 || !public_key || pubkey_len != 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  ByteVector msg(message, message + message_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = verifySolanaMessage(msg, sig, pubkey);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_derive_pubkey(
  const uint8_t* private_key,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!private_key || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = derivePublicKey(priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

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
) {
  if (!program_id || !address_out || address_size < 44 || !bump_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 prog;
  std::copy(program_id, program_id + 32, prog.begin());

  // Parse seeds
  std::vector<ByteVector> seed_vec;
  if (num_seeds > 0 && seeds && seed_lengths) {
    size_t offset = 0;
    for (size_t i = 0; i < num_seeds; i++) {
      ByteVector seed(seeds + offset, seeds + offset + seed_lengths[i]);
      seed_vec.push_back(std::move(seed));
      offset += seed_lengths[i];
    }
  }

  auto result = findProgramAddress(prog, seed_vec);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.first.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.first.c_str());
  *bump_out = result.value.second;
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_sol_get_associated_token_address(
  const char* wallet_address,
  const char* mint_address,
  char* address_out,
  size_t address_size
) {
  if (!wallet_address || !mint_address || !address_out || address_size < 44) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = getAssociatedTokenAddress(wallet_address, mint_address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
