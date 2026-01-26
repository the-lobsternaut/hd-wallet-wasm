/**
 * @file bitcoin.h
 * @brief Bitcoin Support
 *
 * Provides Bitcoin address generation, validation, and message signing.
 *
 * Supported address types:
 * - P2PKH: Pay-to-Public-Key-Hash (1...)
 * - P2SH: Pay-to-Script-Hash (3...)
 * - P2WPKH: Native SegWit v0 (bc1q...)
 * - P2WSH: Pay-to-Witness-Script-Hash (bc1q... 62 chars)
 * - P2TR: Taproot (bc1p...)
 *
 * Message signing follows Bitcoin Signed Message format:
 * "Bitcoin Signed Message:\n" + message
 */

#ifndef HD_WALLET_BITCOIN_H
#define HD_WALLET_BITCOIN_H

#include "coin.h"

namespace hd_wallet {
namespace coins {

// =============================================================================
// Bitcoin Network Parameters
// =============================================================================

/**
 * Bitcoin network version bytes and parameters
 */
struct BitcoinParams {
  /// P2PKH address version (mainnet: 0x00, testnet: 0x6F)
  uint8_t p2pkh_version;

  /// P2SH address version (mainnet: 0x05, testnet: 0xC4)
  uint8_t p2sh_version;

  /// Bech32 human-readable part (mainnet: "bc", testnet: "tb")
  const char* bech32_hrp;

  /// WIF private key version (mainnet: 0x80, testnet: 0xEF)
  uint8_t wif_version;

  /// Extended private key version (xprv/tprv)
  uint32_t xprv_version;

  /// Extended public key version (xpub/tpub)
  uint32_t xpub_version;

  /// BIP-49 extended private key version (yprv)
  uint32_t yprv_version;

  /// BIP-49 extended public key version (ypub)
  uint32_t ypub_version;

  /// BIP-84 extended private key version (zprv)
  uint32_t zprv_version;

  /// BIP-84 extended public key version (zpub)
  uint32_t zpub_version;
};

/// Bitcoin mainnet parameters
extern const BitcoinParams BITCOIN_MAINNET;

/// Bitcoin testnet parameters
extern const BitcoinParams BITCOIN_TESTNET;

// =============================================================================
// Bitcoin Address Generation
// =============================================================================

/**
 * Generate P2PKH address (1...)
 * @param public_key Compressed (33-byte) or uncompressed (65-byte) public key
 * @param params Network parameters
 * @return P2PKH address string
 */
Result<std::string> bitcoinP2PKH(const ByteVector& public_key, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Generate P2SH address (3...)
 * Creates P2SH-P2WPKH (wrapped SegWit) address
 * @param public_key Compressed (33-byte) public key
 * @param params Network parameters
 * @return P2SH address string
 */
Result<std::string> bitcoinP2SH(const Bytes33& public_key, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Generate P2SH address from redeem script
 * @param redeem_script The redeem script
 * @param params Network parameters
 * @return P2SH address string
 */
Result<std::string> bitcoinP2SHFromScript(const ByteVector& redeem_script, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Generate P2WPKH address (bc1q...)
 * Native SegWit v0 address for single public key
 * @param public_key Compressed (33-byte) public key
 * @param params Network parameters
 * @return Bech32 P2WPKH address string
 */
Result<std::string> bitcoinP2WPKH(const Bytes33& public_key, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Generate P2WSH address (bc1q... 62 chars)
 * Native SegWit v0 address for scripts
 * @param witness_script The witness script
 * @param params Network parameters
 * @return Bech32 P2WSH address string
 */
Result<std::string> bitcoinP2WSH(const ByteVector& witness_script, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Generate P2TR address (bc1p...)
 * Taproot address (SegWit v1)
 * @param public_key 32-byte x-only public key or 33-byte compressed public key
 * @param params Network parameters
 * @return Bech32m P2TR address string
 */
Result<std::string> bitcoinP2TR(const ByteVector& public_key, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Convert compressed public key to x-only format for Taproot
 * @param public_key 33-byte compressed public key
 * @return 32-byte x-only public key
 */
Result<Bytes32> toXOnlyPublicKey(const Bytes33& public_key);

// =============================================================================
// Bitcoin Address Validation
// =============================================================================

/**
 * Detect Bitcoin address type
 * @param address Address string
 * @param params Network parameters
 * @return Address type
 */
Result<BitcoinAddressType> detectBitcoinAddressType(
  const std::string& address,
  const BitcoinParams& params = BITCOIN_MAINNET
);

/**
 * Validate P2PKH address
 */
Result<void> validateP2PKH(const std::string& address, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Validate P2SH address
 */
Result<void> validateP2SH(const std::string& address, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Validate P2WPKH address
 */
Result<void> validateP2WPKH(const std::string& address, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Validate P2WSH address
 */
Result<void> validateP2WSH(const std::string& address, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Validate P2TR address
 */
Result<void> validateP2TR(const std::string& address, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Validate any Bitcoin address type
 */
Result<void> validateBitcoinAddress(
  const std::string& address,
  const BitcoinParams& params = BITCOIN_MAINNET
);

/**
 * Decode Bitcoin address to script pubkey
 * @param address Address string
 * @param params Network parameters
 * @return Script pubkey bytes
 */
Result<ByteVector> decodeToScriptPubKey(
  const std::string& address,
  const BitcoinParams& params = BITCOIN_MAINNET
);

// =============================================================================
// Bitcoin Message Signing
// =============================================================================

/**
 * Sign a message using Bitcoin Signed Message format
 *
 * Format: SHA256(SHA256("Bitcoin Signed Message:\n" + varint(len) + message))
 *
 * @param message Message to sign
 * @param private_key 32-byte private key
 * @param compressed Whether to use compressed public key (affects recovery)
 * @return 65-byte signature (1 byte header + 32 bytes r + 32 bytes s)
 */
Result<ByteVector> signBitcoinMessage(
  const std::string& message,
  const Bytes32& private_key,
  bool compressed = true
);

/**
 * Verify a Bitcoin signed message
 *
 * @param message Original message
 * @param signature 65-byte signature
 * @param address Bitcoin address to verify against
 * @param params Network parameters
 * @return true if signature is valid for the address
 */
Result<bool> verifyBitcoinMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address,
  const BitcoinParams& params = BITCOIN_MAINNET
);

/**
 * Recover public key from Bitcoin message signature
 *
 * @param message Original message
 * @param signature 65-byte signature
 * @return Recovered public key (compressed or uncompressed based on signature)
 */
Result<ByteVector> recoverBitcoinMessageSigner(
  const std::string& message,
  const ByteVector& signature
);

/**
 * Compute Bitcoin message hash
 * @param message Message to hash
 * @return 32-byte hash
 */
Bytes32 bitcoinMessageHash(const std::string& message);

// =============================================================================
// WIF (Wallet Import Format)
// =============================================================================

/**
 * Encode private key as WIF
 * @param private_key 32-byte private key
 * @param compressed Whether to use compressed public key
 * @param params Network parameters
 * @return WIF-encoded private key
 */
std::string toWIF(const Bytes32& private_key, bool compressed = true, const BitcoinParams& params = BITCOIN_MAINNET);

/**
 * Decode WIF private key
 * @param wif WIF string
 * @param compressed Output: whether compressed flag was set
 * @return Private key and network parameters
 */
Result<std::pair<Bytes32, bool>> fromWIF(const std::string& wif);

// =============================================================================
// Bitcoin Coin Implementation
// =============================================================================

/**
 * Bitcoin coin implementation
 */
class Bitcoin : public Coin {
public:
  explicit Bitcoin(Network network = Network::MAINNET);

  // ----- Identification -----
  CoinType coinType() const override { return CoinType::BITCOIN; }
  const char* name() const override { return "Bitcoin"; }
  const char* symbol() const override { return "BTC"; }
  Curve curve() const override { return Curve::SECP256K1; }

  // ----- Network -----
  Network network() const override { return network_; }
  void setNetwork(Network net) override;

  /// Get current network parameters
  const BitcoinParams& params() const { return *params_; }

  // ----- Address Types -----

  /// Get/set preferred address type
  BitcoinAddressType addressType() const { return address_type_; }
  void setAddressType(BitcoinAddressType type) { address_type_ = type; }

  // ----- Address Generation -----
  Result<std::string> addressFromPublicKey(const Bytes33& public_key) const override;
  Result<std::string> addressFromPublicKeyUncompressed(const Bytes65& public_key) const override;

  /// Generate specific address type
  Result<std::string> p2pkhAddress(const Bytes33& public_key) const;
  Result<std::string> p2shAddress(const Bytes33& public_key) const;
  Result<std::string> p2wpkhAddress(const Bytes33& public_key) const;
  Result<std::string> p2wshAddress(const ByteVector& witness_script) const;
  Result<std::string> p2trAddress(const Bytes33& public_key) const;

  // ----- Address Validation -----
  Error validateAddress(const std::string& address) const override;
  Result<DecodedAddress> decodeAddress(const std::string& address) const override;

  /// Detect address type
  Result<BitcoinAddressType> detectAddressType(const std::string& address) const;

  // ----- Message Signing -----
  Result<ByteVector> signMessage(const ByteVector& message, const Bytes32& private_key) const override;
  Result<bool> verifyMessage(
    const ByteVector& message,
    const ByteVector& signature,
    const ByteVector& public_key
  ) const override;

  // ----- Derivation Path -----
  std::string getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const override;
  uint32_t defaultPurpose() const override;

private:
  Network network_;
  const BitcoinParams* params_;
  BitcoinAddressType address_type_;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2pkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2sh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wpkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wsh_address(
  const uint8_t* witness_script,
  size_t script_len,
  int32_t network,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2tr_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_validate_address(
  const char* address,
  int32_t network
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_detect_address_type(
  const char* address,
  int32_t network
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_sign_message(
  const char* message,
  const uint8_t* private_key,
  int32_t compressed,
  uint8_t* signature_out,
  size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_verify_message(
  const char* message,
  const uint8_t* signature,
  size_t signature_len,
  const char* address,
  int32_t network
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_to_wif(
  const uint8_t* private_key,
  int32_t compressed,
  int32_t network,
  char* wif_out,
  size_t wif_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_from_wif(
  const char* wif,
  uint8_t* private_key_out,
  int32_t* compressed_out
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_BITCOIN_H
