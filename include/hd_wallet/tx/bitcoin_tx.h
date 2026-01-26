/**
 * @file bitcoin_tx.h
 * @brief Bitcoin Transaction Types
 *
 * Implementation of Bitcoin transaction building and signing.
 *
 * Features:
 * - Legacy transactions (pre-SegWit)
 * - SegWit transactions (BIP-141)
 * - P2PKH, P2SH, P2WPKH, P2WSH script types
 * - Input/output management
 * - Transaction signing (SIGHASH_ALL, etc.)
 * - TXID and size/vsize calculation
 * - Witness data handling
 *
 * Reference:
 * - BIP-141: Segregated Witness
 * - BIP-143: Transaction Signature Verification for Version 0 Witness Program
 * - BIP-144: Segregated Witness (Peer Services)
 */

#ifndef HD_WALLET_TX_BITCOIN_TX_H
#define HD_WALLET_TX_BITCOIN_TX_H

#include "transaction.h"
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

/// Bitcoin transaction version
constexpr uint32_t BTC_TX_VERSION = 2;

/// Default sequence number (RBF disabled)
constexpr uint32_t SEQUENCE_FINAL = 0xFFFFFFFF;

/// Sequence for RBF (Replace-By-Fee)
constexpr uint32_t SEQUENCE_RBF = 0xFFFFFFFD;

/// SegWit marker and flag
constexpr uint8_t SEGWIT_MARKER = 0x00;
constexpr uint8_t SEGWIT_FLAG = 0x01;

/// Dust threshold (satoshis)
constexpr uint64_t DUST_THRESHOLD = 546;

/// Maximum Bitcoin value (21 million BTC in satoshis)
constexpr uint64_t MAX_MONEY = 2100000000000000ULL;

// =============================================================================
// Script Types
// =============================================================================

/**
 * Bitcoin output script type
 */
enum class ScriptType : uint8_t {
  /// Unknown script type
  UNKNOWN = 0,

  /// Pay-to-Public-Key-Hash (legacy, starts with 1)
  P2PKH = 1,

  /// Pay-to-Script-Hash (starts with 3)
  P2SH = 2,

  /// Pay-to-Witness-Public-Key-Hash (native SegWit, starts with bc1q)
  P2WPKH = 3,

  /// Pay-to-Witness-Script-Hash (native SegWit)
  P2WSH = 4,

  /// Pay-to-Taproot (starts with bc1p)
  P2TR = 5,

  /// Pay-to-Script-Hash wrapping P2WPKH (starts with 3)
  P2SH_P2WPKH = 6,

  /// Pay-to-Script-Hash wrapping P2WSH (starts with 3)
  P2SH_P2WSH = 7,

  /// Null data (OP_RETURN)
  NULLDATA = 8,

  /// Multisig (bare)
  MULTISIG = 9
};

/**
 * Get script type name
 */
const char* scriptTypeName(ScriptType type);

// =============================================================================
// Outpoint
// =============================================================================

/**
 * Transaction outpoint (reference to a previous output)
 */
struct Outpoint {
  /// Previous transaction hash (32 bytes, internal byte order)
  Bytes32 txid;

  /// Output index in previous transaction
  uint32_t vout;

  Outpoint() : txid{}, vout(0) {}
  Outpoint(const Bytes32& hash, uint32_t index) : txid(hash), vout(index) {}

  bool operator==(const Outpoint& other) const {
    return txid == other.txid && vout == other.vout;
  }

  bool operator!=(const Outpoint& other) const {
    return !(*this == other);
  }

  /// Serialize to bytes (36 bytes: 32 + 4)
  ByteVector serialize() const;

  /// Parse from bytes
  static std::optional<Outpoint> parse(const ByteVector& data, size_t& offset);
};

// =============================================================================
// Transaction Input
// =============================================================================

/**
 * Bitcoin transaction input
 */
struct TxInput {
  /// Previous output reference
  Outpoint prevout;

  /// Unlocking script (scriptSig)
  ByteVector scriptSig;

  /// Sequence number
  uint32_t sequence;

  /// Witness data (for SegWit inputs)
  std::vector<ByteVector> witness;

  /// Amount of the previous output (needed for SegWit signing)
  uint64_t amount;

  /// Script type of the previous output
  ScriptType scriptType;

  /// Public key (for signing)
  Bytes33 publicKey;

  /// Redeem script (for P2SH)
  ByteVector redeemScript;

  /// Witness script (for P2WSH)
  ByteVector witnessScript;

  TxInput()
    : prevout()
    , scriptSig()
    , sequence(SEQUENCE_FINAL)
    , witness()
    , amount(0)
    , scriptType(ScriptType::UNKNOWN)
    , publicKey{}
    , redeemScript()
    , witnessScript() {}

  /// Check if this input has witness data
  bool hasWitness() const {
    return !witness.empty();
  }

  /// Check if this input is SegWit
  bool isSegWit() const {
    return scriptType == ScriptType::P2WPKH ||
           scriptType == ScriptType::P2WSH ||
           scriptType == ScriptType::P2SH_P2WPKH ||
           scriptType == ScriptType::P2SH_P2WSH;
  }

  /// Serialize input (without witness)
  ByteVector serialize() const;

  /// Serialize witness data
  ByteVector serializeWitness() const;
};

// =============================================================================
// Transaction Output
// =============================================================================

/**
 * Bitcoin transaction output
 */
struct TxOutput {
  /// Value in satoshis
  uint64_t value;

  /// Locking script (scriptPubKey)
  ByteVector scriptPubKey;

  TxOutput() : value(0), scriptPubKey() {}
  TxOutput(uint64_t val, const ByteVector& script)
    : value(val), scriptPubKey(script) {}

  /// Check if this is a dust output
  bool isDust() const {
    return value < DUST_THRESHOLD;
  }

  /// Get the script type
  ScriptType getScriptType() const;

  /// Serialize output
  ByteVector serialize() const;

  /// Parse from bytes
  static std::optional<TxOutput> parse(const ByteVector& data, size_t& offset);
};

// =============================================================================
// Script Builders
// =============================================================================

/**
 * Build P2PKH scriptPubKey
 * @param pubkeyHash 20-byte public key hash
 */
ByteVector buildP2PKH(const std::array<uint8_t, 20>& pubkeyHash);

/**
 * Build P2PKH scriptPubKey from public key
 * @param publicKey 33-byte compressed public key
 */
ByteVector buildP2PKHFromPubKey(const Bytes33& publicKey);

/**
 * Build P2SH scriptPubKey
 * @param scriptHash 20-byte script hash
 */
ByteVector buildP2SH(const std::array<uint8_t, 20>& scriptHash);

/**
 * Build P2WPKH scriptPubKey (native SegWit)
 * @param pubkeyHash 20-byte public key hash
 */
ByteVector buildP2WPKH(const std::array<uint8_t, 20>& pubkeyHash);

/**
 * Build P2WPKH scriptPubKey from public key
 * @param publicKey 33-byte compressed public key
 */
ByteVector buildP2WPKHFromPubKey(const Bytes33& publicKey);

/**
 * Build P2WSH scriptPubKey
 * @param witnessScriptHash 32-byte witness script hash
 */
ByteVector buildP2WSH(const Bytes32& witnessScriptHash);

/**
 * Build P2SH-P2WPKH scriptPubKey (wrapped SegWit)
 * @param publicKey 33-byte compressed public key
 */
ByteVector buildP2SH_P2WPKH(const Bytes33& publicKey);

/**
 * Build P2SH-P2WPKH redeem script
 * @param publicKey 33-byte compressed public key
 */
ByteVector buildP2SH_P2WPKH_RedeemScript(const Bytes33& publicKey);

/**
 * Build OP_RETURN script
 * @param data Data to embed (max 80 bytes)
 */
ByteVector buildOpReturn(const ByteVector& data);

/**
 * Build P2PKH scriptSig
 * @param signature DER-encoded signature with sighash type
 * @param publicKey 33-byte compressed public key
 */
ByteVector buildP2PKHScriptSig(const ByteVector& signature, const Bytes33& publicKey);

// =============================================================================
// Bitcoin Transaction Class
// =============================================================================

/**
 * Bitcoin transaction
 *
 * Supports both legacy and SegWit transaction formats.
 * Provides methods for building, signing, and serializing transactions.
 */
class BitcoinTransaction : public Transaction {
public:
  /**
   * Create an empty transaction
   */
  BitcoinTransaction();

  /**
   * Create transaction with version
   * @param version Transaction version (default: 2)
   */
  explicit BitcoinTransaction(uint32_t version);

  /**
   * Parse transaction from bytes
   * @param data Serialized transaction
   * @return Parsed transaction or error
   */
  static Result<BitcoinTransaction> parse(const ByteVector& data);

  /**
   * Parse transaction from hex string
   * @param hex Hex-encoded transaction
   * @return Parsed transaction or error
   */
  static Result<BitcoinTransaction> parseHex(const std::string& hex);

  ~BitcoinTransaction() override = default;

  // ----- Input Management -----

  /**
   * Add an input
   * @param txid Previous transaction ID (32 bytes)
   * @param vout Output index
   * @param amount Amount in satoshis (needed for SegWit signing)
   * @param scriptType Script type of the previous output
   * @param publicKey Public key for signing
   * @param sequence Sequence number
   * @return Index of added input
   */
  size_t addInput(
    const Bytes32& txid,
    uint32_t vout,
    uint64_t amount,
    ScriptType scriptType,
    const Bytes33& publicKey,
    uint32_t sequence = SEQUENCE_FINAL
  );

  /**
   * Add an input with full control
   */
  size_t addInput(TxInput&& input);
  size_t addInput(const TxInput& input);

  /**
   * Get input by index
   */
  const TxInput& getInput(size_t index) const;
  TxInput& getInput(size_t index);

  /**
   * Get number of inputs
   */
  size_t inputCount() const { return inputs_.size(); }

  /**
   * Remove input by index
   */
  void removeInput(size_t index);

  /**
   * Clear all inputs
   */
  void clearInputs();

  // ----- Output Management -----

  /**
   * Add an output
   * @param value Amount in satoshis
   * @param scriptPubKey Locking script
   * @return Index of added output
   */
  size_t addOutput(uint64_t value, const ByteVector& scriptPubKey);

  /**
   * Add P2PKH output
   * @param value Amount in satoshis
   * @param pubkeyHash 20-byte public key hash
   */
  size_t addP2PKHOutput(uint64_t value, const std::array<uint8_t, 20>& pubkeyHash);

  /**
   * Add P2WPKH output
   * @param value Amount in satoshis
   * @param pubkeyHash 20-byte public key hash
   */
  size_t addP2WPKHOutput(uint64_t value, const std::array<uint8_t, 20>& pubkeyHash);

  /**
   * Add P2SH output
   * @param value Amount in satoshis
   * @param scriptHash 20-byte script hash
   */
  size_t addP2SHOutput(uint64_t value, const std::array<uint8_t, 20>& scriptHash);

  /**
   * Add OP_RETURN output
   * @param data Data to embed (max 80 bytes)
   */
  size_t addOpReturnOutput(const ByteVector& data);

  /**
   * Add output with full control
   */
  size_t addOutput(TxOutput&& output);
  size_t addOutput(const TxOutput& output);

  /**
   * Get output by index
   */
  const TxOutput& getOutput(size_t index) const;
  TxOutput& getOutput(size_t index);

  /**
   * Get number of outputs
   */
  size_t outputCount() const { return outputs_.size(); }

  /**
   * Remove output by index
   */
  void removeOutput(size_t index);

  /**
   * Clear all outputs
   */
  void clearOutputs();

  // ----- Transaction Properties -----

  /**
   * Get transaction version
   */
  uint32_t version() const { return version_; }

  /**
   * Set transaction version
   */
  void setVersion(uint32_t version) { version_ = version; }

  /**
   * Get locktime
   */
  uint32_t lockTime() const { return lockTime_; }

  /**
   * Set locktime
   */
  void setLockTime(uint32_t lockTime) { lockTime_ = lockTime; }

  /**
   * Check if transaction has any witness data
   */
  bool hasWitness() const;

  /**
   * Get total input value
   */
  uint64_t totalInputValue() const;

  /**
   * Get total output value
   */
  uint64_t totalOutputValue() const;

  /**
   * Calculate fee (input value - output value)
   */
  uint64_t fee() const;

  // ----- Transaction Interface Implementation -----

  TxStatus status() const override { return status_; }

  Result<Bytes32> hash() const override;
  Result<std::string> txid() const override;

  size_t size() const override;
  size_t virtualSize() const override;
  size_t weight() const override;

  Result<ByteVector> serialize() const override;

  /**
   * Serialize without witness (legacy format)
   */
  Result<ByteVector> serializeLegacy() const;

  /**
   * Serialize with witness (SegWit format)
   */
  Result<ByteVector> serializeWitness() const;

  Error sign(const Bytes32& privateKey, int inputIndex = -1) override;

  /**
   * Sign a specific input
   * @param inputIndex Index of input to sign
   * @param privateKey Private key for signing
   * @param sigHashType Signature hash type
   * @return Error code
   */
  Error signInput(
    size_t inputIndex,
    const Bytes32& privateKey,
    SigHashType sigHashType = SigHashType::ALL
  );

  bool verify() const override;

  Error validate() const override;

  std::unique_ptr<Transaction> clone() const override;

  // ----- Signature Hash Calculation -----

  /**
   * Calculate signature hash for legacy input
   * @param inputIndex Input index to sign
   * @param scriptCode Script to sign (usually scriptPubKey)
   * @param sigHashType Signature hash type
   * @return 32-byte signature hash
   */
  Result<Bytes32> signatureHashLegacy(
    size_t inputIndex,
    const ByteVector& scriptCode,
    SigHashType sigHashType
  ) const;

  /**
   * Calculate signature hash for SegWit input (BIP-143)
   * @param inputIndex Input index to sign
   * @param scriptCode Script to sign
   * @param value Value of the input being signed
   * @param sigHashType Signature hash type
   * @return 32-byte signature hash
   */
  Result<Bytes32> signatureHashSegWit(
    size_t inputIndex,
    const ByteVector& scriptCode,
    uint64_t value,
    SigHashType sigHashType
  ) const;

private:
  uint32_t version_;
  uint32_t lockTime_;
  std::vector<TxInput> inputs_;
  std::vector<TxOutput> outputs_;
  TxStatus status_;

  // Cached values for BIP-143
  mutable std::optional<Bytes32> hashPrevouts_;
  mutable std::optional<Bytes32> hashSequence_;
  mutable std::optional<Bytes32> hashOutputs_;

  void invalidateCache();

  // BIP-143 precomputed hashes
  Bytes32 computeHashPrevouts() const;
  Bytes32 computeHashSequence() const;
  Bytes32 computeHashOutputs() const;
};

// =============================================================================
// C API for WASM Bindings
// =============================================================================

/// Opaque handle for BitcoinTransaction
typedef struct btc_tx_t* btc_tx_handle;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
btc_tx_handle hd_btc_tx_create();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
btc_tx_handle hd_btc_tx_create_v(uint32_t version);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_add_input(
  btc_tx_handle tx,
  const uint8_t* txid,
  uint32_t vout,
  uint64_t amount,
  int32_t script_type,
  const uint8_t* pubkey,
  uint32_t sequence
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_add_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* script,
  size_t script_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_add_p2pkh_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* pubkey_hash
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_add_p2wpkh_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* pubkey_hash
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_sign(
  btc_tx_handle tx,
  const uint8_t* privkey,
  int32_t input_index
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_sign_input(
  btc_tx_handle tx,
  size_t input_index,
  const uint8_t* privkey,
  uint8_t sighash_type
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_serialize(
  btc_tx_handle tx,
  uint8_t* out,
  size_t out_size,
  size_t* actual_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_get_txid(
  btc_tx_handle tx,
  uint8_t* txid_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_get_txid_hex(
  btc_tx_handle tx,
  char* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
size_t hd_btc_tx_get_size(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
size_t hd_btc_tx_get_vsize(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
size_t hd_btc_tx_get_weight(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint64_t hd_btc_tx_get_fee(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_tx_validate(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_btc_tx_destroy(btc_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
btc_tx_handle hd_btc_tx_parse(
  const uint8_t* data,
  size_t data_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
btc_tx_handle hd_btc_tx_parse_hex(const char* hex);

} // namespace tx
} // namespace hd_wallet

#endif // HD_WALLET_TX_BITCOIN_TX_H
