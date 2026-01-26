/**
 * @file ecdsa.h
 * @brief ECDSA Digital Signature Operations
 *
 * Elliptic Curve Digital Signature Algorithm (ECDSA) implementation
 * for multiple curves:
 * - secp256k1 (Bitcoin, Ethereum)
 * - P-256/secp256r1 (NIST)
 * - P-384/secp384r1 (NIST)
 *
 * Features:
 * - Standard ECDSA signing and verification
 * - Recoverable signatures (for Ethereum, Bitcoin message signing)
 * - Deterministic signatures (RFC 6979)
 * - Low-S normalization (BIP-62)
 */

#ifndef HD_WALLET_ECDSA_H
#define HD_WALLET_ECDSA_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace hd_wallet {
namespace ecdsa {

// =============================================================================
// Signature Formats
// =============================================================================

/**
 * ECDSA signature (R, S components)
 *
 * Standard format: 32 bytes R + 32 bytes S for secp256k1/P-256
 * For P-384: 48 bytes R + 48 bytes S
 */
struct Signature {
    ByteVector r;      ///< R component
    ByteVector s;      ///< S component
    uint8_t v;         ///< Recovery parameter (0 or 1, optional)
    bool hasRecovery;  ///< Whether v is valid

    /// Serialize to compact format (R || S)
    ByteVector compact() const;

    /// Serialize to DER format
    ByteVector der() const;

    /// Parse from compact format (64 bytes for secp256k1/P-256)
    static Result<Signature> fromCompact(const ByteVector& data);

    /// Parse from DER format
    static Result<Signature> fromDer(const ByteVector& data);
};

/// 64-byte compact signature (R || S)
using CompactSignature = std::array<uint8_t, 64>;

/// 65-byte recoverable signature (R || S || V)
using RecoverableSignature = std::array<uint8_t, 65>;

// =============================================================================
// secp256k1 Operations
// =============================================================================

/**
 * Sign message hash with secp256k1
 *
 * Uses RFC 6979 deterministic k generation.
 * Produces low-S normalized signatures per BIP-62.
 *
 * @param privateKey 32-byte private key
 * @param messageHash 32-byte message hash (already hashed)
 * @return Result containing 64-byte compact signature (R || S)
 *
 * @example
 * ```cpp
 * Bytes32 privkey = {...};
 * auto msgHash = sha256(message);
 * auto result = secp256k1Sign(privkey, msgHash);
 * if (result.ok()) {
 *     auto signature = result.value;
 * }
 * ```
 */
Result<CompactSignature> secp256k1Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
);

/**
 * Sign message hash with secp256k1 (recoverable)
 *
 * Returns signature with recovery parameter V (0 or 1).
 * V can be used to recover the public key from signature.
 *
 * @param privateKey 32-byte private key
 * @param messageHash 32-byte message hash
 * @return Result containing 65-byte signature (R || S || V)
 *
 * @note For Ethereum EIP-155, V = 27 + recovery_id + chain_id * 2 + 35
 */
Result<RecoverableSignature> secp256k1SignRecoverable(
    const Bytes32& privateKey,
    const Bytes32& messageHash
);

/**
 * Verify secp256k1 signature
 *
 * @param publicKey 33-byte compressed or 65-byte uncompressed public key
 * @param messageHash 32-byte message hash
 * @param signature 64-byte compact signature
 * @return true if signature is valid
 */
bool secp256k1Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);

bool secp256k1Verify(
    const Bytes33& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);

/**
 * Recover public key from secp256k1 recoverable signature
 *
 * @param messageHash 32-byte message hash
 * @param signature 65-byte recoverable signature (R || S || V)
 * @return Result containing 65-byte uncompressed public key
 *
 * @example
 * ```cpp
 * auto result = secp256k1Recover(msgHash, signature);
 * if (result.ok()) {
 *     auto pubkey = result.value;
 *     // Verify this is the expected public key
 * }
 * ```
 */
Result<Bytes65> secp256k1Recover(
    const Bytes32& messageHash,
    const RecoverableSignature& signature
);

/**
 * Recover compressed public key from secp256k1 recoverable signature
 */
Result<Bytes33> secp256k1RecoverCompressed(
    const Bytes32& messageHash,
    const RecoverableSignature& signature
);

// =============================================================================
// P-256 (secp256r1) Operations
// =============================================================================

/**
 * Sign message hash with P-256 (secp256r1)
 *
 * @param privateKey 32-byte private key
 * @param messageHash 32-byte message hash
 * @return Result containing 64-byte compact signature
 */
Result<CompactSignature> p256Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
);

/**
 * Verify P-256 signature
 *
 * @param publicKey 33-byte compressed or 65-byte uncompressed public key
 * @param messageHash 32-byte message hash
 * @param signature 64-byte compact signature
 * @return true if signature is valid
 */
bool p256Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);

bool p256Verify(
    const Bytes33& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);

// =============================================================================
// P-384 (secp384r1) Operations
// =============================================================================

/// 48-byte P-384 private key
using P384PrivateKey = std::array<uint8_t, 48>;

/// 96-byte P-384 compact signature
using P384Signature = std::array<uint8_t, 96>;

/// 49-byte P-384 compressed public key
using P384CompressedPublicKey = std::array<uint8_t, 49>;

/**
 * Sign message hash with P-384 (secp384r1)
 *
 * @param privateKey 48-byte private key
 * @param messageHash 48-byte message hash (SHA-384)
 * @return Result containing 96-byte compact signature
 */
Result<P384Signature> p384Sign(
    const P384PrivateKey& privateKey,
    const std::array<uint8_t, 48>& messageHash
);

/**
 * Verify P-384 signature
 *
 * @param publicKey P-384 public key
 * @param messageHash 48-byte message hash
 * @param signature 96-byte compact signature
 * @return true if signature is valid
 */
bool p384Verify(
    const ByteVector& publicKey,
    const std::array<uint8_t, 48>& messageHash,
    const P384Signature& signature
);

// =============================================================================
// Signature Utilities
// =============================================================================

/**
 * Normalize signature to low-S form (BIP-62)
 *
 * If S > curve_order/2, replace S with curve_order - S.
 * This eliminates signature malleability.
 *
 * @param signature Signature to normalize (modified in place)
 * @param curve Elliptic curve
 * @return true if signature was modified
 */
bool normalizeSignature(Signature& signature, Curve curve = Curve::SECP256K1);

/**
 * Check if signature is in low-S form
 */
bool isLowS(const Signature& signature, Curve curve = Curve::SECP256K1);

/**
 * Convert DER signature to compact format
 */
Result<CompactSignature> derToCompact(const ByteVector& der);

/**
 * Convert compact signature to DER format
 */
ByteVector compactToDer(const CompactSignature& compact);

// =============================================================================
// Private Key Utilities
// =============================================================================

/**
 * Validate private key
 *
 * Checks that key is:
 * - Non-zero
 * - Less than curve order
 *
 * @param privateKey Private key bytes
 * @param curve Elliptic curve
 * @return true if valid
 */
bool isValidPrivateKey(const Bytes32& privateKey, Curve curve = Curve::SECP256K1);

/**
 * Generate public key from private key
 *
 * @param privateKey 32-byte private key
 * @param curve Elliptic curve
 * @return Result containing 33-byte compressed public key
 */
Result<Bytes33> publicKeyFromPrivate(
    const Bytes32& privateKey,
    Curve curve = Curve::SECP256K1
);

/**
 * Compress public key
 *
 * @param uncompressed 65-byte uncompressed public key
 * @return 33-byte compressed public key
 */
Result<Bytes33> compressPublicKey(const Bytes65& uncompressed);

/**
 * Decompress public key
 *
 * @param compressed 33-byte compressed public key
 * @return 65-byte uncompressed public key
 */
Result<Bytes65> decompressPublicKey(const Bytes33& compressed);

/**
 * Validate public key
 *
 * Checks that public key point is on the curve.
 *
 * @param publicKey Public key (compressed or uncompressed)
 * @param curve Elliptic curve
 * @return true if valid
 */
bool isValidPublicKey(const ByteVector& publicKey, Curve curve = Curve::SECP256K1);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_secp256k1_sign(
    const uint8_t* private_key,
    const uint8_t* message_hash,
    uint8_t* signature_out,
    size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_secp256k1_sign_recoverable(
    const uint8_t* private_key,
    const uint8_t* message_hash,
    uint8_t* signature_out,
    size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_secp256k1_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message_hash,
    const uint8_t* signature,
    size_t signature_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_secp256k1_recover(
    const uint8_t* message_hash,
    const uint8_t* signature,
    size_t signature_len,
    uint8_t* public_key_out,
    size_t public_key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_p256_sign(
    const uint8_t* private_key,
    const uint8_t* message_hash,
    uint8_t* signature_out,
    size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_p256_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message_hash,
    const uint8_t* signature,
    size_t signature_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_p384_sign(
    const uint8_t* private_key,
    const uint8_t* message_hash,
    uint8_t* signature_out,
    size_t signature_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_p384_verify(
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* message_hash,
    const uint8_t* signature,
    size_t signature_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdsa_pubkey_from_privkey(
    const uint8_t* private_key,
    size_t private_key_len,
    int32_t curve,
    uint8_t* public_key_out,
    size_t public_key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdsa_compress_pubkey(
    const uint8_t* public_key,
    size_t public_key_len,
    int32_t curve,
    uint8_t* compressed_out,
    size_t compressed_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdsa_decompress_pubkey(
    const uint8_t* compressed,
    size_t compressed_len,
    int32_t curve,
    uint8_t* public_key_out,
    size_t public_key_size
);

} // namespace ecdsa
} // namespace hd_wallet

#endif // HD_WALLET_ECDSA_H
