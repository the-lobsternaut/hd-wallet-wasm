/**
 * @file eddsa.h
 * @brief EdDSA Digital Signature Operations
 *
 * Edwards-curve Digital Signature Algorithm (EdDSA) implementation
 * using Ed25519 (Curve25519 in Edwards form).
 *
 * Features:
 * - Ed25519 signing and verification
 * - Ed25519ph (pre-hashed) for large messages
 * - Ed25519ctx (context) for domain separation
 *
 * Used by:
 * - Solana
 * - Polkadot (alternative to Sr25519)
 * - Cardano
 * - Stellar
 * - NEAR Protocol
 * - Aptos/Sui
 *
 * @note Ed25519 is NOT FIPS-approved. In FIPS mode, these functions
 *       will return FIPS_NOT_ALLOWED error.
 */

#ifndef HD_WALLET_EDDSA_H
#define HD_WALLET_EDDSA_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hd_wallet {
namespace eddsa {

// =============================================================================
// Ed25519 Constants
// =============================================================================

/// Ed25519 private key size (seed)
constexpr size_t ED25519_SEED_SIZE = 32;

/// Ed25519 expanded private key size (64 bytes)
constexpr size_t ED25519_PRIVATE_KEY_SIZE = 64;

/// Ed25519 public key size
constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;

/// Ed25519 signature size
constexpr size_t ED25519_SIGNATURE_SIZE = 64;

// =============================================================================
// Type Aliases
// =============================================================================

/// Ed25519 seed (32 bytes, used as private key input)
using Ed25519Seed = Bytes32;

/// Ed25519 public key (32 bytes)
using Ed25519PublicKey = Bytes32;

/// Ed25519 signature (64 bytes)
using Ed25519Signature = Bytes64;

/// Ed25519 expanded private key (64 bytes: scalar + prefix)
using Ed25519ExpandedKey = Bytes64;

// =============================================================================
// Key Generation
// =============================================================================

/**
 * Generate Ed25519 public key from seed
 *
 * The seed is the 32-byte private key input. Internally, it is
 * hashed with SHA-512 to produce the actual scalar and prefix.
 *
 * @param seed 32-byte seed (private key)
 * @return 32-byte public key
 *
 * @example
 * ```cpp
 * Bytes32 seed = {...};  // From BIP-39/SLIP-10 derivation
 * auto pubkey = ed25519PublicKeyFromSeed(seed);
 * ```
 */
Ed25519PublicKey ed25519PublicKeyFromSeed(const Ed25519Seed& seed);

/**
 * Expand Ed25519 seed to full private key
 *
 * Performs SHA-512 on seed and clamps the first 32 bytes
 * as the scalar, keeping the last 32 bytes as the prefix.
 *
 * @param seed 32-byte seed
 * @return 64-byte expanded private key
 */
Ed25519ExpandedKey ed25519ExpandKey(const Ed25519Seed& seed);

/**
 * Validate Ed25519 seed
 *
 * Ed25519 accepts any 32-byte value as a valid seed.
 * This function just checks the length.
 *
 * @param seed Seed bytes
 * @return true if valid (32 bytes)
 */
bool isValidEd25519Seed(const ByteVector& seed);

/**
 * Validate Ed25519 public key
 *
 * Checks that the public key is a valid point on the curve.
 *
 * @param publicKey Public key bytes
 * @return true if valid
 */
bool isValidEd25519PublicKey(const ByteVector& publicKey);

// =============================================================================
// Ed25519 Signing
// =============================================================================

/**
 * Sign message with Ed25519
 *
 * @param seed 32-byte seed (private key)
 * @param message Message to sign (any length)
 * @param messageLength Message length
 * @return 64-byte signature
 *
 * @note This is pure Ed25519, not Ed25519ph. The message is
 *       included directly in the signature computation.
 *
 * @example
 * ```cpp
 * Ed25519Seed seed = {...};
 * const char* msg = "Hello, World!";
 * auto sig = ed25519Sign(seed, reinterpret_cast<const uint8_t*>(msg), strlen(msg));
 * ```
 */
Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const uint8_t* message,
    size_t messageLength
);

Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const ByteVector& message
);

Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const std::string& message
);

/**
 * Sign pre-hashed message with Ed25519ph
 *
 * Ed25519ph (pre-hashed) variant that takes a 64-byte SHA-512 hash
 * instead of the raw message. Useful for very large messages.
 *
 * @param seed 32-byte seed
 * @param messageHash 64-byte SHA-512 hash of message
 * @return 64-byte signature
 */
Ed25519Signature ed25519phSign(
    const Ed25519Seed& seed,
    const Bytes64& messageHash
);

/**
 * Sign message with Ed25519ctx (context)
 *
 * Ed25519ctx variant that includes a context string for domain separation.
 * Context must be at most 255 bytes.
 *
 * @param seed 32-byte seed
 * @param message Message to sign
 * @param messageLength Message length
 * @param context Context string (max 255 bytes)
 * @param contextLength Context length
 * @return 64-byte signature
 */
Ed25519Signature ed25519ctxSign(
    const Ed25519Seed& seed,
    const uint8_t* message,
    size_t messageLength,
    const uint8_t* context,
    size_t contextLength
);

// =============================================================================
// Ed25519 Verification
// =============================================================================

/**
 * Verify Ed25519 signature
 *
 * @param publicKey 32-byte public key
 * @param message Original message
 * @param messageLength Message length
 * @param signature 64-byte signature
 * @return true if signature is valid
 *
 * @example
 * ```cpp
 * Ed25519PublicKey pubkey = {...};
 * Ed25519Signature sig = {...};
 * bool valid = ed25519Verify(pubkey, message.data(), message.size(), sig);
 * ```
 */
bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const uint8_t* message,
    size_t messageLength,
    const Ed25519Signature& signature
);

bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const ByteVector& message,
    const Ed25519Signature& signature
);

bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const std::string& message,
    const Ed25519Signature& signature
);

/**
 * Verify Ed25519ph signature
 *
 * @param publicKey 32-byte public key
 * @param messageHash 64-byte SHA-512 hash of message
 * @param signature 64-byte signature
 * @return true if signature is valid
 */
bool ed25519phVerify(
    const Ed25519PublicKey& publicKey,
    const Bytes64& messageHash,
    const Ed25519Signature& signature
);

/**
 * Verify Ed25519ctx signature
 *
 * @param publicKey 32-byte public key
 * @param message Original message
 * @param messageLength Message length
 * @param context Context string
 * @param contextLength Context length
 * @param signature 64-byte signature
 * @return true if signature is valid
 */
bool ed25519ctxVerify(
    const Ed25519PublicKey& publicKey,
    const uint8_t* message,
    size_t messageLength,
    const uint8_t* context,
    size_t contextLength,
    const Ed25519Signature& signature
);

// =============================================================================
// SLIP-10 Ed25519 Key Derivation
// =============================================================================

/**
 * Derive Ed25519 master key from seed using SLIP-10
 *
 * SLIP-10 defines Ed25519 key derivation compatible with BIP-32 paths.
 * Only hardened derivation is allowed for Ed25519.
 *
 * @param seed 64-byte seed (from BIP-39)
 * @return Result containing 32-byte Ed25519 seed and 32-byte chain code
 */
struct Ed25519DerivedKey {
    Ed25519Seed key;
    Bytes32 chainCode;
};

Result<Ed25519DerivedKey> slip10Ed25519Master(const Bytes64& seed);

/**
 * Derive child Ed25519 key using SLIP-10
 *
 * @param parentKey Parent key
 * @param parentChainCode Parent chain code
 * @param index Child index (must be hardened, >= 0x80000000)
 * @return Result containing derived key and chain code
 */
Result<Ed25519DerivedKey> slip10Ed25519DeriveChild(
    const Ed25519Seed& parentKey,
    const Bytes32& parentChainCode,
    uint32_t index
);

/**
 * Derive Ed25519 key at path using SLIP-10
 *
 * @param seed 64-byte seed
 * @param path Derivation path (e.g., "m/44'/501'/0'/0'")
 * @return Result containing derived key and chain code
 *
 * @note All path components must be hardened for Ed25519
 */
Result<Ed25519DerivedKey> slip10Ed25519DerivePath(
    const Bytes64& seed,
    const std::string& path
);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ed25519_pubkey_from_seed(
    const uint8_t* seed,
    uint8_t* public_key_out,
    size_t public_key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ed25519_sign(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out,
    size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ed25519_verify(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ed25519_expand_key(
    const uint8_t* seed,
    uint8_t* expanded_out,
    size_t expanded_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_slip10_ed25519_master(
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* key_out,
    uint8_t* chain_code_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_slip10_ed25519_derive_path(
    const uint8_t* seed,
    size_t seed_len,
    const char* path,
    uint8_t* key_out,
    uint8_t* chain_code_out
);

} // namespace eddsa
} // namespace hd_wallet

#endif // HD_WALLET_EDDSA_H
