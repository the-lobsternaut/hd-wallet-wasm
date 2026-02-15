/**
 * @file eddsa.h
 * @brief EdDSA Digital Signature Operations
 *
 * Edwards-curve Digital Signature Algorithm (EdDSA) implementation
 * using Ed25519 (Curve25519 in Edwards form).
 *
 * Features:
 * - Ed25519 signing and verification
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
