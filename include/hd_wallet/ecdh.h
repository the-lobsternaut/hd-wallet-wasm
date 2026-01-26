/**
 * @file ecdh.h
 * @brief Elliptic Curve Diffie-Hellman Key Exchange
 *
 * ECDH key exchange implementations for:
 * - secp256k1 (Bitcoin/Ethereum ecosystem)
 * - P-256/secp256r1 (NIST, TLS)
 * - P-384/secp384r1 (NIST, high security)
 * - X25519 (modern, fast key exchange)
 *
 * ECDH allows two parties to establish a shared secret over an
 * insecure channel. Each party generates a key pair and exchanges
 * public keys. The shared secret is computed as:
 *   shared = privateKey * otherPublicKey
 *
 * @note For actual encryption, the shared secret should be processed
 *       through a KDF like HKDF before use as an encryption key.
 */

#ifndef HD_WALLET_ECDH_H
#define HD_WALLET_ECDH_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <vector>

namespace hd_wallet {
namespace ecdh {

// =============================================================================
// X25519 Constants
// =============================================================================

/// X25519 private key size
constexpr size_t X25519_PRIVATE_KEY_SIZE = 32;

/// X25519 public key size
constexpr size_t X25519_PUBLIC_KEY_SIZE = 32;

/// X25519 shared secret size
constexpr size_t X25519_SHARED_SECRET_SIZE = 32;

// =============================================================================
// Type Aliases
// =============================================================================

/// X25519 private key
using X25519PrivateKey = Bytes32;

/// X25519 public key
using X25519PublicKey = Bytes32;

/// Shared secret (32 bytes for most curves)
using SharedSecret = Bytes32;

// =============================================================================
// secp256k1 ECDH
// =============================================================================

/**
 * Perform ECDH on secp256k1
 *
 * Computes shared secret: SHA256(ECDH_point.x)
 *
 * @param privateKey 32-byte private key
 * @param publicKey 33-byte compressed or 65-byte uncompressed public key
 * @return Result containing 32-byte shared secret
 *
 * @example
 * ```cpp
 * // Alice and Bob each have key pairs
 * Bytes32 alicePrivate = {...};
 * Bytes33 bobPublic = {...};
 *
 * auto result = secp256k1Ecdh(alicePrivate, bobPublic);
 * if (result.ok()) {
 *     auto sharedSecret = result.value;
 *     // Use sharedSecret for symmetric encryption
 * }
 * ```
 */
Result<SharedSecret> secp256k1Ecdh(
    const Bytes32& privateKey,
    const Bytes33& publicKey
);

Result<SharedSecret> secp256k1Ecdh(
    const Bytes32& privateKey,
    const Bytes65& publicKey
);

Result<SharedSecret> secp256k1Ecdh(
    const Bytes32& privateKey,
    const ByteVector& publicKey
);

/**
 * Perform raw ECDH on secp256k1 (no hashing)
 *
 * Returns the raw x-coordinate of the ECDH point.
 * Use this if you want to apply your own KDF.
 *
 * @param privateKey 32-byte private key
 * @param publicKey Public key
 * @return Result containing 32-byte x-coordinate
 */
Result<SharedSecret> secp256k1EcdhRaw(
    const Bytes32& privateKey,
    const ByteVector& publicKey
);

// =============================================================================
// P-256 (secp256r1) ECDH
// =============================================================================

/**
 * Perform ECDH on P-256 (secp256r1)
 *
 * @param privateKey 32-byte private key
 * @param publicKey 33-byte compressed or 65-byte uncompressed public key
 * @return Result containing 32-byte shared secret
 */
Result<SharedSecret> p256Ecdh(
    const Bytes32& privateKey,
    const Bytes33& publicKey
);

Result<SharedSecret> p256Ecdh(
    const Bytes32& privateKey,
    const Bytes65& publicKey
);

Result<SharedSecret> p256Ecdh(
    const Bytes32& privateKey,
    const ByteVector& publicKey
);

// =============================================================================
// P-384 (secp384r1) ECDH
// =============================================================================

/// P-384 private key (48 bytes)
using P384PrivateKey = std::array<uint8_t, 48>;

/// P-384 shared secret (48 bytes)
using P384SharedSecret = std::array<uint8_t, 48>;

/**
 * Perform ECDH on P-384 (secp384r1)
 *
 * @param privateKey 48-byte private key
 * @param publicKey 49-byte compressed or 97-byte uncompressed public key
 * @return Result containing 48-byte shared secret
 */
Result<P384SharedSecret> p384Ecdh(
    const P384PrivateKey& privateKey,
    const ByteVector& publicKey
);

// =============================================================================
// X25519 (Curve25519)
// =============================================================================

/**
 * Generate X25519 public key from private key
 *
 * @param privateKey 32-byte private key
 * @return 32-byte public key
 *
 * @note The private key is clamped internally per X25519 specification
 */
X25519PublicKey x25519PublicKey(const X25519PrivateKey& privateKey);

/**
 * Perform X25519 key exchange
 *
 * @param privateKey 32-byte private key
 * @param publicKey 32-byte public key
 * @return Result containing 32-byte shared secret
 *
 * @example
 * ```cpp
 * // Generate key pairs
 * X25519PrivateKey alicePrivate = {...};  // Random 32 bytes
 * X25519PublicKey alicePublic = x25519PublicKey(alicePrivate);
 *
 * X25519PrivateKey bobPrivate = {...};
 * X25519PublicKey bobPublic = x25519PublicKey(bobPrivate);
 *
 * // Exchange public keys and compute shared secret
 * auto aliceShared = x25519Ecdh(alicePrivate, bobPublic);
 * auto bobShared = x25519Ecdh(bobPrivate, alicePublic);
 * // aliceShared == bobShared
 * ```
 *
 * @note X25519 is NOT FIPS-approved. In FIPS mode, returns FIPS_NOT_ALLOWED.
 */
Result<SharedSecret> x25519Ecdh(
    const X25519PrivateKey& privateKey,
    const X25519PublicKey& publicKey
);

/**
 * Validate X25519 public key
 *
 * Checks for low-order points that would result in zero shared secret.
 *
 * @param publicKey 32-byte public key
 * @return true if public key is safe to use
 */
bool isValidX25519PublicKey(const X25519PublicKey& publicKey);

// =============================================================================
// Key Agreement with KDF
// =============================================================================

/**
 * Perform ECDH and derive key using HKDF
 *
 * Combines ECDH shared secret derivation with HKDF to produce
 * a key suitable for symmetric encryption.
 *
 * @param curve Elliptic curve to use
 * @param privateKey Private key
 * @param publicKey Public key
 * @param salt Optional HKDF salt
 * @param info Optional HKDF info
 * @param keyLength Desired output key length
 * @return Result containing derived key
 *
 * @example
 * ```cpp
 * auto result = ecdhDeriveKey(
 *     Curve::SECP256K1,
 *     myPrivateKey, theirPublicKey,
 *     {}, // no salt
 *     "encryption-key",  // info
 *     32  // 256-bit key
 * );
 * ```
 */
Result<ByteVector> ecdhDeriveKey(
    Curve curve,
    const ByteVector& privateKey,
    const ByteVector& publicKey,
    const ByteVector& salt,
    const ByteVector& info,
    size_t keyLength
);

// =============================================================================
// Ephemeral Key Exchange
// =============================================================================

/**
 * Generate ephemeral key pair for ECDH
 *
 * Creates a random key pair for one-time use in key exchange.
 *
 * @param curve Elliptic curve
 * @return Result containing private and public key
 *
 * @note In WASI environments, requires entropy to be injected first.
 */
struct KeyPair {
    ByteVector privateKey;
    ByteVector publicKey;
};

Result<KeyPair> generateEphemeralKeyPair(Curve curve);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdh_secp256k1(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdh_p256(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdh_p384(
    const uint8_t* private_key,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret_out,
    size_t shared_secret_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdh_x25519(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret_out,
    size_t shared_secret_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_x25519_pubkey(
    const uint8_t* private_key,
    uint8_t* public_key_out,
    size_t public_key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecdh_derive_key(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* key_out,
    size_t key_len
);

} // namespace ecdh
} // namespace hd_wallet

#endif // HD_WALLET_ECDH_H
