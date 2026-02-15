/**
 * @file ecies.h
 * @brief Elliptic Curve Integrated Encryption Scheme (ECIES)
 *
 * Unified ECIES API combining ECDH key agreement, HKDF key derivation,
 * and AES-256-GCM authenticated encryption into a single encrypt/decrypt
 * interface.
 *
 * Supported curves:
 * - secp256k1 (Bitcoin/Ethereum ecosystem)
 * - P-256/secp256r1 (NIST, FIPS-approved)
 * - P-384/secp384r1 (NIST, FIPS-approved)
 * - X25519 (modern, fast)
 *
 * Algorithm:
 *   Encrypt:
 *     1. Generate ephemeral key pair
 *     2. ECDH(ephemeralPrivate, recipientPublic) -> sharedSecret
 *     3. HKDF-SHA256(sharedSecret, salt, info) -> aesKey (32 bytes)
 *     4. AES-256-GCM(aesKey, randomIV, plaintext, aad) -> (ciphertext, tag)
 *     5. Output: ephemeralPublic || iv || ciphertext || tag
 *
 *   Decrypt:
 *     1. Parse ephemeralPublic, iv, ciphertext, tag from message
 *     2. ECDH(recipientPrivate, ephemeralPublic) -> sharedSecret
 *     3. HKDF-SHA256(sharedSecret, salt, info) -> aesKey
 *     4. AES-256-GCM-Decrypt(aesKey, iv, ciphertext, tag, aad) -> plaintext
 *
 * Wire Format:
 *   [ephemeral_public_key][iv (12 bytes)][ciphertext (N bytes)][tag (16 bytes)]
 *
 *   Overhead per curve:
 *     secp256k1: 33 + 12 + 16 = 61 bytes
 *     P-256:     33 + 12 + 16 = 61 bytes
 *     P-384:     49 + 12 + 16 = 77 bytes
 *     X25519:    32 + 12 + 16 = 60 bytes
 *
 * FIPS Mode:
 *   When HD_WALLET_FIPS_MODE is enabled, only P-256 and P-384 are allowed.
 *   HKDF and AES-GCM are routed through OpenSSL FIPS provider automatically.
 */

#ifndef HD_WALLET_ECIES_H
#define HD_WALLET_ECIES_H

#include "config.h"
#include "types.h"

#include <cstdint>
#include <vector>

namespace hd_wallet {
namespace ecies {

// =============================================================================
// Constants
// =============================================================================

/// AES-256-GCM IV size
constexpr size_t ECIES_IV_SIZE = 12;

/// AES-256-GCM tag size
constexpr size_t ECIES_TAG_SIZE = 16;

/// AES-256 key size
constexpr size_t ECIES_KEY_SIZE = 32;

/// HKDF salt used for ECIES key derivation
constexpr const char* ECIES_HKDF_SALT = "ecies";

// =============================================================================
// Overhead Calculation
// =============================================================================

/**
 * Get the ephemeral public key size for a curve
 *
 * @param curve Elliptic curve
 * @return Public key size in bytes, or 0 if curve not supported
 */
size_t eciesEphemeralKeySize(Curve curve);

/**
 * Get total ECIES overhead (ephemeral key + IV + tag)
 *
 * @param curve Elliptic curve
 * @return Overhead in bytes, or 0 if curve not supported
 */
size_t eciesOverhead(Curve curve);

// =============================================================================
// Unified ECIES Encrypt / Decrypt
// =============================================================================

/**
 * ECIES Encrypt
 *
 * Encrypts plaintext for a recipient using their public key.
 * Generates an ephemeral key pair internally and outputs the
 * serialized wire format.
 *
 * @param curve Elliptic curve to use
 * @param recipientPubKey Recipient's public key (compressed)
 * @param recipientPubKeyLen Public key length
 * @param plaintext Data to encrypt
 * @param plaintextLen Plaintext length
 * @param aad Additional authenticated data (optional, can be nullptr)
 * @param aadLen AAD length
 * @param out Output buffer (must be at least plaintextLen + eciesOverhead(curve))
 * @param outSize Output buffer size
 * @return Bytes written on success, negative error code on failure
 */
int32_t eciesEncrypt(
    Curve curve,
    const uint8_t* recipientPubKey,
    size_t recipientPubKeyLen,
    const uint8_t* plaintext,
    size_t plaintextLen,
    const uint8_t* aad,
    size_t aadLen,
    uint8_t* out,
    size_t outSize
);

/**
 * ECIES Decrypt
 *
 * Decrypts an ECIES message using the recipient's private key.
 * Parses the wire format and returns the plaintext.
 *
 * @param curve Elliptic curve to use
 * @param recipientPrivKey Recipient's private key
 * @param recipientPrivKeyLen Private key length
 * @param message ECIES encrypted message (wire format)
 * @param messageLen Message length
 * @param aad Additional authenticated data (must match encryption AAD)
 * @param aadLen AAD length
 * @param out Output buffer for plaintext
 * @param outSize Output buffer size (must be at least messageLen - eciesOverhead(curve))
 * @return Plaintext bytes written on success, negative error code on failure
 */
int32_t eciesDecrypt(
    Curve curve,
    const uint8_t* recipientPrivKey,
    size_t recipientPrivKeyLen,
    const uint8_t* message,
    size_t messageLen,
    const uint8_t* aad,
    size_t aadLen,
    uint8_t* out,
    size_t outSize
);

// =============================================================================
// AES-CTR (Standalone)
// =============================================================================

/// AES-CTR IV size (16 bytes = AES block size)
constexpr size_t AES_CTR_IV_SIZE = 16;

/**
 * AES-CTR Encrypt
 *
 * Counter mode encryption. No authentication — pair with HMAC if integrity
 * is needed. Supports AES-128, AES-192, and AES-256 (key size selects variant).
 *
 * @param key AES key (16, 24, or 32 bytes)
 * @param keyLen Key length (determines AES variant)
 * @param plaintext Data to encrypt
 * @param plaintextLen Plaintext length
 * @param iv 16-byte initialization vector / nonce
 * @param ivLen IV length (must be 16)
 * @param out Output buffer (must be at least plaintextLen bytes)
 * @param outSize Output buffer size
 * @return Bytes written on success, negative error code on failure
 */
int32_t aesCtrEncrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* plaintext, size_t plaintextLen,
    const uint8_t* iv, size_t ivLen,
    uint8_t* out, size_t outSize
);

/**
 * AES-CTR Decrypt
 *
 * Counter mode decryption (symmetric with encrypt).
 *
 * @param key AES key (16, 24, or 32 bytes)
 * @param keyLen Key length (determines AES variant)
 * @param ciphertext Data to decrypt
 * @param ciphertextLen Ciphertext length
 * @param iv 16-byte initialization vector / nonce (must match encryption IV)
 * @param ivLen IV length (must be 16)
 * @param out Output buffer (must be at least ciphertextLen bytes)
 * @param outSize Output buffer size
 * @return Bytes written on success, negative error code on failure
 */
int32_t aesCtrDecrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* ciphertext, size_t ciphertextLen,
    const uint8_t* iv, size_t ivLen,
    uint8_t* out, size_t outSize
);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecies_encrypt(
    int32_t curve,
    const uint8_t* recipient_pubkey,
    size_t pubkey_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out,
    size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecies_decrypt(
    int32_t curve,
    const uint8_t* recipient_privkey,
    size_t privkey_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out,
    size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ecies_overhead(int32_t curve);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aes_ctr_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* out, size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aes_ctr_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* out, size_t out_size
);

} // namespace ecies
} // namespace hd_wallet

#endif // HD_WALLET_ECIES_H
