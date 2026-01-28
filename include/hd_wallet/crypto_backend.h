/**
 * @file crypto_backend.h
 * @brief Crypto Backend Abstraction Layer
 *
 * Provides compile-time backend selection for cryptographic operations.
 * When HD_WALLET_USE_OPENSSL is defined, FIPS-approved algorithms are
 * routed through OpenSSL. Non-FIPS algorithms always use Crypto++.
 *
 * Algorithm Routing:
 *
 * | Algorithm           | OpenSSL Mode       | Default Mode    |
 * |---------------------|-------------------|-----------------|
 * | SHA-256/384/512     | OpenSSL           | Crypto++        |
 * | HMAC-SHA256/512     | OpenSSL           | Crypto++        |
 * | HKDF-SHA256/384     | OpenSSL           | Crypto++        |
 * | PBKDF2-SHA512       | OpenSSL           | Crypto++        |
 * | AES-256-GCM         | OpenSSL           | Crypto++        |
 * | ECDSA P-256/P-384   | OpenSSL           | Crypto++        |
 * | ECDH P-256/P-384    | OpenSSL           | Crypto++        |
 * | secp256k1           | Crypto++ (always) | Crypto++        |
 * | Ed25519             | Crypto++ (always) | Crypto++        |
 * | X25519              | Crypto++ (always) | Crypto++        |
 * | Keccak-256          | Crypto++ (always) | Crypto++        |
 * | BLAKE2b/s           | Crypto++ (always) | Crypto++        |
 * | RIPEMD-160          | Crypto++ (always) | Crypto++        |
 * | scrypt              | Crypto++ (always) | Crypto++        |
 */

#ifndef HD_WALLET_CRYPTO_BACKEND_H
#define HD_WALLET_CRYPTO_BACKEND_H

#include "hd_wallet/config.h"

#ifdef HD_WALLET_USE_OPENSSL

// =============================================================================
// OpenSSL Backend Active
// =============================================================================

#include "hd_wallet/crypto_openssl.h"

// -----------------------------------------------------------------------------
// Hash Functions
// Route SHA-256/384/512 through OpenSSL
// -----------------------------------------------------------------------------

#define HD_BACKEND_SHA256(data, len, out) \
    hd_ossl_sha256(data, len, out)

#define HD_BACKEND_SHA384(data, len, out) \
    hd_ossl_sha384(data, len, out)

#define HD_BACKEND_SHA512(data, len, out) \
    hd_ossl_sha512(data, len, out)

// -----------------------------------------------------------------------------
// HMAC Functions
// Route HMAC-SHA256/512 through OpenSSL
// -----------------------------------------------------------------------------

#define HD_BACKEND_HMAC_SHA256(key, klen, data, dlen, out) \
    hd_ossl_hmac_sha256(key, klen, data, dlen, out)

#define HD_BACKEND_HMAC_SHA512(key, klen, data, dlen, out) \
    hd_ossl_hmac_sha512(key, klen, data, dlen, out)

// -----------------------------------------------------------------------------
// Key Derivation Functions
// Route HKDF, PBKDF2 through OpenSSL
// -----------------------------------------------------------------------------

#define HD_BACKEND_HKDF_SHA256(ikm, ikm_len, salt, salt_len, info, info_len, okm, okm_len) \
    hd_ossl_hkdf_sha256(ikm, ikm_len, salt, salt_len, info, info_len, okm, okm_len)

#define HD_BACKEND_HKDF_SHA384(ikm, ikm_len, salt, salt_len, info, info_len, okm, okm_len) \
    hd_ossl_hkdf_sha384(ikm, ikm_len, salt, salt_len, info, info_len, okm, okm_len)

#define HD_BACKEND_PBKDF2_SHA512(pwd, pwd_len, salt, salt_len, iter, out, out_len) \
    hd_ossl_pbkdf2_sha512(pwd, pwd_len, salt, salt_len, iter, out, out_len)

// -----------------------------------------------------------------------------
// AES-GCM
// Route through OpenSSL
// -----------------------------------------------------------------------------

#define HD_BACKEND_AES_GCM_ENCRYPT(key, key_len, pt, pt_len, iv, iv_len, aad, aad_len, ct, tag) \
    hd_ossl_aes_gcm_encrypt(key, key_len, pt, pt_len, iv, iv_len, aad, aad_len, ct, tag)

#define HD_BACKEND_AES_GCM_DECRYPT(key, key_len, ct, ct_len, iv, iv_len, aad, aad_len, tag, pt) \
    hd_ossl_aes_gcm_decrypt(key, key_len, ct, ct_len, iv, iv_len, aad, aad_len, tag, pt)

// -----------------------------------------------------------------------------
// ECDSA/ECDH (NIST curves P-256, P-384)
// Route through OpenSSL
// -----------------------------------------------------------------------------

// OpenSSL NID values
#define HD_CURVE_NID_P256 415  // NID_X9_62_prime256v1
#define HD_CURVE_NID_P384 715  // NID_secp384r1

#define HD_BACKEND_ECDSA_SIGN_P256(privkey, hash, hash_len, sig, sig_len) \
    hd_ossl_ecdsa_sign(HD_CURVE_NID_P256, privkey, 32, hash, hash_len, sig, sig_len)

#define HD_BACKEND_ECDSA_VERIFY_P256(pubkey, pub_len, hash, hash_len, sig, sig_len) \
    hd_ossl_ecdsa_verify(HD_CURVE_NID_P256, pubkey, pub_len, hash, hash_len, sig, sig_len)

#define HD_BACKEND_ECDSA_SIGN_P384(privkey, hash, hash_len, sig, sig_len) \
    hd_ossl_ecdsa_sign(HD_CURVE_NID_P384, privkey, 48, hash, hash_len, sig, sig_len)

#define HD_BACKEND_ECDSA_VERIFY_P384(pubkey, pub_len, hash, hash_len, sig, sig_len) \
    hd_ossl_ecdsa_verify(HD_CURVE_NID_P384, pubkey, pub_len, hash, hash_len, sig, sig_len)

#define HD_BACKEND_ECDH_P256(privkey, pubkey, pub_len, shared, ss_len) \
    hd_ossl_ecdh_compute(HD_CURVE_NID_P256, privkey, 32, pubkey, pub_len, shared, ss_len)

#define HD_BACKEND_ECDH_P384(privkey, pubkey, pub_len, shared, ss_len) \
    hd_ossl_ecdh_compute(HD_CURVE_NID_P384, privkey, 48, pubkey, pub_len, shared, ss_len)

// Flag indicating OpenSSL backend is active
#define HD_BACKEND_OPENSSL 1
#define HD_BACKEND_CRYPTOPP 0

#else

// =============================================================================
// Crypto++ Backend (Default)
// =============================================================================

// When OpenSSL is not available, all functions use Crypto++ via the existing
// implementations in hash.cpp, ecdsa.cpp, ecdh.cpp, etc.
// The macros below are placeholders that indicate direct function calls should be used.

#define HD_BACKEND_OPENSSL 0
#define HD_BACKEND_CRYPTOPP 1

// For non-OpenSSL builds, implementations call Crypto++ directly
// No macro routing needed - the existing functions in hash.cpp, ecdsa.cpp, etc.
// are used directly.

#endif // HD_WALLET_USE_OPENSSL

// =============================================================================
// Non-FIPS Algorithms (Always Crypto++)
// These are never routed through OpenSSL, even when HD_WALLET_USE_OPENSSL is defined
// =============================================================================

// secp256k1 - Bitcoin/Ethereum curve (not FIPS approved)
// Uses: Crypto++ via ecdsa.cpp, ecdh.cpp

// Ed25519 - Solana, Cosmos (not FIPS approved)
// Uses: Crypto++ via eddsa.cpp

// X25519 - Key exchange (not FIPS approved)
// Uses: Crypto++ via eddsa.cpp

// Keccak-256 - Ethereum hash (not FIPS approved, different from SHA3-256)
// Uses: Crypto++ via hash.cpp

// BLAKE2b/s - Modern hash functions (not FIPS approved)
// Uses: Crypto++ via hash.cpp

// RIPEMD-160 - Bitcoin address hash (not FIPS approved)
// Uses: Crypto++ via hash.cpp

// scrypt - Memory-hard KDF (not FIPS approved)
// Uses: Crypto++ via wasm_exports.cpp

#endif // HD_WALLET_CRYPTO_BACKEND_H
