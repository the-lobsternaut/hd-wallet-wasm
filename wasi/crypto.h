/**
 * Self-contained crypto primitives for WASI
 *
 * Based on TweetNaCl (public domain) by Daniel J. Bernstein et al.
 * SHA-256 implementation added for BIP-39 checksum
 */

#ifndef WASI_CRYPTO_H
#define WASI_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// SHA-256 (32 bytes output)
void crypto_sha256(uint8_t *out, const uint8_t *m, size_t n);

// SHA-512 (64 bytes output)
void crypto_sha512(uint8_t *out, const uint8_t *m, size_t n);

// HMAC-SHA512 (64 bytes output)
void crypto_hmac_sha512(
    uint8_t *out,
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len
);

// PBKDF2-HMAC-SHA512 (output_len bytes)
void crypto_pbkdf2_sha512(
    uint8_t *out, size_t out_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations
);

// Ed25519: derive public key from 32-byte seed
// Note: This follows TweetNaCl convention where "seed" is hashed internally
void crypto_ed25519_pubkey(uint8_t *pk, const uint8_t *seed);

// Ed25519: sign message (signature is 64 bytes)
// sk must be 64 bytes: first 32 = seed, last 32 = public key
void crypto_ed25519_sign(
    uint8_t *sig,
    const uint8_t *m, size_t mlen,
    const uint8_t *sk
);

// Ed25519: verify signature (returns 0 on success, -1 on failure)
int crypto_ed25519_verify(
    const uint8_t *sig,
    const uint8_t *m, size_t mlen,
    const uint8_t *pk
);

// X25519: compute public key from 32-byte private key
void crypto_x25519_pubkey(uint8_t *pk, const uint8_t *sk);

// X25519: compute shared secret (ECDH)
// Returns 0 on success
int crypto_x25519_shared(uint8_t *shared, const uint8_t *sk, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif // WASI_CRYPTO_H
