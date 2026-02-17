/**
 * @file libp2p.h
 * @brief libp2p PeerID and IPNS hash derivation
 *
 * Computes libp2p-compatible peer IDs and IPNS hashes from public keys.
 * The output matches what IPFS/libp2p produces for the same key material.
 *
 * Supported curves:
 *   - secp256k1 (Curve 0) — compressed 33-byte public key
 *   - Ed25519 (Curve 1)   — raw 32-byte public key
 *   - P-256/ECDSA (Curve 2) — compressed 33-byte public key
 */

#ifndef HD_WALLET_LIBP2P_H
#define HD_WALLET_LIBP2P_H

#include "hd_wallet/config.h"
#include <stdint.h>
#include <stddef.h>

/**
 * Compute libp2p peerID (raw multihash bytes) from a public key.
 *
 * @param public_key  Public key bytes (compressed for secp256k1/P-256, raw for ed25519)
 * @param pubkey_len  Length of public key
 * @param curve       Curve type (0=secp256k1, 1=ed25519, 2=P-256)
 * @param output      Output buffer for multihash bytes
 * @param output_size Size of output buffer (64 bytes is always sufficient)
 * @return            Bytes written on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_libp2p_peer_id(
    const uint8_t* public_key,
    size_t pubkey_len,
    int32_t curve,
    uint8_t* output,
    size_t output_size
);

/**
 * Compute libp2p peerID as base58btc string.
 *
 * @param public_key  Public key bytes
 * @param pubkey_len  Length of public key
 * @param curve       Curve type (0=secp256k1, 1=ed25519, 2=P-256)
 * @param output      Output buffer for null-terminated string
 * @param output_size Size of output buffer (64 bytes is sufficient)
 * @return            0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_libp2p_peer_id_string(
    const uint8_t* public_key,
    size_t pubkey_len,
    int32_t curve,
    char* output,
    size_t output_size
);

/**
 * Compute IPNS hash (CIDv1 base36lower with 'k' prefix).
 *
 * @param public_key  Public key bytes
 * @param pubkey_len  Length of public key
 * @param curve       Curve type (0=secp256k1, 1=ed25519, 2=P-256)
 * @param output      Output buffer for null-terminated string
 * @param output_size Size of output buffer (128 bytes is sufficient)
 * @return            0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_libp2p_ipns_hash(
    const uint8_t* public_key,
    size_t pubkey_len,
    int32_t curve,
    char* output,
    size_t output_size
);

/**
 * Compute IPNS hash (CIDv1 base32lower with 'b' prefix).
 *
 * @param public_key  Public key bytes
 * @param pubkey_len  Length of public key
 * @param curve       Curve type (0=secp256k1, 1=ed25519, 2=P-256)
 * @param output      Output buffer for null-terminated string
 * @param output_size Size of output buffer (128 bytes is sufficient)
 * @return            0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_libp2p_ipns_hash_base32(
    const uint8_t* public_key,
    size_t pubkey_len,
    int32_t curve,
    char* output,
    size_t output_size
);

/**
 * Encode data as RFC 4648 base32 lowercase, no padding.
 *
 * @param data        Input data
 * @param data_len    Length of input data
 * @param output      Output buffer for null-terminated string
 * @param output_size Size of output buffer
 * @return            0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_base32lower(
    const uint8_t* data,
    size_t data_len,
    char* output,
    size_t output_size
);

/**
 * Encode data as base36 lowercase.
 *
 * @param data        Input data
 * @param data_len    Length of input data
 * @param output      Output buffer for null-terminated string
 * @param output_size Size of output buffer
 * @return            0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_base36lower(
    const uint8_t* data,
    size_t data_len,
    char* output,
    size_t output_size
);

#endif // HD_WALLET_LIBP2P_H
