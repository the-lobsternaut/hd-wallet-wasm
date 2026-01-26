/**
 * @file aligned_api.h
 * @brief Aligned Binary Format API for HD Wallet
 *
 * Provides efficient batch operations for key derivation, signing, and
 * verification using aligned, fixed-size structs. Designed for zero-copy
 * interop with WASM and cross-language WASI hosts.
 *
 * Features:
 * - Batch key derivation (derive multiple children at once)
 * - Batch signing (sign multiple hashes with same key)
 * - Batch verification (verify multiple signatures)
 * - Streaming derivation (generate keys on demand)
 *
 * All functions use the aligned structs defined in generated/aligned/hd_wallet_aligned.h
 * for zero-copy data access.
 */

#ifndef HD_WALLET_ALIGNED_API_H
#define HD_WALLET_ALIGNED_API_H

#include "config.h"
#include "types.h"
#include "bip32.h"

// Include generated aligned structs
#include "hd_wallet_aligned.h"

#include <cstdint>
#include <cstddef>

// =============================================================================
// Streaming Handle Type
// =============================================================================

/// Opaque handle for streaming derivation context
typedef struct hd_aligned_stream_impl* hd_aligned_stream_handle;

// =============================================================================
// C API Functions (extern "C")
// =============================================================================

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Derive multiple child keys from a base key in batch.
 *
 * This function performs efficient batch derivation, processing keys in a
 * cache-friendly order. Each derived key's error is tracked individually,
 * so the entire batch doesn't fail if one derivation fails.
 *
 * @param request Pointer to batch derivation request containing:
 *                - base_key: The extended key to derive from
 *                - start_index: Starting child index
 *                - count: Number of keys to derive
 *                - hardened: Whether to use hardened derivation
 * @param results Array to receive derived key entries
 * @param results_capacity Maximum number of results that can be written
 * @return Number of results written, or negative error code on critical failure
 *
 * @note Results are written in order: [start_index, start_index+1, ...]
 * @note Each result entry contains its own error code
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_derive_batch(
    const HdWallet::Aligned::BatchDeriveRequest* request,
    HdWallet::Aligned::DerivedKeyEntry* results,
    uint32_t results_capacity
);

/**
 * Sign multiple message hashes with the same private key.
 *
 * @param request Pointer to batch sign request containing:
 *                - private_key: The signing key
 *                - curve: Elliptic curve type
 *                - count: Number of hashes to sign
 * @param hashes Array of hash entries to sign
 * @param hashes_count Number of hash entries
 * @param results Array to receive signature entries
 * @param results_capacity Maximum number of results
 * @return Number of results written, or negative error code
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_sign_batch(
    const HdWallet::Aligned::BatchSignRequest* request,
    const HdWallet::Aligned::HashEntry* hashes,
    uint32_t hashes_count,
    HdWallet::Aligned::SignatureEntry* results,
    uint32_t results_capacity
);

/**
 * Verify multiple signatures against the same public key.
 *
 * @param request Pointer to batch verify request containing:
 *                - public_key: The verification key
 *                - curve: Elliptic curve type
 *                - count: Number of signatures to verify
 * @param entries Array of verify entries (hash + signature pairs)
 * @param entries_count Number of entries
 * @param results Array to receive verification results
 * @param results_capacity Maximum number of results
 * @return Number of results written, or negative error code
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_verify_batch(
    const HdWallet::Aligned::BatchVerifyRequest* request,
    const HdWallet::Aligned::VerifyEntry* entries,
    uint32_t entries_count,
    HdWallet::Aligned::VerifyResultEntry* results,
    uint32_t results_capacity
);

/**
 * Create a new streaming derivation context.
 *
 * Streaming derivation allows generating keys on demand without allocating
 * memory for all keys upfront. Useful for:
 * - Generating unlimited address sequences
 * - Memory-constrained environments
 * - Progress reporting during bulk derivation
 *
 * @param config Configuration for streaming derivation
 * @return Stream handle, or nullptr on error
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_aligned_stream_handle hd_aligned_stream_create(
    const HdWallet::Aligned::StreamDeriveConfig* config
);

/**
 * Get next batch of derived keys from stream.
 *
 * @param stream Stream handle
 * @param results Array to receive derived key entries
 * @param results_capacity Maximum number of results
 * @return Number of keys written, 0 if stream ended, negative on error
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_stream_next(
    hd_aligned_stream_handle stream,
    HdWallet::Aligned::DerivedKeyEntry* results,
    uint32_t results_capacity
);

/**
 * Get current stream status.
 *
 * @param stream Stream handle
 * @param status Output status structure
 * @return 0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_stream_status(
    hd_aligned_stream_handle stream,
    HdWallet::Aligned::StreamStatus* status
);

/**
 * Destroy streaming derivation context.
 *
 * @param stream Stream handle (may be nullptr)
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_aligned_stream_destroy(
    hd_aligned_stream_handle stream
);

/**
 * Convert ExtendedKey to aligned ExtendedKeyData.
 *
 * @param key Handle to ExtendedKey
 * @param out Output aligned data structure
 * @return 0 on success, negative error code on failure
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_from_extended_key(
    hd_wallet::bip32::hd_key_handle key,
    HdWallet::Aligned::ExtendedKeyData* out
);

/**
 * Create ExtendedKey from aligned ExtendedKeyData.
 *
 * @param data Pointer to aligned data
 * @return Handle to new ExtendedKey, or nullptr on error
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_wallet::bip32::hd_key_handle hd_aligned_to_extended_key(
    const HdWallet::Aligned::ExtendedKeyData* data
);

/**
 * Get size of a derived key entry.
 *
 * @return Size in bytes (76)
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_derived_key_entry_size(void);

/**
 * Get size of a signature entry.
 *
 * @return Size in bytes (76)
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_signature_entry_size(void);

/**
 * Get size of extended key data.
 *
 * @return Size in bytes (116)
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_extended_key_data_size(void);

/**
 * Get size of batch derive request.
 *
 * @return Size in bytes (132)
 */
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_batch_derive_request_size(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // HD_WALLET_ALIGNED_API_H
