/**
 * @file error.h
 * @brief Error Handling for HD Wallet
 *
 * Error code definitions and error handling utilities.
 * Error codes are categorized by subsystem for easier debugging.
 *
 * Error Code Ranges:
 *   0        - Success
 *   1-99     - General errors
 *   100-199  - Entropy errors
 *   200-299  - BIP-39 mnemonic errors
 *   300-399  - BIP-32 HD key errors
 *   400-499  - Cryptographic errors
 *   500-599  - Transaction errors
 *   600-699  - Hardware wallet errors
 *   700-799  - WASI bridge errors
 *   800-899  - FIPS compliance errors
 */

#ifndef HD_WALLET_ERROR_H
#define HD_WALLET_ERROR_H

#include "config.h"
#include "types.h"

#include <cstdint>

namespace hd_wallet {

// =============================================================================
// Error String Conversion
// =============================================================================

/**
 * Convert error code to human-readable string
 *
 * @param error Error code
 * @return Null-terminated string describing the error
 *
 * @example
 * ```cpp
 * Error err = Error::INVALID_MNEMONIC_LENGTH;
 * std::cout << "Error: " << errorToString(err) << std::endl;
 * // Output: "Error: Invalid mnemonic length"
 * ```
 */
const char* errorToString(Error error);

/**
 * Get error category name
 *
 * @param error Error code
 * @return Category name (e.g., "BIP-39", "Crypto", "WASI")
 */
const char* errorCategory(Error error);

/**
 * Check if error is recoverable
 *
 * Some errors (like NO_ENTROPY) can be recovered from by providing
 * the missing resource. Others (like INTERNAL) indicate fatal issues.
 *
 * @param error Error code
 * @return true if the error can be recovered from
 */
bool isRecoverableError(Error error);

// =============================================================================
// Error Code Documentation
// =============================================================================

/**
 * Error code categories and their meanings:
 *
 * === General Errors (1-99) ===
 * - OK (0): Operation completed successfully
 * - UNKNOWN (1): An unknown error occurred
 * - INVALID_ARGUMENT (2): Invalid argument passed to function
 * - NOT_SUPPORTED (3): Operation not supported in this configuration
 * - OUT_OF_MEMORY (4): Memory allocation failed
 * - INTERNAL (5): Internal library error
 *
 * === Entropy Errors (100-199) ===
 * - NO_ENTROPY (100): No entropy source available (WASI: inject entropy first)
 * - INSUFFICIENT_ENTROPY (101): Not enough entropy for requested operation
 *
 * === BIP-39 Errors (200-299) ===
 * - INVALID_WORD (200): Word not found in wordlist
 * - INVALID_CHECKSUM (201): Mnemonic checksum verification failed
 * - INVALID_MNEMONIC_LENGTH (202): Invalid word count (must be 12,15,18,21,24)
 * - INVALID_ENTROPY_LENGTH (203): Invalid entropy length for mnemonic
 *
 * === BIP-32 Errors (300-399) ===
 * - INVALID_SEED (300): Invalid seed length (must be 64 bytes)
 * - INVALID_PATH (301): Invalid derivation path format
 * - INVALID_CHILD_INDEX (302): Child index out of valid range
 * - HARDENED_FROM_PUBLIC (303): Cannot derive hardened child from public key
 * - INVALID_EXTENDED_KEY (304): Invalid xprv/xpub format
 *
 * === Cryptographic Errors (400-499) ===
 * - INVALID_PRIVATE_KEY (400): Private key is invalid (zero, >= curve order)
 * - INVALID_PUBLIC_KEY (401): Public key is not on curve
 * - INVALID_SIGNATURE (402): Signature format is invalid
 * - VERIFICATION_FAILED (403): Signature verification failed
 * - KEY_DERIVATION_FAILED (404): Key derivation operation failed
 *
 * === Transaction Errors (500-599) ===
 * - INVALID_TRANSACTION (500): Transaction format is invalid
 * - INSUFFICIENT_FUNDS (501): Insufficient funds for transaction
 * - INVALID_ADDRESS (502): Address format is invalid
 *
 * === Hardware Wallet Errors (600-699) ===
 * - DEVICE_NOT_CONNECTED (600): Hardware wallet not connected
 * - DEVICE_COMM_ERROR (601): Communication error with device
 * - USER_CANCELLED (602): User cancelled operation on device
 * - DEVICE_BUSY (603): Device is busy with another operation
 * - DEVICE_NOT_SUPPORTED (604): Operation not supported by this device
 *
 * === WASI Bridge Errors (700-799) ===
 * - BRIDGE_NOT_SET (700): Required bridge callback not registered
 * - BRIDGE_FAILED (701): Bridge callback returned error
 * - NEEDS_BRIDGE (702): Operation requires bridge in WASI environment
 *
 * === FIPS Errors (800-899) ===
 * - FIPS_NOT_ALLOWED (800): Algorithm not permitted in FIPS mode
 */

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_error_to_string(int32_t error_code);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_error_category(int32_t error_code);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_error_is_recoverable(int32_t error_code);

} // namespace hd_wallet

#endif // HD_WALLET_ERROR_H
