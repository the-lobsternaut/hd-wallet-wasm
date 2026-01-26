/**
 * @file hash.h
 * @brief Cryptographic Hash Functions for HD Wallet
 *
 * Provides all hash functions used in HD wallet operations:
 * - SHA-256, SHA-512 (seed derivation, checksums)
 * - RIPEMD-160 (Bitcoin addresses)
 * - Hash160 (SHA-256 + RIPEMD-160)
 * - Keccak-256 (Ethereum addresses)
 * - BLAKE2b, BLAKE2s (Polkadot, various protocols)
 * - HMAC variants
 */

#ifndef HD_WALLET_HASH_H
#define HD_WALLET_HASH_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hd_wallet {
namespace hash {

// =============================================================================
// Hash Constants
// =============================================================================

constexpr size_t SHA256_DIGEST_SIZE = 32;
constexpr size_t SHA512_DIGEST_SIZE = 64;
constexpr size_t RIPEMD160_DIGEST_SIZE = 20;
constexpr size_t KECCAK256_DIGEST_SIZE = 32;
constexpr size_t BLAKE2B_MAX_DIGEST_SIZE = 64;
constexpr size_t BLAKE2S_MAX_DIGEST_SIZE = 32;
constexpr size_t HASH160_DIGEST_SIZE = 20;

// =============================================================================
// Type Aliases
// =============================================================================

using SHA256Digest = std::array<uint8_t, SHA256_DIGEST_SIZE>;
using SHA512Digest = std::array<uint8_t, SHA512_DIGEST_SIZE>;
using RIPEMD160Digest = std::array<uint8_t, RIPEMD160_DIGEST_SIZE>;
using Keccak256Digest = std::array<uint8_t, KECCAK256_DIGEST_SIZE>;
using Hash160Digest = std::array<uint8_t, HASH160_DIGEST_SIZE>;

// =============================================================================
// SHA-256
// =============================================================================

/**
 * Compute SHA-256 hash
 *
 * @param data Input data
 * @param length Data length in bytes
 * @return 32-byte SHA-256 digest
 *
 * @example
 * ```cpp
 * const char* msg = "Hello, World!";
 * auto hash = sha256(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
 * ```
 */
SHA256Digest sha256(const uint8_t* data, size_t length);
SHA256Digest sha256(const ByteVector& data);
SHA256Digest sha256(const std::string& data);

/**
 * Compute double SHA-256 (SHA-256(SHA-256(data)))
 * Used in Bitcoin for transaction IDs, block hashes, etc.
 */
SHA256Digest doubleSha256(const uint8_t* data, size_t length);
SHA256Digest doubleSha256(const ByteVector& data);

// =============================================================================
// SHA-512
// =============================================================================

/**
 * Compute SHA-512 hash
 *
 * @param data Input data
 * @param length Data length in bytes
 * @return 64-byte SHA-512 digest
 */
SHA512Digest sha512(const uint8_t* data, size_t length);
SHA512Digest sha512(const ByteVector& data);
SHA512Digest sha512(const std::string& data);

// =============================================================================
// RIPEMD-160
// =============================================================================

/**
 * Compute RIPEMD-160 hash
 *
 * @param data Input data
 * @param length Data length in bytes
 * @return 20-byte RIPEMD-160 digest
 */
RIPEMD160Digest ripemd160(const uint8_t* data, size_t length);
RIPEMD160Digest ripemd160(const ByteVector& data);

// =============================================================================
// Hash160 (SHA-256 + RIPEMD-160)
// =============================================================================

/**
 * Compute Hash160 (RIPEMD-160(SHA-256(data)))
 * Used for Bitcoin address generation from public keys.
 *
 * @param data Input data (typically a public key)
 * @param length Data length in bytes
 * @return 20-byte Hash160 digest
 *
 * @example
 * ```cpp
 * // Generate Bitcoin address from public key
 * auto pubkeyHash = hash160(compressedPubkey.data(), 33);
 * ```
 */
Hash160Digest hash160(const uint8_t* data, size_t length);
Hash160Digest hash160(const ByteVector& data);

template<size_t N>
Hash160Digest hash160(const std::array<uint8_t, N>& data) {
    return hash160(data.data(), N);
}

// =============================================================================
// Keccak-256
// =============================================================================

/**
 * Compute Keccak-256 hash (NOT SHA-3)
 *
 * Note: Ethereum uses Keccak-256 (pre-NIST), not FIPS-202 SHA-3.
 * This is the original Keccak without the domain separation byte.
 *
 * @param data Input data
 * @param length Data length in bytes
 * @return 32-byte Keccak-256 digest
 *
 * @example
 * ```cpp
 * // Generate Ethereum address from public key
 * auto pubkeyHash = keccak256(uncompressedPubkey.data() + 1, 64);
 * // Address is last 20 bytes
 * ```
 */
Keccak256Digest keccak256(const uint8_t* data, size_t length);
Keccak256Digest keccak256(const ByteVector& data);
Keccak256Digest keccak256(const std::string& data);

// =============================================================================
// BLAKE2b
// =============================================================================

/**
 * Compute BLAKE2b hash
 *
 * @param data Input data
 * @param length Data length in bytes
 * @param digestLength Output digest length (1-64 bytes, default 32)
 * @param key Optional key for keyed hashing
 * @param keyLength Key length
 * @return BLAKE2b digest as byte vector
 *
 * @example
 * ```cpp
 * // Compute 32-byte BLAKE2b hash
 * auto hash = blake2b(data.data(), data.size(), 32);
 *
 * // Compute keyed hash
 * auto mac = blake2b(data.data(), data.size(), 32, key.data(), key.size());
 * ```
 */
ByteVector blake2b(
    const uint8_t* data,
    size_t length,
    size_t digestLength = 32,
    const uint8_t* key = nullptr,
    size_t keyLength = 0
);

ByteVector blake2b(
    const ByteVector& data,
    size_t digestLength = 32,
    const ByteVector& key = {}
);

/**
 * Compute BLAKE2b-256 (32-byte output)
 */
Bytes32 blake2b256(const uint8_t* data, size_t length);
Bytes32 blake2b256(const ByteVector& data);

/**
 * Compute BLAKE2b-512 (64-byte output)
 */
Bytes64 blake2b512(const uint8_t* data, size_t length);
Bytes64 blake2b512(const ByteVector& data);

// =============================================================================
// BLAKE2s
// =============================================================================

/**
 * Compute BLAKE2s hash
 *
 * @param data Input data
 * @param length Data length in bytes
 * @param digestLength Output digest length (1-32 bytes, default 32)
 * @param key Optional key for keyed hashing
 * @param keyLength Key length
 * @return BLAKE2s digest as byte vector
 */
ByteVector blake2s(
    const uint8_t* data,
    size_t length,
    size_t digestLength = 32,
    const uint8_t* key = nullptr,
    size_t keyLength = 0
);

ByteVector blake2s(
    const ByteVector& data,
    size_t digestLength = 32,
    const ByteVector& key = {}
);

/**
 * Compute BLAKE2s-256 (32-byte output)
 */
Bytes32 blake2s256(const uint8_t* data, size_t length);
Bytes32 blake2s256(const ByteVector& data);

// =============================================================================
// HMAC (Hash-based Message Authentication Code)
// =============================================================================

/**
 * Compute HMAC-SHA256
 *
 * @param key HMAC key
 * @param keyLength Key length
 * @param data Input data
 * @param dataLength Data length
 * @return 32-byte HMAC-SHA256 result
 */
SHA256Digest hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength
);

SHA256Digest hmacSha256(const ByteVector& key, const ByteVector& data);
SHA256Digest hmacSha256(const std::string& key, const ByteVector& data);

/**
 * Compute HMAC-SHA512
 *
 * @param key HMAC key
 * @param keyLength Key length
 * @param data Input data
 * @param dataLength Data length
 * @return 64-byte HMAC-SHA512 result
 */
SHA512Digest hmacSha512(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength
);

SHA512Digest hmacSha512(const ByteVector& key, const ByteVector& data);
SHA512Digest hmacSha512(const std::string& key, const ByteVector& data);

// =============================================================================
// Key Derivation Functions
// =============================================================================

/**
 * PBKDF2 with HMAC-SHA512
 *
 * Used for BIP-39 mnemonic to seed derivation.
 *
 * @param password Password/passphrase
 * @param passwordLength Password length
 * @param salt Salt value
 * @param saltLength Salt length
 * @param iterations Number of iterations (BIP-39 uses 2048)
 * @param outputLength Desired output length in bytes
 * @return Derived key
 *
 * @example
 * ```cpp
 * // BIP-39 seed derivation
 * auto seed = pbkdf2Sha512(
 *     mnemonic.data(), mnemonic.size(),
 *     "mnemonic" + passphrase, saltLen,
 *     2048, 64
 * );
 * ```
 */
ByteVector pbkdf2Sha512(
    const uint8_t* password,
    size_t passwordLength,
    const uint8_t* salt,
    size_t saltLength,
    uint32_t iterations,
    size_t outputLength
);

ByteVector pbkdf2Sha512(
    const std::string& password,
    const std::string& salt,
    uint32_t iterations,
    size_t outputLength
);

/**
 * HKDF (HMAC-based Key Derivation Function)
 *
 * @param inputKey Input keying material
 * @param inputLength Input length
 * @param salt Optional salt
 * @param saltLength Salt length
 * @param info Optional context info
 * @param infoLength Info length
 * @param outputLength Desired output length
 * @return Derived key
 */
ByteVector hkdf(
    const uint8_t* inputKey,
    size_t inputLength,
    const uint8_t* salt,
    size_t saltLength,
    const uint8_t* info,
    size_t infoLength,
    size_t outputLength
);

ByteVector hkdf(
    const ByteVector& inputKey,
    const ByteVector& salt,
    const ByteVector& info,
    size_t outputLength
);

/**
 * scrypt key derivation function
 *
 * @param password Password
 * @param passwordLength Password length
 * @param salt Salt
 * @param saltLength Salt length
 * @param N CPU/memory cost parameter (power of 2)
 * @param r Block size parameter
 * @param p Parallelization parameter
 * @param outputLength Output length
 * @return Derived key
 */
Result<ByteVector> scrypt(
    const uint8_t* password,
    size_t passwordLength,
    const uint8_t* salt,
    size_t saltLength,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    size_t outputLength
);

Result<ByteVector> scrypt(
    const std::string& password,
    const ByteVector& salt,
    uint64_t N,
    uint32_t r,
    uint32_t p,
    size_t outputLength
);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_sha256(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_sha512(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_keccak256(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_ripemd160(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_hash160(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_blake2b(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size,
    const uint8_t* key,
    size_t key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hash_blake2s(
    const uint8_t* data,
    size_t length,
    uint8_t* output,
    size_t output_size,
    const uint8_t* key,
    size_t key_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_hmac_sha512(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* data,
    size_t data_len,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_kdf_pbkdf2(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_kdf_hkdf(
    const uint8_t* input,
    size_t input_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_kdf_scrypt(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint64_t n,
    uint32_t r,
    uint32_t p,
    uint8_t* output,
    size_t output_size
);

} // namespace hash
} // namespace hd_wallet

#endif // HD_WALLET_HASH_H
