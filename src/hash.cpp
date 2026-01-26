/**
 * @file hash.cpp
 * @brief Cryptographic Hash Functions
 *
 * Implementation of various hash functions using Crypto++:
 * - SHA-256, SHA-512
 * - RIPEMD-160
 * - Keccak-256 (Ethereum)
 * - BLAKE2b, BLAKE2s
 * - HMAC variants
 * - Hash160 (SHA-256 then RIPEMD-160)
 */

#include "hd_wallet/hash.h"
#include "hd_wallet/types.h"
#include "hd_wallet/config.h"

#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/keccak.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hmac.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

#include <cstring>
#include <stdexcept>

namespace hd_wallet {
namespace hash {

// =============================================================================
// SHA-256
// =============================================================================

/**
 * Internal helper: Compute SHA-256 hash into output buffer
 */
static bool sha256Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        CryptoPP::SHA256 hash;
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute SHA-256 hash (raw buffer interface)
 */
SHA256Digest sha256(const uint8_t* data, size_t length) {
    SHA256Digest result{};
    if (!sha256Internal(data, length, result.data())) {
        throw std::runtime_error("SHA-256 computation failed");
    }
    return result;
}

/**
 * Compute SHA-256 hash (vector interface)
 */
SHA256Digest sha256(const ByteVector& data) {
    return sha256(data.data(), data.size());
}

/**
 * Compute SHA-256 hash (string interface)
 */
SHA256Digest sha256(const std::string& data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// =============================================================================
// SHA-512
// =============================================================================

/**
 * Internal helper: Compute SHA-512 hash into output buffer
 */
static bool sha512Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        CryptoPP::SHA512 hash;
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute SHA-512 hash (raw buffer interface)
 */
SHA512Digest sha512(const uint8_t* data, size_t length) {
    SHA512Digest result{};
    if (!sha512Internal(data, length, result.data())) {
        throw std::runtime_error("SHA-512 computation failed");
    }
    return result;
}

/**
 * Compute SHA-512 hash (vector interface)
 */
SHA512Digest sha512(const ByteVector& data) {
    return sha512(data.data(), data.size());
}

/**
 * Compute SHA-512 hash (string interface)
 */
SHA512Digest sha512(const std::string& data) {
    return sha512(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// =============================================================================
// Keccak-256 (Ethereum hash)
// =============================================================================

/**
 * Internal helper: Compute Keccak-256 hash into output buffer
 */
static bool keccak256Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        // CryptoPP::Keccak_256 is the original Keccak, not SHA3-256
        CryptoPP::Keccak_256 hash;
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute Keccak-256 hash (raw buffer interface)
 */
Keccak256Digest keccak256(const uint8_t* data, size_t length) {
    Keccak256Digest result{};
    if (!keccak256Internal(data, length, result.data())) {
        throw std::runtime_error("Keccak-256 computation failed");
    }
    return result;
}

/**
 * Compute Keccak-256 hash (vector interface)
 */
Keccak256Digest keccak256(const ByteVector& data) {
    return keccak256(data.data(), data.size());
}

/**
 * Compute Keccak-256 hash (string interface)
 */
Keccak256Digest keccak256(const std::string& data) {
    return keccak256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// =============================================================================
// RIPEMD-160
// =============================================================================

/**
 * Internal helper: Compute RIPEMD-160 hash into output buffer
 */
static bool ripemd160Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        CryptoPP::RIPEMD160 hash;
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute RIPEMD-160 hash (raw buffer interface)
 */
RIPEMD160Digest ripemd160(const uint8_t* data, size_t length) {
    RIPEMD160Digest result{};
    if (!ripemd160Internal(data, length, result.data())) {
        throw std::runtime_error("RIPEMD-160 computation failed");
    }
    return result;
}

/**
 * Compute RIPEMD-160 hash (vector interface)
 */
RIPEMD160Digest ripemd160(const ByteVector& data) {
    return ripemd160(data.data(), data.size());
}

// =============================================================================
// Hash160 (SHA-256 then RIPEMD-160)
// =============================================================================

/**
 * Internal helper: Compute Hash160: RIPEMD160(SHA256(data))
 */
static bool hash160Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        // First compute SHA-256
        uint8_t sha256_hash[32];
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(sha256_hash, data, length);

        // Then compute RIPEMD-160
        CryptoPP::RIPEMD160 ripemd;
        ripemd.CalculateDigest(output, sha256_hash, 32);

        // Secure cleanup
        CryptoPP::SecureWipeArray(sha256_hash, 32);

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute Hash160 (raw buffer interface)
 */
Hash160Digest hash160(const uint8_t* data, size_t length) {
    Hash160Digest result{};
    if (!hash160Internal(data, length, result.data())) {
        throw std::runtime_error("Hash160 computation failed");
    }
    return result;
}

/**
 * Compute Hash160 (vector interface)
 */
Hash160Digest hash160(const ByteVector& data) {
    return hash160(data.data(), data.size());
}

// =============================================================================
// BLAKE2b
// =============================================================================

/**
 * Compute BLAKE2b hash with configurable output length
 *
 * @param data Input data
 * @param length Data length
 * @param output Output buffer
 * @param outputLength Desired output length (1-64 bytes)
 * @return true on success
 */
bool blake2b(const uint8_t* data, size_t length, uint8_t* output, size_t outputLength) {
    if (!data || !output) return false;
    if (outputLength == 0 || outputLength > 64) return false;

    try {
        CryptoPP::BLAKE2b hash(static_cast<unsigned int>(outputLength));
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute BLAKE2b-256 hash
 *
 * @param data Input data
 * @return 32-byte hash result
 */
Bytes32 blake2b256(const ByteVector& data) {
    Bytes32 result{};
    if (!blake2b(data.data(), data.size(), result.data(), 32)) {
        throw std::runtime_error("BLAKE2b-256 computation failed");
    }
    return result;
}

/**
 * Compute BLAKE2b-512 hash
 *
 * @param data Input data
 * @return 64-byte hash result
 */
Bytes64 blake2b512(const ByteVector& data) {
    Bytes64 result{};
    if (!blake2b(data.data(), data.size(), result.data(), 64)) {
        throw std::runtime_error("BLAKE2b-512 computation failed");
    }
    return result;
}

/**
 * Compute BLAKE2b hash with key (MAC mode)
 *
 * @param data Input data
 * @param dataLength Data length
 * @param key Key data
 * @param keyLength Key length (0-64 bytes)
 * @param output Output buffer
 * @param outputLength Desired output length (1-64 bytes)
 * @return true on success
 */
bool blake2bKeyed(
    const uint8_t* data,
    size_t dataLength,
    const uint8_t* key,
    size_t keyLength,
    uint8_t* output,
    size_t outputLength
) {
    if (!data || !output) return false;
    if (outputLength == 0 || outputLength > 64) return false;
    if (keyLength > 64) return false;

    try {
        CryptoPP::BLAKE2b hash(
            key,
            static_cast<unsigned int>(keyLength),
            nullptr,  // salt
            0,        // saltLength
            nullptr,  // personalization
            0,        // personalizationLength
            false,    // treeMode
            static_cast<unsigned int>(outputLength)
        );
        hash.CalculateDigest(output, data, dataLength);
        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// BLAKE2s
// =============================================================================

/**
 * Compute BLAKE2s hash with configurable output length
 *
 * @param data Input data
 * @param length Data length
 * @param output Output buffer
 * @param outputLength Desired output length (1-32 bytes)
 * @return true on success
 */
bool blake2s(const uint8_t* data, size_t length, uint8_t* output, size_t outputLength) {
    if (!data || !output) return false;
    if (outputLength == 0 || outputLength > 32) return false;

    try {
        CryptoPP::BLAKE2s hash(static_cast<unsigned int>(outputLength));
        hash.CalculateDigest(output, data, length);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute BLAKE2s-256 hash
 *
 * @param data Input data
 * @return 32-byte hash result
 */
Bytes32 blake2s256(const ByteVector& data) {
    Bytes32 result{};
    if (!blake2s(data.data(), data.size(), result.data(), 32)) {
        throw std::runtime_error("BLAKE2s-256 computation failed");
    }
    return result;
}

/**
 * Compute BLAKE2s hash with key (MAC mode)
 *
 * @param data Input data
 * @param dataLength Data length
 * @param key Key data
 * @param keyLength Key length (0-32 bytes)
 * @param output Output buffer
 * @param outputLength Desired output length (1-32 bytes)
 * @return true on success
 */
bool blake2sKeyed(
    const uint8_t* data,
    size_t dataLength,
    const uint8_t* key,
    size_t keyLength,
    uint8_t* output,
    size_t outputLength
) {
    if (!data || !output) return false;
    if (outputLength == 0 || outputLength > 32) return false;
    if (keyLength > 32) return false;

    try {
        CryptoPP::BLAKE2s hash(
            key,
            static_cast<unsigned int>(keyLength),
            nullptr,  // salt
            0,        // saltLength
            nullptr,  // personalization
            0,        // personalizationLength
            false,    // treeMode
            static_cast<unsigned int>(outputLength)
        );
        hash.CalculateDigest(output, data, dataLength);
        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// HMAC Functions
// =============================================================================

/**
 * Internal helper: Compute HMAC-SHA256 into output buffer
 */
static bool hmacSha256Internal(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t* output
) {
    if (!key || !data || !output) return false;

    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(key, keyLength);
        hmac.CalculateDigest(output, data, dataLength);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute HMAC-SHA256 (raw buffer interface)
 */
SHA256Digest hmacSha256(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength
) {
    SHA256Digest result{};
    if (!hmacSha256Internal(key, keyLength, data, dataLength, result.data())) {
        throw std::runtime_error("HMAC-SHA256 computation failed");
    }
    return result;
}

/**
 * Compute HMAC-SHA256 (vector interface)
 */
SHA256Digest hmacSha256(const ByteVector& key, const ByteVector& data) {
    return hmacSha256(key.data(), key.size(), data.data(), data.size());
}

/**
 * Compute HMAC-SHA256 (string key interface)
 */
SHA256Digest hmacSha256(const std::string& key, const ByteVector& data) {
    return hmacSha256(
        reinterpret_cast<const uint8_t*>(key.data()),
        key.size(),
        data.data(),
        data.size()
    );
}

/**
 * Internal helper: Compute HMAC-SHA512 into output buffer
 */
static bool hmacSha512Internal(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength,
    uint8_t* output
) {
    if (!key || !data || !output) return false;

    try {
        CryptoPP::HMAC<CryptoPP::SHA512> hmac(key, keyLength);
        hmac.CalculateDigest(output, data, dataLength);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute HMAC-SHA512 (raw buffer interface)
 */
SHA512Digest hmacSha512(
    const uint8_t* key,
    size_t keyLength,
    const uint8_t* data,
    size_t dataLength
) {
    SHA512Digest result{};
    if (!hmacSha512Internal(key, keyLength, data, dataLength, result.data())) {
        throw std::runtime_error("HMAC-SHA512 computation failed");
    }
    return result;
}

/**
 * Compute HMAC-SHA512 (vector interface)
 */
SHA512Digest hmacSha512(const ByteVector& key, const ByteVector& data) {
    return hmacSha512(key.data(), key.size(), data.data(), data.size());
}

/**
 * Compute HMAC-SHA512 with string key (for BIP-32)
 */
SHA512Digest hmacSha512(const std::string& key, const ByteVector& data) {
    return hmacSha512(
        reinterpret_cast<const uint8_t*>(key.data()),
        key.size(),
        data.data(),
        data.size()
    );
}

// =============================================================================
// Double Hash Functions
// =============================================================================

/**
 * Internal helper: Compute double SHA-256
 */
static bool doubleSha256Internal(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        uint8_t first_hash[32];
        CryptoPP::SHA256 sha;

        // First SHA-256
        sha.CalculateDigest(first_hash, data, length);

        // Second SHA-256
        sha.Restart();
        sha.CalculateDigest(output, first_hash, 32);

        // Secure cleanup
        CryptoPP::SecureWipeArray(first_hash, 32);

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute double SHA-256 (raw buffer interface)
 */
SHA256Digest doubleSha256(const uint8_t* data, size_t length) {
    SHA256Digest result{};
    if (!doubleSha256Internal(data, length, result.data())) {
        throw std::runtime_error("Double SHA-256 computation failed");
    }
    return result;
}

/**
 * Compute double SHA-256 (vector interface)
 */
SHA256Digest doubleSha256(const ByteVector& data) {
    return doubleSha256(data.data(), data.size());
}

// =============================================================================
// Checksum Functions
// =============================================================================

/**
 * Compute 4-byte checksum using double SHA-256
 * Used in Base58Check encoding
 *
 * @param data Input data
 * @param length Data length
 * @param output Output buffer (must be at least 4 bytes)
 * @return true on success
 */
static bool checksum4(const uint8_t* data, size_t length, uint8_t* output) {
    if (!data || !output) return false;

    try {
        uint8_t hash[32];
        if (!doubleSha256Internal(data, length, hash)) {
            return false;
        }

        std::memcpy(output, hash, 4);
        CryptoPP::SecureWipeArray(hash, 32);

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Verify 4-byte checksum
 *
 * @param data Input data (including checksum as last 4 bytes)
 * @param length Total length (data + checksum)
 * @return true if checksum is valid
 */
bool verifyChecksum4(const uint8_t* data, size_t length) {
    if (!data || length < 5) return false;

    try {
        uint8_t computed[4];
        if (!checksum4(data, length - 4, computed)) {
            return false;
        }

        return std::memcmp(computed, data + length - 4, 4) == 0;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// PBKDF2 Functions
// =============================================================================

/**
 * Compute PBKDF2-HMAC-SHA512
 * Used in BIP-39 mnemonic to seed conversion
 *
 * @param password Password bytes
 * @param passwordLength Password length
 * @param salt Salt bytes
 * @param saltLength Salt length
 * @param iterations Number of iterations
 * @param output Output buffer
 * @param outputLength Desired output length
 * @return true on success
 */
static bool pbkdf2HmacSha512Internal(
    const uint8_t* password,
    size_t passwordLength,
    const uint8_t* salt,
    size_t saltLength,
    uint32_t iterations,
    uint8_t* output,
    size_t outputLength
) {
    if (!password || !salt || !output) return false;
    if (iterations == 0) return false;

    try {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
        pbkdf2.DeriveKey(
            output,
            outputLength,
            0,  // purpose byte (unused)
            password,
            passwordLength,
            salt,
            saltLength,
            iterations,
            0   // time in seconds (unused when iterations specified)
        );
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Compute PBKDF2-HMAC-SHA512 with raw buffers
 */
ByteVector pbkdf2Sha512(
    const uint8_t* password,
    size_t passwordLength,
    const uint8_t* salt,
    size_t saltLength,
    uint32_t iterations,
    size_t outputLength
) {
    ByteVector output(outputLength);
    if (!pbkdf2HmacSha512Internal(
        password,
        passwordLength,
        salt,
        saltLength,
        iterations,
        output.data(),
        outputLength
    )) {
        throw std::runtime_error("PBKDF2-HMAC-SHA512 computation failed");
    }
    return output;
}

/**
 * Compute PBKDF2-HMAC-SHA512 with string inputs
 * Convenience function for BIP-39
 *
 * @param password Password string
 * @param salt Salt string
 * @param iterations Number of iterations
 * @param outputLength Desired output length
 * @return Output bytes
 */
ByteVector pbkdf2Sha512(
    const std::string& password,
    const std::string& salt,
    uint32_t iterations,
    size_t outputLength
) {
    ByteVector output(outputLength);
    if (!pbkdf2HmacSha512Internal(
        reinterpret_cast<const uint8_t*>(password.data()),
        password.size(),
        reinterpret_cast<const uint8_t*>(salt.data()),
        salt.size(),
        iterations,
        output.data(),
        outputLength
    )) {
        throw std::runtime_error("PBKDF2-HMAC-SHA512 computation failed");
    }
    return output;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Securely wipe memory
 *
 * @param data Data to wipe
 * @param length Data length
 */
void secureWipe(uint8_t* data, size_t length) {
    if (data && length > 0) {
        CryptoPP::SecureWipeArray(data, length);
    }
}

/**
 * Securely wipe a vector
 *
 * @param data Vector to wipe
 */
void secureWipe(ByteVector& data) {
    if (!data.empty()) {
        CryptoPP::SecureWipeArray(data.data(), data.size());
        data.clear();
    }
}

/**
 * Securely wipe an array
 *
 * @param data Array to wipe
 */
template<size_t N>
void secureWipe(std::array<uint8_t, N>& data) {
    CryptoPP::SecureWipeArray(data.data(), N);
}

// Explicit template instantiations
template void secureWipe<20>(std::array<uint8_t, 20>&);
template void secureWipe<32>(std::array<uint8_t, 32>&);
template void secureWipe<33>(std::array<uint8_t, 33>&);
template void secureWipe<64>(std::array<uint8_t, 64>&);
template void secureWipe<65>(std::array<uint8_t, 65>&);

} // namespace hash
} // namespace hd_wallet
