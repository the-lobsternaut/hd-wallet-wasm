/**
 * WASM-specific C API exports
 *
 * This file contains C wrappers for functions that are NOT already exported
 * from the main library source files (bip32.cpp, bip39.cpp, bip44.cpp, eddsa.cpp).
 *
 * Functions that ARE already exported from main sources:
 * - BIP-39: hd_mnemonic_* (from bip39.cpp)
 * - BIP-32: hd_key_* (from bip32.cpp)
 * - BIP-44: hd_path_* (from bip44.cpp)
 * - Ed25519: hd_ed25519_* (from eddsa.cpp)
 * - X25519: hd_ecdh_x25519, hd_x25519_pubkey (from eddsa.cpp)
 *
 * Functions exported HERE (unique to this file):
 * - Hash: hd_hash_sha256, hd_hash_sha512, hd_hash_keccak256, hd_hash_ripemd160, hd_hash_hash160, hd_hash_blake2b, hd_hash_blake2s
 * - KDF: hd_kdf_hkdf, hd_kdf_pbkdf2, hd_kdf_scrypt
 * - Curves: hd_curve_pubkey_from_privkey
 * - secp256k1: hd_secp256k1_sign, hd_secp256k1_verify, hd_ecdh_secp256k1
 * - P-256/P-384: hd_p256_sign, hd_p256_verify, hd_ecdh_p256, hd_p384_sign, hd_p384_verify, hd_ecdh_p384
 */

#include "hd_wallet/config.h"
#include "hd_wallet/types.h"
#include "hd_wallet/error.h"
#include "hd_wallet/bip32.h"

// Forward declaration of C function from ecdh.cpp
extern "C" int32_t hd_ecdh(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_size
);

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/keccak.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>

#if HD_WALLET_USE_OPENSSL
#include "hd_wallet/crypto_openssl.h"
#endif

#include <cstring>
#include <vector>
#include <string>

namespace hd_wallet {

using Error = hd_wallet::Error;

// =============================================================================
// RFC 6979 Deterministic Nonce Generation
// =============================================================================

namespace {

/**
 * RFC 6979 deterministic k generation for ECDSA
 * This eliminates the need for random number generation during signing,
 * preventing nonce-reuse attacks that could leak private keys.
 */
template<typename HashType>
CryptoPP::Integer generateDeterministicK(
    const CryptoPP::Integer& privateKey,
    const uint8_t* hash,
    size_t hashLen,
    const CryptoPP::Integer& order
) {
    size_t qLen = order.ByteCount();
    size_t hLen = HashType::DIGESTSIZE;

    CryptoPP::SecByteBlock v(hLen);
    std::memset(v.data(), 0x01, hLen);
    CryptoPP::SecByteBlock k(hLen);
    std::memset(k.data(), 0x00, hLen);

    // Encode private key as fixed-length big-endian
    CryptoPP::SecByteBlock x(qLen);
    privateKey.Encode(x.data(), qLen);

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    CryptoPP::HMAC<HashType> hmac;

    // SECURITY FIX [VULN-02]: Use SecByteBlock instead of std::vector to ensure
    // the private key material in hmacInput is securely wiped on destruction.
    CryptoPP::SecByteBlock hmacInput(hLen + 1 + qLen + hashLen);
    size_t pos = 0;
    std::memcpy(hmacInput.data() + pos, v.data(), hLen); pos += hLen;
    hmacInput[pos++] = 0x00;
    std::memcpy(hmacInput.data() + pos, x.data(), qLen); pos += qLen;
    std::memcpy(hmacInput.data() + pos, hash, hashLen); pos += hashLen;

    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(k.data(), hmacInput.data(), pos);

    // V = HMAC_K(V)
    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(v.data(), v.data(), v.size());

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    pos = 0;
    std::memcpy(hmacInput.data() + pos, v.data(), hLen); pos += hLen;
    hmacInput[pos++] = 0x01;
    std::memcpy(hmacInput.data() + pos, x.data(), qLen); pos += qLen;
    std::memcpy(hmacInput.data() + pos, hash, hashLen); pos += hashLen;

    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(k.data(), hmacInput.data(), hmacInput.size());

    // V = HMAC_K(V)
    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(v.data(), v.data(), v.size());

    // Generate k candidates until we get a valid one
    while (true) {
        CryptoPP::SecByteBlock t;
        t.resize(0);

        while (t.size() < qLen) {
            // V = HMAC_K(V)
            hmac.SetKey(k.data(), k.size());
            hmac.CalculateDigest(v.data(), v.data(), v.size());
            size_t oldSize = t.size();
            t.Grow(oldSize + v.size());
            std::memcpy(t.data() + oldSize, v.data(), v.size());
        }

        CryptoPP::Integer candidate(t.data(), qLen);

        // Valid k: 1 <= k < order
        if (candidate >= 1 && candidate < order) {
            // Securely wipe sensitive data
            std::memset(x.data(), 0, x.size());
            return candidate;
        }

        // K = HMAC_K(V || 0x00)
        std::memcpy(hmacInput.data(), v.data(), hLen);
        hmacInput[hLen] = 0x00;

        hmac.SetKey(k.data(), k.size());
        hmac.CalculateDigest(k.data(), hmacInput.data(), hLen + 1);

        // V = HMAC_K(V)
        hmac.SetKey(k.data(), k.size());
        hmac.CalculateDigest(v.data(), v.data(), v.size());
    }
}

/**
 * Securely wipe a CryptoPP::Integer
 *
 * SECURITY FIX [VULN-03]: Previous implementation encoded to a temp buffer
 * and wiped the temp, not the Integer's internal storage. Now we directly
 * access the Integer's word array via IsZero() pattern and overwrite in-place.
 */
inline void secureWipeInteger(CryptoPP::Integer& val) {
    // Set to zero — this overwrites the internal SecBlock<word> storage
    // and uses CryptoPP's own secure memory management
    val = CryptoPP::Integer::Zero();
    // Additionally, assign a new zero to force any lazy/cached state clear
    CryptoPP::Integer zero(0L);
    val.swap(zero);
}

} // anonymous namespace

// =============================================================================
// Hash Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha512(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 64;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_keccak256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::Keccak_256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_ripemd160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::RIPEMD160 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_hash160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    // Hash160 = RIPEMD160(SHA256(data))
    uint8_t sha_out[32];
    CryptoPP::SHA256 sha;
    sha.CalculateDigest(sha_out, data, data_len);
    CryptoPP::RIPEMD160 ripemd;
    ripemd.CalculateDigest(hash_out, sha_out, 32);
    // Wipe intermediate hash
    std::memset(sha_out, 0, sizeof(sha_out));
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2b(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < digest_size || digest_size > 64 || digest_size == 0) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::BLAKE2b hash(false, digest_size);
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(digest_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2s(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < digest_size || digest_size > 32 || digest_size == 0) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::BLAKE2s hash(false, digest_size);
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(digest_size);
}

// =============================================================================
// Key Derivation Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_hkdf(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm_out, size_t okm_len
) {
    try {
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(okm_out, okm_len, ikm, ikm_len, salt, salt_len, info, info_len);
        return static_cast<int32_t>(okm_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_pbkdf2(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* key_out, size_t key_len
) {
    try {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
        pbkdf2.DeriveKey(key_out, key_len, 0, password, password_len, salt, salt_len, iterations);
        return static_cast<int32_t>(key_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_scrypt(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint64_t N, uint32_t r, uint32_t p,
    uint8_t* key_out, size_t key_len
) {
    try {
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(key_out, key_len, password, password_len, salt, salt_len, N, r, p);
        return static_cast<int32_t>(key_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// Curve Operations
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_pubkey_from_privkey(
    const uint8_t* private_key,
    int32_t curve_type,
    uint8_t* public_key_out,
    size_t out_size
) {
    try {
        auto curve = static_cast<Curve>(curve_type);

        switch (curve) {
            case Curve::SECP256K1: {
                if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 32);
                privKey.Initialize(CryptoPP::ASN1::secp256k1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                // Compressed format: 0x02/0x03 + x coordinate
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 32);
                return 33;
            }
            case Curve::P256: {
                if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 32);
                privKey.Initialize(CryptoPP::ASN1::secp256r1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 32);
                return 33;
            }
            case Curve::P384: {
                if (out_size < 49) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 48);
                privKey.Initialize(CryptoPP::ASN1::secp384r1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 48);
                return 49;
            }
            case Curve::ED25519:
            case Curve::X25519:
                // These are handled by the Ed25519/X25519 specific functions in eddsa.cpp
                return static_cast<int32_t>(Error::NOT_SUPPORTED);
            default:
                return static_cast<int32_t>(Error::NOT_SUPPORTED);
        }
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// secp256k1 Signing (RFC 6979 Deterministic)
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    // Return compact R||S format (64 bytes) for consistency with blockchain usage
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        // Get curve parameters
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
        params.Initialize(CryptoPP::ASN1::secp256k1());
        const CryptoPP::ECP& ec = params.GetCurve();
        const CryptoPP::Integer& n = params.GetGroupOrder();
        const CryptoPP::Integer halfN = n >> 1;

        // Parse private key
        CryptoPP::Integer d(private_key, 32);

        // Validate private key range
        if (d <= 0 || d >= n) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        // Hash message with SHA-256 (standard for secp256k1 ECDSA)
        uint8_t msgHash[32];
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash, message, message_len);

        // Generate deterministic k using RFC 6979
        CryptoPP::Integer k = generateDeterministicK<CryptoPP::SHA256>(d, msgHash, 32, n);

        // Compute R = k * G
        CryptoPP::ECPPoint R = ec.ScalarMultiply(params.GetSubgroupGenerator(), k);

        // r = R.x mod n
        CryptoPP::Integer r = R.x % n;
        if (r.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // z = hash (interpreted as integer)
        CryptoPP::Integer z(msgHash, 32);

        // s = k^-1 * (z + r*d) mod n
        CryptoPP::Integer kInv = k.InverseMod(n);
        CryptoPP::Integer s = (kInv * (z + r * d)) % n;

        if (s.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // Low-S normalization (BIP-62/BIP-146)
        if (s > halfN) {
            s = n - s;
        }

        // Encode as compact R||S (64 bytes)
        std::memset(signature_out, 0, 64);
        r.Encode(signature_out, 32);
        s.Encode(signature_out + 32, 32);

        // Secure cleanup
        secureWipeInteger(d);
        secureWipeInteger(k);
        secureWipeInteger(kInv);
        std::memset(msgHash, 0, sizeof(msgHash));

        return 64;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len,
    const uint8_t* public_key, size_t public_key_len
) {
    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;

        // Only support uncompressed public key for simplicity
        if (public_key_len == 65 && public_key[0] == 0x04) {
            CryptoPP::ECP::Point point;
            point.x.Decode(public_key + 1, 32);
            point.y.Decode(public_key + 33, 32);
            pubKey.Initialize(CryptoPP::ASN1::secp256k1(), point);
        } else if (public_key_len == 33) {
            // Compressed public key - need to decompress
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
            params.Initialize(CryptoPP::ASN1::secp256k1());
            const auto& curve = params.GetCurve();

            CryptoPP::Integer x(public_key + 1, 32);
            // secp256k1: y^2 = x^3 + 7
            CryptoPP::Integer a = params.GetCurve().GetA();
            CryptoPP::Integer b = params.GetCurve().GetB();
            CryptoPP::Integer p = curve.GetField().GetModulus();

            CryptoPP::Integer y2 = (x*x*x + a*x + b) % p;
            CryptoPP::Integer y = CryptoPP::ModularSquareRoot(y2, p);

            bool yOdd = (public_key[0] == 0x03);
            if (y.IsOdd() != yOdd) {
                y = p - y;
            }

            CryptoPP::ECP::Point point(x, y);
            pubKey.Initialize(CryptoPP::ASN1::secp256k1(), point);
        } else {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        // Check if signature is already DER-encoded
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(pubKey);
        if (signature_len > 64 && signature[0] == 0x30) {
            // Already DER encoded
            return verifier.VerifyMessage(message, message_len, signature, signature_len) ? 1 : 0;
        }

        // Convert R||S (64 bytes) to DER format
        // Uses fixed-size buffer to avoid timing side channels
        if (signature_len != 64) {
            return static_cast<int32_t>(Error::INVALID_SIGNATURE);
        }

        // Max DER signature: 2 (header) + 2 (R tag+len) + 33 (R) + 2 (S tag+len) + 33 (S) = 72
        uint8_t derSig[72];
        size_t pos = 0;

        derSig[pos++] = 0x30; // SEQUENCE
        derSig[pos++] = 0;    // length placeholder (filled at end)

        // R component
        derSig[pos++] = 0x02; // INTEGER
        uint8_t rPad = (signature[0] >> 7); // 1 if high bit set, 0 otherwise
        derSig[pos++] = 32 + rPad;
        derSig[pos] = 0;      // padding byte (only meaningful if rPad==1)
        pos += rPad;
        std::memcpy(derSig + pos, signature, 32);
        pos += 32;

        // S component
        derSig[pos++] = 0x02; // INTEGER
        uint8_t sPad = (signature[32] >> 7);
        derSig[pos++] = 32 + sPad;
        derSig[pos] = 0;
        pos += sPad;
        std::memcpy(derSig + pos, signature + 32, 32);
        pos += 32;

        derSig[1] = static_cast<uint8_t>(pos - 2);

        return verifier.VerifyMessage(message, message_len, derSig, pos) ? 1 : 0;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_decompress_pubkey(
    const uint8_t* compressed,
    int32_t curve,
    uint8_t* uncompressed_out,
    size_t out_size
) {
    if (out_size < 65) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (curve != static_cast<int32_t>(Curve::SECP256K1)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    Bytes33 pubkey;
    std::memcpy(pubkey.data(), compressed, 33);

    auto result = bip32::decompressPublicKey(pubkey, static_cast<Curve>(curve));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(uncompressed_out, result.value.data(), 65);
    return 0;
}

// Static singleton for secp256k1 curve (same pattern as ecdsa.cpp)
namespace {
class Secp256k1Curve {
public:
    static Secp256k1Curve& instance() {
        static Secp256k1Curve inst;
        return inst;
    }

    const CryptoPP::ECP& ec() const { return curve_.GetCurve(); }
    const CryptoPP::Integer& order() const { return n_; }

private:
    Secp256k1Curve() {
        curve_.Initialize(CryptoPP::ASN1::secp256k1());
        n_ = curve_.GetGroupOrder();
    }

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
    CryptoPP::Integer n_;
};
} // anonymous namespace

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_secp256k1(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    // Validate public key format
    if (public_key_len != 33 && public_key_len != 65) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        // Use static singleton curve (same pattern as working ECDSA code)
        const CryptoPP::ECP& ec = Secp256k1Curve::instance().ec();
        const CryptoPP::Integer& order = Secp256k1Curve::instance().order();

        // Parse private key as integer
        CryptoPP::Integer d(private_key, 32);

        // Validate private key range
        if (d <= 0 || d >= order) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        // Parse public key point using DecodePoint for proper initialization
        // NOTE: Must use DecodePoint instead of manual x/y decoding for ScalarMultiply to work
        CryptoPP::ECP::Point Q;
        Q.identity = false;

        if (public_key_len == 65) {
            if (public_key[0] != 0x04) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
            if (!ec.DecodePoint(Q, public_key, 65)) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
        } else {
            if (public_key[0] != 0x02 && public_key[0] != 0x03) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
            if (!ec.DecodePoint(Q, public_key, 33)) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
        }

        // Validate public key is on curve
        if (!ec.VerifyPoint(Q)) {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        // Compute shared secret: S = d * Q (scalar multiplication)
        CryptoPP::ECP::Point S = ec.ScalarMultiply(Q, d);

        // Check for point at infinity
        if (S.identity) {
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // Output the x-coordinate as the shared secret (32 bytes)
        S.x.Encode(shared_secret_out, 32);
        return 32;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// P-256 (NIST secp256r1) - RFC 6979 Deterministic
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        // Get curve parameters
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
        params.Initialize(CryptoPP::ASN1::secp256r1());
        const CryptoPP::ECP& ec = params.GetCurve();
        const CryptoPP::Integer& n = params.GetGroupOrder();
        const CryptoPP::Integer halfN = n >> 1;

        // Parse private key
        CryptoPP::Integer d(private_key, 32);

        // Validate private key range
        if (d <= 0 || d >= n) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        // Hash message with SHA-256
        uint8_t msgHash[32];
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash, message, message_len);

        // Generate deterministic k using RFC 6979
        CryptoPP::Integer k = generateDeterministicK<CryptoPP::SHA256>(d, msgHash, 32, n);

        // Compute R = k * G
        CryptoPP::ECPPoint R = ec.ScalarMultiply(params.GetSubgroupGenerator(), k);

        // r = R.x mod n
        CryptoPP::Integer r = R.x % n;
        if (r.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // z = hash (interpreted as integer)
        CryptoPP::Integer z(msgHash, 32);

        // s = k^-1 * (z + r*d) mod n
        CryptoPP::Integer kInv = k.InverseMod(n);
        CryptoPP::Integer s = (kInv * (z + r * d)) % n;

        if (s.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // Low-S normalization for signature malleability protection
        if (s > halfN) {
            s = n - s;
        }

        // Encode as compact R||S (64 bytes)
        std::memset(signature_out, 0, 64);
        r.Encode(signature_out, 32);
        s.Encode(signature_out + 32, 32);

        // Secure cleanup
        secureWipeInteger(d);
        secureWipeInteger(k);
        secureWipeInteger(kInv);
        std::memset(msgHash, 0, sizeof(msgHash));

        return 64;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* public_key, size_t public_key_len,
    const uint8_t* signature
) {
    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;

        if (public_key_len == 65 && public_key[0] == 0x04) {
            CryptoPP::ECP::Point point;
            point.x.Decode(public_key + 1, 32);
            point.y.Decode(public_key + 33, 32);
            pubKey.Initialize(CryptoPP::ASN1::secp256r1(), point);
        } else {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        // Convert R||S to DER
        std::vector<uint8_t> derSig;
        derSig.push_back(0x30);
        derSig.push_back(0);

        derSig.push_back(0x02);
        bool rPad = (signature[0] & 0x80) != 0;
        derSig.push_back(rPad ? 33 : 32);
        if (rPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature, signature + 32);

        derSig.push_back(0x02);
        bool sPad = (signature[32] & 0x80) != 0;
        derSig.push_back(sPad ? 33 : 32);
        if (sPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature + 32, signature + 64);

        derSig[1] = derSig.size() - 2;

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier(pubKey);
        return verifier.VerifyMessage(message, message_len, derSig.data(), derSig.size()) ? 0 : static_cast<int32_t>(Error::INVALID_SIGNATURE);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p256(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (public_key_len != 65 || public_key[0] != 0x04) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);

    try {
        CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh(CryptoPP::ASN1::secp256r1());
        // SECURITY FIX [VULN-12]: Use SecByteBlock to auto-wipe shared secret
        CryptoPP::SecByteBlock sharedPoint(ecdh.AgreedValueLength());
        if (!ecdh.Agree(sharedPoint.data(), private_key, public_key + 1)) {
            return static_cast<int32_t>(Error::INTERNAL);
        }
        std::memcpy(shared_secret_out, sharedPoint.data(), 32);
        return 32;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// P-384 (NIST secp384r1) - RFC 6979 Deterministic
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 96) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        // Get curve parameters
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
        params.Initialize(CryptoPP::ASN1::secp384r1());
        const CryptoPP::ECP& ec = params.GetCurve();
        const CryptoPP::Integer& n = params.GetGroupOrder();
        const CryptoPP::Integer halfN = n >> 1;

        // Parse private key (48 bytes for P-384)
        CryptoPP::Integer d(private_key, 48);

        // Validate private key range
        if (d <= 0 || d >= n) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        // Hash message with SHA-384
        uint8_t msgHash[48];
        CryptoPP::SHA384 sha;
        sha.CalculateDigest(msgHash, message, message_len);

        // Generate deterministic k using RFC 6979 with SHA-384
        CryptoPP::Integer k = generateDeterministicK<CryptoPP::SHA384>(d, msgHash, 48, n);

        // Compute R = k * G
        CryptoPP::ECPPoint R = ec.ScalarMultiply(params.GetSubgroupGenerator(), k);

        // r = R.x mod n
        CryptoPP::Integer r = R.x % n;
        if (r.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // z = hash (interpreted as integer)
        CryptoPP::Integer z(msgHash, 48);

        // s = k^-1 * (z + r*d) mod n
        CryptoPP::Integer kInv = k.InverseMod(n);
        CryptoPP::Integer s = (kInv * (z + r * d)) % n;

        if (s.IsZero()) {
            secureWipeInteger(d);
            secureWipeInteger(k);
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // Low-S normalization for signature malleability protection
        if (s > halfN) {
            s = n - s;
        }

        // Encode as compact R||S (96 bytes)
        std::memset(signature_out, 0, 96);
        r.Encode(signature_out, 48);
        s.Encode(signature_out + 48, 48);

        // Secure cleanup
        secureWipeInteger(d);
        secureWipeInteger(k);
        secureWipeInteger(kInv);
        std::memset(msgHash, 0, sizeof(msgHash));

        return 96;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* public_key, size_t public_key_len,
    const uint8_t* signature
) {
    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pubKey;

        if (public_key_len == 97 && public_key[0] == 0x04) {
            CryptoPP::ECP::Point point;
            point.x.Decode(public_key + 1, 48);
            point.y.Decode(public_key + 49, 48);
            pubKey.Initialize(CryptoPP::ASN1::secp384r1(), point);
        } else {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        // Convert R||S to DER
        std::vector<uint8_t> derSig;
        derSig.push_back(0x30);
        derSig.push_back(0);

        derSig.push_back(0x02);
        bool rPad = (signature[0] & 0x80) != 0;
        derSig.push_back(rPad ? 49 : 48);
        if (rPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature, signature + 48);

        derSig.push_back(0x02);
        bool sPad = (signature[48] & 0x80) != 0;
        derSig.push_back(sPad ? 49 : 48);
        if (sPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature + 48, signature + 96);

        derSig[1] = derSig.size() - 2;

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier verifier(pubKey);
        return verifier.VerifyMessage(message, message_len, derSig.data(), derSig.size()) ? 0 : static_cast<int32_t>(Error::INVALID_SIGNATURE);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p384(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 48) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (public_key_len != 97 || public_key[0] != 0x04) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);

    try {
        CryptoPP::ECDH<CryptoPP::ECP>::Domain ecdh(CryptoPP::ASN1::secp384r1());
        // SECURITY FIX [VULN-12]: Use SecByteBlock to auto-wipe shared secret
        CryptoPP::SecByteBlock sharedPoint(ecdh.AgreedValueLength());
        if (!ecdh.Agree(sharedPoint.data(), private_key, public_key + 1)) {
            return static_cast<int32_t>(Error::INTERNAL);
        }
        std::memcpy(shared_secret_out, sharedPoint.data(), 48);
        return 48;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// AES-GCM Encryption
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_aes_gcm_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag
) {
    if (key_len != 32) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (iv_len != 12) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_encrypt(key, key_len, plaintext, pt_len,
                                   iv, iv_len, aad, aad_len, ciphertext, tag);
#else
    // Use non-throwing API due to WASM -fignore-exceptions
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key_len, iv, iv_len);

    // Set data lengths for authentication (AAD length, plaintext length, footer length)
    enc.SpecifyDataLengths(aad_len, pt_len, 0);

    // Process AAD
    if (aad && aad_len > 0) {
        enc.Update(aad, aad_len);
    }

    // Encrypt plaintext
    enc.ProcessData(ciphertext, plaintext, pt_len);

    // Generate authentication tag
    enc.TruncatedFinal(tag, 16);

    return static_cast<int32_t>(pt_len);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_aes_gcm_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag,
    uint8_t* plaintext
) {
    if (key_len != 32) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (iv_len != 12) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_decrypt(key, key_len, ciphertext, ct_len,
                                   iv, iv_len, aad, aad_len, tag, plaintext);
#else
    // Use non-throwing API due to WASM -fignore-exceptions
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key_len, iv, iv_len);

    // For GCM, we need to:
    // 1. Process AAD
    // 2. Decrypt ciphertext
    // 3. Verify the authentication tag

    // Set data lengths for authentication
    dec.SpecifyDataLengths(aad_len, ct_len, 0);

    // Process AAD
    if (aad && aad_len > 0) {
        dec.Update(aad, aad_len);
    }

    // Decrypt ciphertext
    dec.ProcessData(plaintext, ciphertext, ct_len);

    // Verify the tag (TruncatedVerify returns true if tag matches)
    if (!dec.TruncatedVerify(tag, 16)) {
        // Authentication failed - zero out plaintext for safety
        std::memset(plaintext, 0, ct_len);
        return -static_cast<int32_t>(Error::VERIFICATION_FAILED);
    }

    return static_cast<int32_t>(ct_len);
#endif
}

} // namespace hd_wallet
