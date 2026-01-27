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

#include <cstring>
#include <vector>
#include <string>

namespace hd_wallet {

using Error = hd_wallet::Error;

// =============================================================================
// Hash Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha512(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 64;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_keccak256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::Keccak_256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_ripemd160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::RIPEMD160 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_hash160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    // Hash160 = RIPEMD160(SHA256(data))
    uint8_t sha_out[32];
    CryptoPP::SHA256 sha;
    sha.CalculateDigest(sha_out, data, data_len);
    CryptoPP::RIPEMD160 ripemd;
    ripemd.CalculateDigest(hash_out, sha_out, 32);
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2b(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (out_size < digest_size || digest_size > 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::BLAKE2b hash(false, digest_size);
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(digest_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2s(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (out_size < digest_size || digest_size > 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
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
// secp256k1 Signing
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 72) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey key;
        CryptoPP::Integer privKeyInt(private_key, 32);
        key.Initialize(CryptoPP::ASN1::secp256k1(), privKeyInt);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(key);

        std::string signature;
        CryptoPP::StringSource ss(message, message_len, true,
            new CryptoPP::SignerFilter(rng, signer,
                new CryptoPP::StringSink(signature)
            )
        );

        if (signature.size() > out_size) {
            return static_cast<int32_t>(Error::OUT_OF_MEMORY);
        }

        std::memcpy(signature_out, signature.data(), signature.size());
        return static_cast<int32_t>(signature.size());
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
        if (signature_len != 64) {
            return static_cast<int32_t>(Error::INVALID_SIGNATURE);
        }
        std::vector<uint8_t> derSig;
        derSig.push_back(0x30); // SEQUENCE
        derSig.push_back(0); // length placeholder

        // R
        derSig.push_back(0x02);
        bool rPad = (signature[0] & 0x80) != 0;
        derSig.push_back(rPad ? 33 : 32);
        if (rPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature, signature + 32);

        // S
        derSig.push_back(0x02);
        bool sPad = (signature[32] & 0x80) != 0;
        derSig.push_back(sPad ? 33 : 32);
        if (sPad) derSig.push_back(0);
        derSig.insert(derSig.end(), signature + 32, signature + 64);

        derSig[1] = derSig.size() - 2;

        return verifier.VerifyMessage(message, message_len, derSig.data(), derSig.size()) ? 1 : 0;
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
// P-256 (NIST secp256r1)
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
        CryptoPP::Integer privKeyInt(private_key, 32);
        privKey.Initialize(CryptoPP::ASN1::secp256r1(), privKeyInt);

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer signer(privKey);
        CryptoPP::AutoSeededRandomPool rng;

        size_t sigLen = signer.MaxSignatureLength();
        std::vector<uint8_t> derSig(sigLen);
        sigLen = signer.SignMessage(rng, message, message_len, derSig.data());

        // Convert DER to R||S format
        size_t pos = 3;
        size_t rLen = derSig[pos++];
        const uint8_t* rStart = derSig.data() + pos;
        if (rLen == 33 && rStart[0] == 0) { rStart++; rLen--; }
        pos += derSig[pos-1] == 33 ? 33 : rLen;
        pos++;
        size_t sLen = derSig[pos++];
        const uint8_t* sStart = derSig.data() + pos;
        if (sLen == 33 && sStart[0] == 0) { sStart++; sLen--; }

        std::memset(signature_out, 0, 64);
        std::memcpy(signature_out + (32 - rLen), rStart, rLen);
        std::memcpy(signature_out + 32 + (32 - sLen), sStart, sLen);

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
        std::vector<uint8_t> sharedPoint(ecdh.AgreedValueLength());
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
// P-384 (NIST secp384r1)
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 96) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    try {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privKey;
        CryptoPP::Integer privKeyInt(private_key, 48);
        privKey.Initialize(CryptoPP::ASN1::secp384r1(), privKeyInt);

        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Signer signer(privKey);
        CryptoPP::AutoSeededRandomPool rng;

        size_t sigLen = signer.MaxSignatureLength();
        std::vector<uint8_t> derSig(sigLen);
        sigLen = signer.SignMessage(rng, message, message_len, derSig.data());

        // Parse DER and extract R||S (96 bytes for P-384)
        size_t pos = 3;
        size_t rLen = derSig[pos++];
        const uint8_t* rStart = derSig.data() + pos;
        if (rLen == 49 && rStart[0] == 0) { rStart++; rLen--; }
        pos += derSig[pos-1] == 49 ? 49 : rLen;
        pos++;
        size_t sLen = derSig[pos++];
        const uint8_t* sStart = derSig.data() + pos;
        if (sLen == 49 && sStart[0] == 0) { sStart++; sLen--; }

        std::memset(signature_out, 0, 96);
        std::memcpy(signature_out + (48 - rLen), rStart, rLen);
        std::memcpy(signature_out + 48 + (48 - sLen), sStart, sLen);

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
        std::vector<uint8_t> sharedPoint(ecdh.AgreedValueLength());
        if (!ecdh.Agree(sharedPoint.data(), private_key, public_key + 1)) {
            return static_cast<int32_t>(Error::INTERNAL);
        }
        std::memcpy(shared_secret_out, sharedPoint.data(), 48);
        return 48;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

} // namespace hd_wallet
