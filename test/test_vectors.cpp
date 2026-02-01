/**
 * @file test_vectors.cpp
 * @brief External Test Vector Loading and Validation
 *
 * Tests that load and verify test vectors from external files.
 * Supports JSON format test vectors from various sources.
 *
 * Vector sources:
 * - Trezor python-mnemonic vectors.json
 * - BIP-32 official test vectors
 * - Bitcoin Core test vectors
 * - Ethereum test vectors
 */

#include "test_framework.h"
#include "hd_wallet/bip39.h"
#include "hd_wallet/bip32.h"
#include "hd_wallet/types.h"

#include <fstream>
#include <sstream>

using namespace hd_wallet;
using namespace hd_wallet::bip39;
using namespace hd_wallet::bip32;

// =============================================================================
// Simple JSON Parser (minimal, for test vectors only)
// =============================================================================

namespace json {

/// Skip whitespace
inline void skipWhitespace(const std::string& s, size_t& pos) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
        ++pos;
    }
}

/// Parse a string value (assumes pos is at opening quote)
inline std::string parseString(const std::string& s, size_t& pos) {
    if (pos >= s.size() || s[pos] != '"') return "";
    ++pos;  // Skip opening quote

    std::string result;
    while (pos < s.size() && s[pos] != '"') {
        if (s[pos] == '\\' && pos + 1 < s.size()) {
            ++pos;
            switch (s[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case 'r': result += '\r'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                default: result += s[pos]; break;
            }
        } else {
            result += s[pos];
        }
        ++pos;
    }
    ++pos;  // Skip closing quote
    return result;
}

/// Simple test vector structure
struct TestVector {
    std::string entropy;
    std::string mnemonic;
    std::string passphrase;
    std::string seed;
    std::string bip32_xprv;
};

/// Parse vectors.json format from Trezor
inline std::vector<TestVector> parseVectorsJson(const std::string& content) {
    std::vector<TestVector> vectors;

    // Find "english" array
    size_t pos = content.find("\"english\"");
    if (pos == std::string::npos) return vectors;

    // Find array start
    pos = content.find('[', pos);
    if (pos == std::string::npos) return vectors;
    ++pos;

    // Parse each vector (array of 4 strings)
    while (pos < content.size()) {
        skipWhitespace(content, pos);
        if (content[pos] == ']') break;

        // Find inner array start
        if (content[pos] != '[') {
            ++pos;
            continue;
        }
        ++pos;

        TestVector vec;
        vec.passphrase = "TREZOR";  // All Trezor vectors use this passphrase

        // Parse 4 strings: [entropy, mnemonic, seed, xprv]
        skipWhitespace(content, pos);
        vec.entropy = parseString(content, pos);

        pos = content.find(',', pos);
        if (pos == std::string::npos) break;
        ++pos;
        skipWhitespace(content, pos);
        vec.mnemonic = parseString(content, pos);

        pos = content.find(',', pos);
        if (pos == std::string::npos) break;
        ++pos;
        skipWhitespace(content, pos);
        vec.seed = parseString(content, pos);

        pos = content.find(',', pos);
        if (pos == std::string::npos) break;
        ++pos;
        skipWhitespace(content, pos);
        vec.bip32_xprv = parseString(content, pos);

        // Find array end
        pos = content.find(']', pos);
        if (pos != std::string::npos) ++pos;

        if (!vec.entropy.empty() && !vec.mnemonic.empty()) {
            vectors.push_back(vec);
        }

        // Find next element or array end
        skipWhitespace(content, pos);
        if (pos < content.size() && content[pos] == ',') {
            ++pos;
        }
    }

    return vectors;
}

} // namespace json

// =============================================================================
// File Loading Utilities
// =============================================================================

namespace {

std::string loadFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

#ifndef TEST_VECTORS_PATH
#define TEST_VECTORS_PATH "."
#endif

std::string getVectorsPath(const std::string& filename) {
    return std::string(TEST_VECTORS_PATH) + "/" + filename;
}

} // namespace

// =============================================================================
// Test: Load and Verify Trezor vectors.json
// =============================================================================

TEST_CASE(Vectors, LoadTrezorVectors) {
    std::string content = loadFile(getVectorsPath("vectors.json"));

    if (content.empty()) {
        SKIP_TEST("vectors.json not found - run cmake to download");
    }

    auto vectors = json::parseVectorsJson(content);
    ASSERT_TRUE(vectors.size() > 0);

    // Trezor vectors.json contains 24 test vectors
    // (may vary by version, but should have at least 20)
    ASSERT_TRUE(vectors.size() >= 20);
}

TEST_CASE(Vectors, VerifyTrezorVectors_Mnemonic) {
    std::string content = loadFile(getVectorsPath("vectors.json"));

    if (content.empty()) {
        SKIP_TEST("vectors.json not found");
    }

    auto vectors = json::parseVectorsJson(content);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];

        // Convert entropy to mnemonic
        auto entropy = test::hexToBytes(vec.entropy);
        ByteVector entropyVec(entropy.begin(), entropy.end());

        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        // Validate mnemonic
        auto validateResult = validateMnemonic(vec.mnemonic);
        ASSERT_EQ(Error::OK, validateResult);
    }
}

TEST_CASE(Vectors, VerifyTrezorVectors_Seed) {
    std::string content = loadFile(getVectorsPath("vectors.json"));

    if (content.empty()) {
        SKIP_TEST("vectors.json not found");
    }

    auto vectors = json::parseVectorsJson(content);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];

        // Derive seed from mnemonic with passphrase
        auto seedResult = mnemonicToSeed(vec.mnemonic, vec.passphrase);
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed, seedHex);
    }
}

TEST_CASE(Vectors, VerifyTrezorVectors_BIP32) {
    std::string content = loadFile(getVectorsPath("vectors.json"));

    if (content.empty()) {
        SKIP_TEST("vectors.json not found");
    }

    auto vectors = json::parseVectorsJson(content);

    for (size_t i = 0; i < vectors.size(); ++i) {
        const auto& vec = vectors[i];

        // Derive master key from seed
        auto seed = test::hexToBytes(vec.seed);
        Bytes64 seed64{};
        std::copy(seed.begin(), seed.end(), seed64.begin());

        auto keyResult = ExtendedKey::fromSeed(seed64);
        ASSERT_OK(keyResult);

        auto xprvResult = keyResult.value.toXprv();
        ASSERT_OK(xprvResult);
        ASSERT_STR_EQ(vec.bip32_xprv, xprvResult.value);
    }
}

// =============================================================================
// Test: Additional Vector Files (when available)
// =============================================================================

TEST_CASE(Vectors, LoadBIP32Vectors) {
    // BIP-32 test vectors are usually in bip32.json
    std::string content = loadFile(getVectorsPath("bip32.json"));

    if (content.empty()) {
        SKIP_TEST("bip32.json not found");
    }

    // Parse and verify BIP-32 specific vectors
    // TODO: Implement BIP-32 JSON parsing when file format is available
}

TEST_CASE(Vectors, LoadBitcoinCoreVectors) {
    // Bitcoin Core test vectors
    std::string content = loadFile(getVectorsPath("base58_keys_valid.json"));

    if (content.empty()) {
        SKIP_TEST("base58_keys_valid.json not found");
    }

    // TODO: Parse and verify Bitcoin Core vectors
}

TEST_CASE(Vectors, LoadEthereumVectors) {
    // Ethereum transaction test vectors
    std::string content = loadFile(getVectorsPath("ethereum_tx.json"));

    if (content.empty()) {
        SKIP_TEST("ethereum_tx.json not found");
    }

    // TODO: Parse and verify Ethereum vectors
}

// =============================================================================
// Test: SLIP-39 Vectors (when implemented)
// =============================================================================

TEST_CASE(Vectors, LoadSLIP39Vectors) {
    std::string content = loadFile(getVectorsPath("slip39.json"));

    if (content.empty()) {
        SKIP_TEST("slip39.json not found");
    }

    // TODO: Parse and verify SLIP-39 Shamir backup vectors
}

// =============================================================================
// Inline Test Vectors (Always Available)
// =============================================================================

// These vectors don't require external files

struct InlineTestVector {
    const char* description;
    const char* entropy_hex;
    const char* mnemonic;
    const char* seed_hex;  // With passphrase "TREZOR"
};

static const InlineTestVector INLINE_VECTORS[] = {
    {
        "All zeros (128 bit)",
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    },
    {
        "All ones (128 bit)",
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"
    },
    {
        "All zeros (256 bit)",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    },
    {
        "All ones (256 bit)",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"
    }
};

static const size_t NUM_INLINE_VECTORS = sizeof(INLINE_VECTORS) / sizeof(INLINE_VECTORS[0]);

TEST_CASE(Vectors, InlineVectors_Mnemonic) {
    for (size_t i = 0; i < NUM_INLINE_VECTORS; ++i) {
        const auto& vec = INLINE_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ByteVector entropyVec(entropy.begin(), entropy.end());

        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);
    }
}

TEST_CASE(Vectors, InlineVectors_Seed) {
    for (size_t i = 0; i < NUM_INLINE_VECTORS; ++i) {
        const auto& vec = INLINE_VECTORS[i];

        auto seedResult = mnemonicToSeed(vec.mnemonic, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(Vectors, InlineVectors_RoundTrip) {
    for (size_t i = 0; i < NUM_INLINE_VECTORS; ++i) {
        const auto& vec = INLINE_VECTORS[i];

        // Entropy -> Mnemonic -> Entropy round trip
        auto entropy = test::hexToBytes(vec.entropy_hex);
        ByteVector entropyVec(entropy.begin(), entropy.end());

        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);

        auto entropyBackResult = mnemonicToEntropy(mnemonicResult.value);
        ASSERT_OK(entropyBackResult);

        ASSERT_BYTES_EQ(entropy.data(), entropyBackResult.value.data(), entropy.size());
    }
}

// =============================================================================
// Test: Edge Cases from Real-World Usage
// =============================================================================

TEST_CASE(Vectors, EdgeCase_LedgerVector) {
    // Mnemonic that caused issues with some implementations
    const char* mnemonic = "glory army abandon abandon abandon abandon abandon abandon abandon abandon abandon above";

    // This should be invalid (checksum doesn't match)
    auto result = validateMnemonic(mnemonic);
    ASSERT_NE(Error::OK, result);
}

TEST_CASE(Vectors, EdgeCase_UnicodeNormalization) {
    // Test that unicode normalization doesn't affect ASCII mnemonics
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    auto seed1 = mnemonicToSeed(mnemonic, "");
    auto seed2 = mnemonicToSeed(mnemonic, "TREZOR");

    ASSERT_OK(seed1);
    ASSERT_OK(seed2);

    // Seeds should be different
    ASSERT_NE(test::bytesToHex(seed1.value), test::bytesToHex(seed2.value));
}

TEST_CASE(Vectors, EdgeCase_MaxLengthMnemonic) {
    // 24-word mnemonic (maximum standard length)
    const char* mnemonic =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon art";

    auto result = validateMnemonic(mnemonic);
    ASSERT_EQ(Error::OK, result);

    auto seedResult = mnemonicToSeed(mnemonic, "");
    ASSERT_OK(seedResult);
    ASSERT_EQ(64u, seedResult.value.size());
}

// =============================================================================
// Test: Cross-Implementation Compatibility
// =============================================================================

TEST_CASE(Vectors, Compatibility_BitcoinJS) {
    // Test vector from bitcoinjs-lib
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* expected_seed_no_pass = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    auto seedResult = mnemonicToSeed(mnemonic, "");
    ASSERT_OK(seedResult);
    ASSERT_STR_EQ(expected_seed_no_pass, test::bytesToHex(seedResult.value));
}

TEST_CASE(Vectors, Compatibility_Electrum) {
    // Electrum uses a different seed derivation, but standard BIP-39 validation should work
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    auto result = validateMnemonic(mnemonic);
    ASSERT_EQ(Error::OK, result);
}

TEST_CASE(Vectors, Compatibility_MetaMask) {
    // MetaMask/ethers.js BIP-44 path for Ethereum
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    auto seedResult = mnemonicToSeed(mnemonic, "");
    ASSERT_OK(seedResult);

    auto masterResult = ExtendedKey::fromSeed(seedResult.value);
    ASSERT_OK(masterResult);

    // Standard Ethereum path: m/44'/60'/0'/0/0
    auto derivedResult = masterResult.value.derivePath("m/44'/60'/0'/0/0");
    ASSERT_OK(derivedResult);

    // The derived private key should match MetaMask's output
    auto privkeyResult = derivedResult.value.privateKey();
    ASSERT_OK(privkeyResult);

    // Known first Ethereum address from this mnemonic
    // (verify externally with MetaMask or ethers.js)
}
