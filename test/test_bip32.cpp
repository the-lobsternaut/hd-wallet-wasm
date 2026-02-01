/**
 * @file test_bip32.cpp
 * @brief BIP-32 Hierarchical Deterministic Key Tests
 *
 * Comprehensive tests for BIP-32 HD key derivation.
 * Includes all official test vectors from the BIP-32 specification.
 *
 * Test vectors source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

#include "test_framework.h"
#include "hd_wallet/bip32.h"
#include "hd_wallet/types.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace hd_wallet;
using namespace hd_wallet::bip32;

// =============================================================================
// BIP-32 Test Vector Structures
// =============================================================================

struct Bip32DerivationStep {
    const char* path;           // Full path from master
    const char* xpub;           // Expected xpub
    const char* xprv;           // Expected xprv
};

struct Bip32TestVector {
    const char* seed_hex;
    const Bip32DerivationStep* steps;
    size_t num_steps;
};

// =============================================================================
// Test Vector 1: 128-bit seed
// Seed: 000102030405060708090a0b0c0d0e0f
// =============================================================================

static const Bip32DerivationStep VECTOR1_STEPS[] = {
    {
        "m",
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    },
    {
        "m/0'",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    },
    {
        "m/0'/1",
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    },
    {
        "m/0'/1/2'",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    },
    {
        "m/0'/1/2'/2",
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    },
    {
        "m/0'/1/2'/2/1000000000",
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    }
};

static const Bip32TestVector VECTOR1 = {
    "000102030405060708090a0b0c0d0e0f",
    VECTOR1_STEPS,
    sizeof(VECTOR1_STEPS) / sizeof(VECTOR1_STEPS[0])
};

// =============================================================================
// Test Vector 2: 512-bit seed
// =============================================================================

static const Bip32DerivationStep VECTOR2_STEPS[] = {
    {
        "m",
        "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    },
    {
        "m/0",
        "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    },
    {
        "m/0/2147483647'",
        "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    },
    {
        "m/0/2147483647'/1",
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    },
    {
        "m/0/2147483647'/1/2147483646'",
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    },
    {
        "m/0/2147483647'/1/2147483646'/2",
        "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        "xprv9zn8u4KBxsqNQPDKLRm4sF9y2C3fWMvkKahht9mP9TD4dqL1stPaTBY5HpDwkYbPKbWvNgvqq5AchCEMFJd7T2E4bgbFGVA4G6CWLCmiJHq"
    }
};

static const Bip32TestVector VECTOR2 = {
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    VECTOR2_STEPS,
    sizeof(VECTOR2_STEPS) / sizeof(VECTOR2_STEPS[0])
};

// =============================================================================
// Test Vector 3: Retry seed with leading zeros in master key
// =============================================================================

static const Bip32DerivationStep VECTOR3_STEPS[] = {
    {
        "m",
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    },
    {
        "m/0'",
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    }
};

static const Bip32TestVector VECTOR3 = {
    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    VECTOR3_STEPS,
    sizeof(VECTOR3_STEPS) / sizeof(VECTOR3_STEPS[0])
};

// =============================================================================
// Test Vector 4: Derivation path with all hardened
// =============================================================================

static const Bip32DerivationStep VECTOR4_STEPS[] = {
    {
        "m",
        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    },
    {
        "m/0'",
        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    },
    {
        "m/0'/1'",
        "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
        "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    }
};

static const Bip32TestVector VECTOR4 = {
    "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    VECTOR4_STEPS,
    sizeof(VECTOR4_STEPS) / sizeof(VECTOR4_STEPS[0])
};

// =============================================================================
// Test: Official BIP-32 Test Vectors
// =============================================================================

TEST_CASE(BIP32, TestVector1_MasterKey) {
    auto seed = test::hexToBytes(VECTOR1.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto xprvResult = keyResult.value.toXprv();
    ASSERT_OK(xprvResult);
    ASSERT_STR_EQ(VECTOR1_STEPS[0].xprv, xprvResult.value);

    auto xpub = keyResult.value.toXpub();
    ASSERT_STR_EQ(VECTOR1_STEPS[0].xpub, xpub);
}

TEST_CASE(BIP32, TestVector1_Derivations) {
    auto seed = test::hexToBytes(VECTOR1.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    for (size_t i = 1; i < VECTOR1.num_steps; ++i) {
        auto derivedResult = masterResult.value.derivePath(VECTOR1_STEPS[i].path);
        ASSERT_OK(derivedResult);

        auto xprvResult = derivedResult.value.toXprv();
        ASSERT_OK(xprvResult);
        ASSERT_STR_EQ(VECTOR1_STEPS[i].xprv, xprvResult.value);

        auto xpub = derivedResult.value.toXpub();
        ASSERT_STR_EQ(VECTOR1_STEPS[i].xpub, xpub);
    }
}

TEST_CASE(BIP32, TestVector2_MasterKey) {
    auto seed = test::hexToBytes(VECTOR2.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto xprvResult = keyResult.value.toXprv();
    ASSERT_OK(xprvResult);
    ASSERT_STR_EQ(VECTOR2_STEPS[0].xprv, xprvResult.value);

    auto xpub = keyResult.value.toXpub();
    ASSERT_STR_EQ(VECTOR2_STEPS[0].xpub, xpub);
}

TEST_CASE(BIP32, TestVector2_Derivations) {
    auto seed = test::hexToBytes(VECTOR2.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    for (size_t i = 1; i < VECTOR2.num_steps; ++i) {
        auto derivedResult = masterResult.value.derivePath(VECTOR2_STEPS[i].path);
        ASSERT_OK(derivedResult);

        auto xprvResult = derivedResult.value.toXprv();
        ASSERT_OK(xprvResult);
        ASSERT_STR_EQ(VECTOR2_STEPS[i].xprv, xprvResult.value);

        auto xpub = derivedResult.value.toXpub();
        ASSERT_STR_EQ(VECTOR2_STEPS[i].xpub, xpub);
    }
}

TEST_CASE(BIP32, TestVector3_MasterKey) {
    auto seed = test::hexToBytes(VECTOR3.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto xprvResult = keyResult.value.toXprv();
    ASSERT_OK(xprvResult);
    ASSERT_STR_EQ(VECTOR3_STEPS[0].xprv, xprvResult.value);

    auto xpub = keyResult.value.toXpub();
    ASSERT_STR_EQ(VECTOR3_STEPS[0].xpub, xpub);
}

TEST_CASE(BIP32, TestVector3_Derivations) {
    auto seed = test::hexToBytes(VECTOR3.seed_hex);
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    for (size_t i = 1; i < VECTOR3.num_steps; ++i) {
        auto derivedResult = masterResult.value.derivePath(VECTOR3_STEPS[i].path);
        ASSERT_OK(derivedResult);

        auto xprvResult = derivedResult.value.toXprv();
        ASSERT_OK(xprvResult);
        ASSERT_STR_EQ(VECTOR3_STEPS[i].xprv, xprvResult.value);

        auto xpub = derivedResult.value.toXpub();
        ASSERT_STR_EQ(VECTOR3_STEPS[i].xpub, xpub);
    }
}

// =============================================================================
// Test: Hardened Derivation
// =============================================================================

TEST_CASE(BIP32, HardenedDerivation_Index) {
    ASSERT_EQ(0x80000000u, harden(0));
    ASSERT_EQ(0x80000001u, harden(1));
    ASSERT_EQ(0x8000002Cu, harden(44));  // BIP-44
    ASSERT_EQ(0x8000003Cu, harden(60));  // Ethereum
}

TEST_CASE(BIP32, HardenedDerivation_Check) {
    ASSERT_TRUE(isHardened(0x80000000));
    ASSERT_TRUE(isHardened(0x80000001));
    ASSERT_TRUE(isHardened(0xFFFFFFFF));
    ASSERT_FALSE(isHardened(0));
    ASSERT_FALSE(isHardened(1));
    ASSERT_FALSE(isHardened(0x7FFFFFFF));
}

TEST_CASE(BIP32, HardenedDerivation_Unharden) {
    ASSERT_EQ(0u, unharden(0x80000000));
    ASSERT_EQ(1u, unharden(0x80000001));
    ASSERT_EQ(44u, unharden(0x8000002C));
}

TEST_CASE(BIP32, HardenedDerivation_FromPublicKey) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    // Neuter the key (remove private key)
    auto publicKey = masterResult.value.neutered();
    ASSERT_TRUE(publicKey.isNeutered());

    // Trying to derive hardened from public key should fail
    auto hardenedResult = publicKey.deriveChild(harden(0));
    ASSERT_EQ(Error::HARDENED_FROM_PUBLIC, hardenedResult.error);

    // But non-hardened derivation should work
    auto nonHardenedResult = publicKey.deriveChild(0);
    ASSERT_OK(nonHardenedResult);
    ASSERT_TRUE(nonHardenedResult.value.isNeutered());
}

// =============================================================================
// Test: Extended Key Serialization
// =============================================================================

TEST_CASE(BIP32, Serialization_XprvRoundTrip) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto xprvResult = keyResult.value.toXprv();
    ASSERT_OK(xprvResult);

    // Parse it back
    auto parsedResult = ExtendedKey::fromString(xprvResult.value);
    ASSERT_OK(parsedResult);

    // Should have private key
    ASSERT_FALSE(parsedResult.value.isNeutered());

    // Should serialize to same string
    auto xprvResult2 = parsedResult.value.toXprv();
    ASSERT_OK(xprvResult2);
    ASSERT_STR_EQ(xprvResult.value, xprvResult2.value);
}

TEST_CASE(BIP32, Serialization_XpubRoundTrip) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto xpub = keyResult.value.toXpub();

    // Parse it back
    auto parsedResult = ExtendedKey::fromString(xpub);
    ASSERT_OK(parsedResult);

    // Should be neutered (no private key)
    ASSERT_TRUE(parsedResult.value.isNeutered());

    // Should serialize to same string
    auto xpub2 = parsedResult.value.toXpub();
    ASSERT_STR_EQ(xpub, xpub2);
}

TEST_CASE(BIP32, Serialization_InvalidString) {
    // Invalid checksum
    auto result = ExtendedKey::fromString(
        "xprv9s21ZrQH143K3GJpoapnV8SFfuZaEZKzFDdMFpvGaAXF5oisQXe4pJWv8NTJK4GnvYXZj8umJsHvTzXBxhqCeLcMqF5fmNGHvGGxXHpXXXX"
    );
    ASSERT_EQ(Error::INVALID_CHECKSUM, result.error);

    // Too short (fails checksum after Base58 decode)
    result = ExtendedKey::fromString("xprv9s21ZrQH143K3");
    ASSERT_EQ(Error::INVALID_CHECKSUM, result.error);

    // Empty
    result = ExtendedKey::fromString("");
    ASSERT_EQ(Error::INVALID_EXTENDED_KEY, result.error);
}

// =============================================================================
// Test: Path Parsing
// =============================================================================

TEST_CASE(BIP32, PathParsing_Master) {
    auto pathResult = DerivationPath::parse("m");
    ASSERT_OK(pathResult);
    ASSERT_EQ(0u, pathResult.value.depth());
}

TEST_CASE(BIP32, PathParsing_Simple) {
    auto pathResult = DerivationPath::parse("m/0/1/2");
    ASSERT_OK(pathResult);
    ASSERT_EQ(3u, pathResult.value.depth());
    ASSERT_EQ(0u, pathResult.value.components[0].index);
    ASSERT_FALSE(pathResult.value.components[0].hardened);
    ASSERT_EQ(1u, pathResult.value.components[1].index);
    ASSERT_EQ(2u, pathResult.value.components[2].index);
}

TEST_CASE(BIP32, PathParsing_Hardened_Apostrophe) {
    auto pathResult = DerivationPath::parse("m/44'/60'/0'");
    ASSERT_OK(pathResult);
    ASSERT_EQ(3u, pathResult.value.depth());

    ASSERT_EQ(44u, pathResult.value.components[0].index);
    ASSERT_TRUE(pathResult.value.components[0].hardened);

    ASSERT_EQ(60u, pathResult.value.components[1].index);
    ASSERT_TRUE(pathResult.value.components[1].hardened);

    ASSERT_EQ(0u, pathResult.value.components[2].index);
    ASSERT_TRUE(pathResult.value.components[2].hardened);
}

TEST_CASE(BIP32, PathParsing_Hardened_H) {
    auto pathResult = DerivationPath::parse("m/44h/60h/0h");
    ASSERT_OK(pathResult);
    ASSERT_EQ(3u, pathResult.value.depth());

    ASSERT_EQ(44u, pathResult.value.components[0].index);
    ASSERT_TRUE(pathResult.value.components[0].hardened);
}

TEST_CASE(BIP32, PathParsing_Mixed) {
    auto pathResult = DerivationPath::parse("m/44'/0'/0/0");
    ASSERT_OK(pathResult);
    ASSERT_EQ(4u, pathResult.value.depth());

    ASSERT_TRUE(pathResult.value.components[0].hardened);
    ASSERT_TRUE(pathResult.value.components[1].hardened);
    ASSERT_FALSE(pathResult.value.components[2].hardened);
    ASSERT_FALSE(pathResult.value.components[3].hardened);
}

TEST_CASE(BIP32, PathParsing_Invalid) {
    // No 'm' prefix
    auto result = DerivationPath::parse("44'/60'/0'");
    ASSERT_EQ(Error::INVALID_PATH, result.error);

    // Double slash
    result = DerivationPath::parse("m//0");
    ASSERT_EQ(Error::INVALID_PATH, result.error);

    // Invalid character
    result = DerivationPath::parse("m/abc");
    ASSERT_EQ(Error::INVALID_PATH, result.error);
}

TEST_CASE(BIP32, PathParsing_ToString) {
    auto pathResult = DerivationPath::parse("m/44'/60'/0'/0/0");
    ASSERT_OK(pathResult);

    auto pathString = pathResult.value.toString();
    ASSERT_STR_EQ("m/44'/60'/0'/0/0", pathString);
}

// =============================================================================
// Test: BIP-44/49/84 Path Construction
// =============================================================================

TEST_CASE(BIP32, BIP44Path_Bitcoin) {
    auto path = DerivationPath::bip44(0, 0, 0, 0);  // Bitcoin first address
    ASSERT_STR_EQ("m/44'/0'/0'/0/0", path.toString());
}

TEST_CASE(BIP32, BIP44Path_Ethereum) {
    auto path = DerivationPath::bip44(60, 0, 0, 0);  // Ethereum first address
    ASSERT_STR_EQ("m/44'/60'/0'/0/0", path.toString());
}

TEST_CASE(BIP32, BIP49Path_Bitcoin) {
    auto path = DerivationPath::bip49(0, 0, 0, 0);  // BIP-49 P2SH-P2WPKH
    ASSERT_STR_EQ("m/49'/0'/0'/0/0", path.toString());
}

TEST_CASE(BIP32, BIP84Path_Bitcoin) {
    auto path = DerivationPath::bip84(0, 0, 0, 0);  // BIP-84 native SegWit
    ASSERT_STR_EQ("m/84'/0'/0'/0/0", path.toString());
}

// =============================================================================
// Test: Key Properties
// =============================================================================

TEST_CASE(BIP32, KeyProperties_Master) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    ASSERT_TRUE(keyResult.value.isMaster());
    ASSERT_EQ(0u, keyResult.value.depth());
    ASSERT_EQ(0u, keyResult.value.parentFingerprint());
    ASSERT_EQ(0u, keyResult.value.childIndex());
    ASSERT_FALSE(keyResult.value.isNeutered());
}

TEST_CASE(BIP32, KeyProperties_Derived) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    auto childResult = masterResult.value.deriveChild(harden(0));
    ASSERT_OK(childResult);

    ASSERT_FALSE(childResult.value.isMaster());
    ASSERT_EQ(1u, childResult.value.depth());
    ASSERT_EQ(masterResult.value.fingerprint(), childResult.value.parentFingerprint());
    ASSERT_EQ(harden(0), childResult.value.childIndex());
}

TEST_CASE(BIP32, KeyProperties_PublicKey) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto pubkey = keyResult.value.publicKey();
    ASSERT_EQ(33u, pubkey.size());

    // Compressed public key should start with 0x02 or 0x03
    ASSERT_TRUE(pubkey[0] == 0x02 || pubkey[0] == 0x03);
}

TEST_CASE(BIP32, KeyProperties_PrivateKey) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto privkeyResult = keyResult.value.privateKey();
    ASSERT_OK(privkeyResult);
    ASSERT_EQ(32u, privkeyResult.value.size());

    // Neutered key should not have private key
    auto neutered = keyResult.value.neutered();
    auto privkeyResult2 = neutered.privateKey();
    ASSERT_EQ(Error::KEY_DERIVATION_FAILED, privkeyResult2.error);
}

// =============================================================================
// Test: Key Cloning and Wiping
// =============================================================================

TEST_CASE(BIP32, KeyClone) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    auto clone = keyResult.value.clone();

    // Clone should produce same serialization
    auto xprv1 = keyResult.value.toXprv();
    auto xprv2 = clone.toXprv();
    ASSERT_OK(xprv1);
    ASSERT_OK(xprv2);
    ASSERT_STR_EQ(xprv1.value, xprv2.value);
}

TEST_CASE(BIP32, KeyWipe) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto keyResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(keyResult);

    // Wipe the key
    keyResult.value.wipe();

    // After wipe, should be neutered
    ASSERT_TRUE(keyResult.value.isNeutered());
}

// =============================================================================
// Test: Version Bytes
// =============================================================================

TEST_CASE(BIP32, VersionBytes_Mainnet) {
    ASSERT_EQ(0x0488ADE4u, XPRV_VERSION);
    ASSERT_EQ(0x0488B21Eu, XPUB_VERSION);
}

TEST_CASE(BIP32, VersionBytes_Testnet) {
    ASSERT_EQ(0x04358394u, TPRV_VERSION);
    ASSERT_EQ(0x043587CFu, TPUB_VERSION);
}

TEST_CASE(BIP32, VersionBytes_BIP49) {
    ASSERT_EQ(0x049D7878u, YPRV_VERSION);
    ASSERT_EQ(0x049D7CB2u, YPUB_VERSION);
}

TEST_CASE(BIP32, VersionBytes_BIP84) {
    ASSERT_EQ(0x04B2430Cu, ZPRV_VERSION);
    ASSERT_EQ(0x04B24746u, ZPUB_VERSION);
}

// =============================================================================
// Test: Public Key Derivation from Extended Public Key
// =============================================================================

TEST_CASE(BIP32, PublicKeyDerivation_NonHardened) {
    auto seed = test::hexToBytes("000102030405060708090a0b0c0d0e0f");
    ByteVector seedVec(seed.begin(), seed.end());

    auto masterResult = ExtendedKey::fromSeed(seedVec);
    ASSERT_OK(masterResult);

    // Derive m/0'/1 from private key
    auto childPrivResult = masterResult.value.derivePath("m/0'/1");
    ASSERT_OK(childPrivResult);

    // Get xpub at m/0'
    auto parentResult = masterResult.value.derivePath("m/0'");
    ASSERT_OK(parentResult);
    auto parentPub = parentResult.value.neutered();

    // Derive /1 from public key
    auto childPubResult = parentPub.deriveChild(1);
    ASSERT_OK(childPubResult);

    // Both should have same public key
    ASSERT_EQ(childPrivResult.value.publicKey(), childPubResult.value.publicKey());
}

// =============================================================================
// Test: Invalid Seed
// =============================================================================

TEST_CASE(BIP32, InvalidSeed_TooShort) {
    Bytes64 seed{};  // All zeros, but passing only partial
    ByteVector shortSeed(15, 0);  // Less than 16 bytes

    auto result = ExtendedKey::fromSeed(shortSeed);
    ASSERT_EQ(Error::INVALID_SEED, result.error);
}

TEST_CASE(BIP32, InvalidSeed_Empty) {
    ByteVector emptySeed;
    auto result = ExtendedKey::fromSeed(emptySeed);
    ASSERT_EQ(Error::INVALID_SEED, result.error);
}

// =============================================================================
// Test: Path Component
// =============================================================================

TEST_CASE(BIP32, PathComponent_FullIndex) {
    PathComponent normal(44, false);
    ASSERT_EQ(44u, normal.fullIndex());

    PathComponent hardened(44, true);
    ASSERT_EQ(harden(44), hardened.fullIndex());
}
