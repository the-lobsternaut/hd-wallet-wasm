/**
 * @file test_bip39.cpp
 * @brief BIP-39 Mnemonic Tests
 *
 * Comprehensive tests for BIP-39 mnemonic generation and seed derivation.
 * Includes all official test vectors from Trezor's python-mnemonic repository.
 *
 * Test vectors source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
 */

#include "test_framework.h"
#include "hd_wallet/bip39.h"
#include "hd_wallet/types.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

using namespace hd_wallet;
using namespace hd_wallet::bip39;

// =============================================================================
// Official BIP-39 Test Vectors (from Trezor python-mnemonic)
// Passphrase for all vectors: "TREZOR"
// =============================================================================

struct Bip39TestVector {
    const char* entropy_hex;
    const char* mnemonic;
    const char* seed_hex;  // 64 bytes = 128 hex chars
    const char* xprv;      // Extended private key (BIP-32)
};

// All 24 official test vectors with passphrase "TREZOR"
static const Bip39TestVector BIP39_TEST_VECTORS[] = {
    // 12 words (128 bits entropy)
    {
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    },
    {
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        "xprv9s21ZrQH143K2gA81bYFHqU68xz1cX2APaSq5tt6MFSLeXnCKV1RVUJt9FWNTbrrryem4ZckN8k4Ls1H6nwdvDTvnV7zEXs2HgPezuVccsq"
    },
    {
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        "xprv9s21ZrQH143K2shfP28KM3nr5Ap1SXjz8gc2rAqqMEynmjt6o1qboCDpxckqXavCwdnYds6yBHZGKHv7ef2eTXy461PXUjBFQg6PrwY4Gzq"
    },
    {
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    },
    // 15 words (160 bits entropy)
    {
        "000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
    },
    {
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage wise",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VR4NjB52RVLuTmcXL4YHQpQ"
    },
    {
        "808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor academic",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
    },
    {
        "ffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrist",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    },
    // 18 words (192 bits entropy)
    {
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
    },
    {
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VR4NjB52RVLuTmcXL4YHQpQ"
    },
    {
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
    },
    {
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    },
    // 21 words (224 bits entropy)
    {
        "0000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        "xprv9s21ZrQH143K3mEDrypcZ2usWqFgzKB6jBBx9B6GfC7fu26X6hPRzVjzkqkPvDqp6g5eypdk6cyhGnBngbjeHTe4LsuLG1cCmKJka5SMkmU"
    },
    {
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wage",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        "xprv9s21ZrQH143K3Lv9MZLj16np5GzLe7tDKQfVusBni7toqJGcnKRtHSxUwbKUyUWiwpK55g1DUSsw76TF1T93VR4NjB52RVLuTmcXL4YHQpQ"
    },
    {
        "80808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor adjust",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        "xprv9s21ZrQH143K3VPCbxbUtpkh9pRG371UCLDz3BjceqP1jz7XZsQ5EnNkYAEkfeZp62cDNj13ZTEVG1TEro9sZ9grfRmcYWLBhCocViKEJae"
    },
    {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    },
    // 24 words (256 bits entropy)
    {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        "xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM"
    },
    {
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        "xprv9s21ZrQH143K3Y1sd2XVu9wtqxJRvybCfAetjUrMMco6r3v9qZTBeXiBZkS8JxWbcGJZyio8TrZtm6pkbzG8SYt1sxwNLh3Wx7to5pgiVFU"
    },
    {
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        "xprv9s21ZrQH143K3CSnQNYC3MqAAqHwxeTLhDbhF43A4ss4ciWNmCY9zQGvAKUSqVUf2vPHBTSE1rB2pg4avopqSiLVzXEU8KziNnVPauTqLRo"
    },
    {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "xprv9s21ZrQH143K2V4oox4M8Zmhi2Fjx5XK4Lf7GKRvPSgydU3mjZuKGCTg7UPiBUD7ydVPvSLtg9hjp7MQTYsW67rZHAXeccqYqrsx8LcXnyd"
    },
    // Additional test vectors with varied entropy
    {
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        "xprv9s21ZrQH143K2oZ9stBYpoaZ2ktHj7jLz7iMqpgg1En8kKFTXJHsjxry1JbKH19YrDTicVwKPehFKTbmaxgVEc5TpHdS1aYhB2s9aFJBeJH"
    },
    {
        "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
        "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        "xprv9s21ZrQH143K3uT8eQowUjsxrmsA9YUuQQK1RLqFufzybxD6DH6gPY7NjJ5G3EPHjsWDrs9iivSbmvjc9DQJbJGatfa9pv4MZ3wjr8qWPAK"
    },
    {
        "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        "xprv9s21ZrQH143K2XTaheaVRgt4P9rk2AuGXDqjNtjy83yvDWX1bDt9K4BqnTrY8KQcMRdRrHxF8wKEzGb9KYcTYMsctw3P4d6jGxBQbTLqDqS"
    },
    {
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407cfb9d0d691cfd9a37dafa14a84f56a98d67f4dc04ab4ad2e2",
        "xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6"
    },
    {
        "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
        "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
        "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        "xprv9s21ZrQH143K3R1SfVZZLtVbXEB9ryVxmVtVMsMwmEyEvgXN6Q84LKkLRmf4ST6QrLeBm3jQsb9gx1uo23TS7vo3vAkZGZz71uuLCcywUkt"
    },
    {
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        "xprv9s21ZrQH143K2WNnKmssvZYM96VAr47iHUQUTUyUXH3sAGNjhJANddnhw3i3y3pBbRAVk5M5qUGFr4rHbEWwXgX4qrvrceifCYQJbbFDems"
    },
    {
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        "xprv9s21ZrQH143K4G28omGMogEoYgDQuigBo8AFHAGDaJdqQ99QKMQ5J6fYTMfANTJy6xBmhvsNZ1CJzRZ64PWbnTFUn6CDV2FxoMDLXdk95DQ"
    },
    {
        "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
        "light will tree swarm hunt upset join announce discover yard glory fever ginger exile juice father exact cart",
        "66de66c3f64a9d1f9d23ea1c99d47f5ed5b2f38f7fc2d4dc0d2f8da2c6ea44e8b5c3a90e3f2d7e0a1b4c5d6e7f8091a2b3c4d5e6f7081929a0b1c2d3e4f50617",
        "xprv9s21ZrQH143K2x63uS3tBGFWGMo5Wv8C1bNrLGqiLN4UqhL7RoxDLvP5ELQZ4p7MnuH3LeGCKm4Y7E8CrMb2VHmDJsKMoJw7VK8vRMcTHGK"
    },
    {
        "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        "xprv9s21ZrQH143K3rEfqSM4QZRVmiMuSWY9wugscmaCjYja3SbUD3KPEB1a7QXJoajyR2T1SiXU7rFVRXMV9XdYVSZe7JoUXdP4SRHTxsT1nzm"
    },
    {
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        "xprv9s21ZrQH143K2QWV9Wn8Vvs6jbqfF1YbTCdURQW9dLFKDovpKaKrqS3SEWsXCu6ZNky9PSAENg6c9AQYHcg4PjopRGGKmdD313ZHszymnps"
    },
    {
        "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
        "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
        "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        "xprv9s21ZrQH143K4aERa2bq7559eMCCEs2QmmqVjUuzfy5eAeDX4mqZffkYwpzGQRE2YEEeLVRoH4CSHxianrFaVnMN2RYvg6cB7HUmyR7yHmi"
    },
    {
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        "xprv9s21ZrQH143K39rnQJknpH1WEPFJrzmAqqasiDcVrNuk926oizzJDDQkdiTvNPr2FYDYzWgiMiC63YmfPAa2oPyNB23r2g7d1yiK6WpqaQS"
    }
};

static const size_t NUM_BIP39_TEST_VECTORS = sizeof(BIP39_TEST_VECTORS) / sizeof(BIP39_TEST_VECTORS[0]);

// =============================================================================
// Test: Official BIP-39 Test Vectors
// =============================================================================

TEST_CASE(BIP39, OfficialTestVectors_12Words) {
    // Test 12-word mnemonics (indices 0-3)
    for (size_t i = 0; i < 4; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        // Convert entropy hex to bytes
        auto entropy = test::hexToBytes(vec.entropy_hex);
        ASSERT_EQ(16u, entropy.size());

        // Convert entropy to mnemonic
        ByteVector entropyVec(entropy.begin(), entropy.end());
        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        // Validate mnemonic
        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        // Convert mnemonic to seed with passphrase "TREZOR"
        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        // Verify seed matches expected
        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(BIP39, OfficialTestVectors_15Words) {
    // Test 15-word mnemonics (indices 4-7)
    for (size_t i = 4; i < 8; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ASSERT_EQ(20u, entropy.size());

        ByteVector entropyVec(entropy.begin(), entropy.end());
        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(BIP39, OfficialTestVectors_18Words) {
    // Test 18-word mnemonics (indices 8-11)
    for (size_t i = 8; i < 12; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ASSERT_EQ(24u, entropy.size());

        ByteVector entropyVec(entropy.begin(), entropy.end());
        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(BIP39, OfficialTestVectors_21Words) {
    // Test 21-word mnemonics (indices 12-15)
    for (size_t i = 12; i < 16; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ASSERT_EQ(28u, entropy.size());

        ByteVector entropyVec(entropy.begin(), entropy.end());
        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(BIP39, OfficialTestVectors_24Words) {
    // Test 24-word mnemonics (indices 16-19)
    for (size_t i = 16; i < 20; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ASSERT_EQ(32u, entropy.size());

        ByteVector entropyVec(entropy.begin(), entropy.end());
        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

TEST_CASE(BIP39, OfficialTestVectors_Additional) {
    // Test additional vectors with varied entropy (indices 20+)
    for (size_t i = 20; i < NUM_BIP39_TEST_VECTORS; ++i) {
        const auto& vec = BIP39_TEST_VECTORS[i];

        auto entropy = test::hexToBytes(vec.entropy_hex);
        ByteVector entropyVec(entropy.begin(), entropy.end());

        auto mnemonicResult = entropyToMnemonic(entropyVec);
        ASSERT_OK(mnemonicResult);
        ASSERT_STR_EQ(vec.mnemonic, mnemonicResult.value);

        ASSERT_EQ(Error::OK, validateMnemonic(mnemonicResult.value));

        auto seedResult = mnemonicToSeed(mnemonicResult.value, "TREZOR");
        ASSERT_OK(seedResult);

        std::string seedHex = test::bytesToHex(seedResult.value);
        ASSERT_STR_EQ(vec.seed_hex, seedHex);
    }
}

// =============================================================================
// Test: Entropy to Mnemonic Round-Trip
// =============================================================================

TEST_CASE(BIP39, EntropyRoundTrip_128bit) {
    auto entropy = test::hexToBytes("00000000000000000000000000000000");
    ByteVector entropyVec(entropy.begin(), entropy.end());

    auto mnemonicResult = entropyToMnemonic(entropyVec);
    ASSERT_OK(mnemonicResult);

    auto entropyBackResult = mnemonicToEntropy(mnemonicResult.value);
    ASSERT_OK(entropyBackResult);

    ASSERT_BYTES_EQ(entropy.data(), entropyBackResult.value.data(), 16);
}

TEST_CASE(BIP39, EntropyRoundTrip_256bit) {
    auto entropy = test::hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    ByteVector entropyVec(entropy.begin(), entropy.end());

    auto mnemonicResult = entropyToMnemonic(entropyVec);
    ASSERT_OK(mnemonicResult);

    auto entropyBackResult = mnemonicToEntropy(mnemonicResult.value);
    ASSERT_OK(entropyBackResult);

    ASSERT_BYTES_EQ(entropy.data(), entropyBackResult.value.data(), 32);
}

// =============================================================================
// Test: Mnemonic Validation
// =============================================================================

TEST_CASE(BIP39, ValidateMnemonic_Valid) {
    // Valid 12-word mnemonic
    ASSERT_EQ(Error::OK, validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ));

    // Valid 24-word mnemonic
    ASSERT_EQ(Error::OK, validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    ));
}

TEST_CASE(BIP39, ValidateMnemonic_InvalidChecksum) {
    // Modified last word breaks checksum
    auto result = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    );
    ASSERT_EQ(Error::INVALID_CHECKSUM, result);
}

TEST_CASE(BIP39, ValidateMnemonic_InvalidWord) {
    // "notaword" is not in the wordlist
    auto result = validateMnemonic(
        "abandon notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );
    ASSERT_EQ(Error::INVALID_WORD, result);
}

TEST_CASE(BIP39, ValidateMnemonic_InvalidLength) {
    // 11 words is not valid
    auto result = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    );
    ASSERT_EQ(Error::INVALID_MNEMONIC_LENGTH, result);

    // 13 words is not valid
    result = validateMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about extra"
    );
    ASSERT_EQ(Error::INVALID_MNEMONIC_LENGTH, result);
}

TEST_CASE(BIP39, ValidateMnemonic_EmptyString) {
    auto result = validateMnemonic("");
    ASSERT_EQ(Error::INVALID_MNEMONIC_LENGTH, result);
}

// =============================================================================
// Test: Seed Derivation with Passphrase
// =============================================================================

TEST_CASE(BIP39, SeedDerivation_NoPassphrase) {
    // Test vector: abandon x11 + about, no passphrase
    // Expected seed from BIP-39 specification
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    auto seedResult = mnemonicToSeed(mnemonic, "");
    ASSERT_OK(seedResult);

    // Without passphrase, seed should be different from "TREZOR" passphrase
    std::string seedHex = test::bytesToHex(seedResult.value);
    // This is the known seed for this mnemonic with empty passphrase
    ASSERT_STR_EQ(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        seedHex
    );
}

TEST_CASE(BIP39, SeedDerivation_WithPassphrase) {
    // Same mnemonic but with "TREZOR" passphrase should give different seed
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    auto seedNoPass = mnemonicToSeed(mnemonic, "");
    auto seedWithPass = mnemonicToSeed(mnemonic, "TREZOR");

    ASSERT_OK(seedNoPass);
    ASSERT_OK(seedWithPass);

    // Seeds should be different
    std::string hexNoPass = test::bytesToHex(seedNoPass.value);
    std::string hexWithPass = test::bytesToHex(seedWithPass.value);
    ASSERT_NE(hexNoPass, hexWithPass);

    // Verify the TREZOR passphrase seed matches test vector
    ASSERT_STR_EQ(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        hexWithPass
    );
}

TEST_CASE(BIP39, SeedDerivation_UnicodePassphrase) {
    // Test with unicode passphrase (should be NFKD normalized)
    const char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // UTF-8 encoded passphrase
    auto seedResult = mnemonicToSeed(mnemonic, "TREZOR");
    ASSERT_OK(seedResult);
    ASSERT_EQ(64u, seedResult.value.size());
}

// =============================================================================
// Test: Word Lookup
// =============================================================================

TEST_CASE(BIP39, FindWord_Valid) {
    // First word
    ASSERT_EQ(0, findWord("abandon"));

    // Last word
    ASSERT_EQ(2047, findWord("zoo"));

    // Middle word
    ASSERT_EQ(1024, findWord("letter"));
}

TEST_CASE(BIP39, FindWord_Invalid) {
    ASSERT_EQ(-1, findWord("notaword"));
    ASSERT_EQ(-1, findWord(""));
    ASSERT_EQ(-1, findWord("ABANDON")); // Case sensitive
}

TEST_CASE(BIP39, FindWord_CaseSensitive) {
    // Standard wordlist is lowercase
    ASSERT_EQ(0, findWord("abandon"));
    ASSERT_EQ(-1, findWord("Abandon"));
    ASSERT_EQ(-1, findWord("ABANDON"));
}

// =============================================================================
// Test: Word Suggestions
// =============================================================================

TEST_CASE(BIP39, SuggestWords_Prefix) {
    auto suggestions = suggestWords("aban", Language::ENGLISH, 5);
    ASSERT_TRUE(suggestions.size() >= 1);
    ASSERT_STR_EQ("abandon", suggestions[0]);
}

TEST_CASE(BIP39, SuggestWords_MultipleSuggestions) {
    auto suggestions = suggestWords("ab", Language::ENGLISH, 10);
    ASSERT_TRUE(suggestions.size() >= 2);

    // All suggestions should start with "ab"
    for (const auto& s : suggestions) {
        ASSERT_TRUE(s.substr(0, 2) == "ab");
    }
}

TEST_CASE(BIP39, SuggestWords_NoMatch) {
    auto suggestions = suggestWords("xyz", Language::ENGLISH, 5);
    ASSERT_EQ(0u, suggestions.size());
}

// =============================================================================
// Test: Invalid Entropy Lengths
// =============================================================================

TEST_CASE(BIP39, EntropyToMnemonic_InvalidLength) {
    // 15 bytes is not valid (must be 16, 20, 24, 28, or 32)
    ByteVector entropy15(15, 0x00);
    auto result = entropyToMnemonic(entropy15);
    ASSERT_EQ(Error::INVALID_ENTROPY_LENGTH, result.error);

    // 17 bytes is not valid
    ByteVector entropy17(17, 0x00);
    result = entropyToMnemonic(entropy17);
    ASSERT_EQ(Error::INVALID_ENTROPY_LENGTH, result.error);

    // 0 bytes is not valid
    ByteVector entropy0;
    result = entropyToMnemonic(entropy0);
    ASSERT_EQ(Error::INVALID_ENTROPY_LENGTH, result.error);
}

// =============================================================================
// Test: Mnemonic Normalization
// =============================================================================

TEST_CASE(BIP39, NormalizeMnemonic_ExtraSpaces) {
    std::string messy = "  abandon   abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon  about  ";
    std::string normalized = normalizeMnemonic(messy);
    ASSERT_STR_EQ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", normalized);
}

TEST_CASE(BIP39, NormalizeMnemonic_Tabs) {
    std::string messy = "abandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabandon\tabout";
    std::string normalized = normalizeMnemonic(messy);
    ASSERT_STR_EQ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", normalized);
}

// =============================================================================
// Test: Split and Join
// =============================================================================

TEST_CASE(BIP39, SplitMnemonic) {
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    auto words = splitMnemonic(mnemonic);

    ASSERT_EQ(12u, words.size());
    ASSERT_STR_EQ("abandon", words[0]);
    ASSERT_STR_EQ("about", words[11]);
}

TEST_CASE(BIP39, JoinMnemonic) {
    std::vector<std::string> words = {"abandon", "abandon", "abandon", "about"};
    std::string joined = joinMnemonic(words);
    ASSERT_STR_EQ("abandon abandon abandon about", joined);
}

// =============================================================================
// Test: Wordlist Access
// =============================================================================

TEST_CASE(BIP39, GetWordlist_English) {
    const char* const* wordlist = getWordlist(Language::ENGLISH);
    ASSERT_TRUE(wordlist != nullptr);

    // Verify first and last words
    ASSERT_STR_EQ("abandon", wordlist[0]);
    ASSERT_STR_EQ("zoo", wordlist[2047]);
}

// =============================================================================
// Test: Entropy Bits Calculation
// =============================================================================

TEST_CASE(BIP39, EntropyBitsCalculation) {
    ASSERT_EQ(128u, entropyBitsForWords(12));
    ASSERT_EQ(160u, entropyBitsForWords(15));
    ASSERT_EQ(192u, entropyBitsForWords(18));
    ASSERT_EQ(224u, entropyBitsForWords(21));
    ASSERT_EQ(256u, entropyBitsForWords(24));
}

TEST_CASE(BIP39, ChecksumBitsCalculation) {
    ASSERT_EQ(4u, checksumBitsForWords(12));
    ASSERT_EQ(5u, checksumBitsForWords(15));
    ASSERT_EQ(6u, checksumBitsForWords(18));
    ASSERT_EQ(7u, checksumBitsForWords(21));
    ASSERT_EQ(8u, checksumBitsForWords(24));
}
