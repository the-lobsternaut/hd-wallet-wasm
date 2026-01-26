/**
 * @file bip44.cpp
 * @brief BIP-44 Path Utilities Implementation
 *
 * Provides utilities for working with BIP-44 hierarchical deterministic paths:
 * - Standard SLIP-44 coin type constants
 * - Path building helpers for signing vs encryption keys
 * - Coin type to curve mapping
 *
 * BIP-44 Path Structure:
 *   m / purpose' / coin_type' / account' / change / address_index
 *
 * Where:
 *   - purpose: 44' for BIP-44 (legacy), 49' for BIP-49 (P2SH-SegWit),
 *              84' for BIP-84 (native SegWit), 86' for BIP-86 (Taproot)
 *   - coin_type: SLIP-44 registered coin type
 *   - account: Account index (hardened)
 *   - change: 0 = external (receiving), 1 = internal (change)
 *   - address_index: Address index within the account
 */

#include "hd_wallet/types.h"
#include "hd_wallet/bip32.h"
#include "hd_wallet/config.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace hd_wallet {
namespace bip44 {

// =============================================================================
// SLIP-44 Coin Type Constants
// =============================================================================

/**
 * Standard SLIP-44 coin type values
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
namespace coin_types {

// Major cryptocurrencies
constexpr uint32_t BITCOIN = 0;
constexpr uint32_t BITCOIN_TESTNET = 1;
constexpr uint32_t LITECOIN = 2;
constexpr uint32_t DOGECOIN = 3;
constexpr uint32_t DASH = 5;
constexpr uint32_t NAMECOIN = 7;
constexpr uint32_t PEERCOIN = 6;
constexpr uint32_t ETHEREUM = 60;
constexpr uint32_t ETHEREUM_CLASSIC = 61;
constexpr uint32_t ZCASH = 133;
constexpr uint32_t BITCOIN_CASH = 145;
constexpr uint32_t BITCOIN_GOLD = 156;

// Cosmos ecosystem
constexpr uint32_t COSMOS = 118;
constexpr uint32_t TERRA = 330;
constexpr uint32_t KAVA = 459;
constexpr uint32_t SECRET = 529;
constexpr uint32_t AKASH = 118;  // Uses Cosmos coin type
constexpr uint32_t OSMOSIS = 118;  // Uses Cosmos coin type
constexpr uint32_t JUNO = 118;  // Uses Cosmos coin type
constexpr uint32_t EVMOS = 60;  // Uses Ethereum coin type (EVM compatible)

// Ed25519-based chains
constexpr uint32_t STELLAR = 148;
constexpr uint32_t SOLANA = 501;
constexpr uint32_t POLKADOT = 354;
constexpr uint32_t KUSAMA = 434;
constexpr uint32_t CARDANO = 1815;
constexpr uint32_t TEZOS = 1729;
constexpr uint32_t ALGORAND = 283;
constexpr uint32_t NEAR = 397;
constexpr uint32_t APTOS = 637;
constexpr uint32_t SUI = 784;

// EVM-compatible chains (use Ethereum coin type 60)
constexpr uint32_t BINANCE_SMART_CHAIN = 60;
constexpr uint32_t POLYGON = 60;
constexpr uint32_t AVALANCHE = 60;
constexpr uint32_t FANTOM = 60;
constexpr uint32_t ARBITRUM = 60;
constexpr uint32_t OPTIMISM = 60;

// BNB Beacon Chain (different from BSC)
constexpr uint32_t BINANCE = 714;

// Other notable chains
constexpr uint32_t MONERO = 128;
constexpr uint32_t RIPPLE = 144;
constexpr uint32_t EOS = 194;
constexpr uint32_t TRON = 195;
constexpr uint32_t VECHAIN = 818;
constexpr uint32_t IOTA = 4218;
constexpr uint32_t HEDERA = 3030;
constexpr uint32_t FILECOIN = 461;
constexpr uint32_t FLOW = 539;

// Privacy coins
constexpr uint32_t ZCASH_SAPLING = 133;

// Layer 2 solutions (often use parent chain coin type)
constexpr uint32_t LIGHTNING = 0;  // Uses Bitcoin coin type

} // namespace coin_types

// =============================================================================
// BIP Purpose Constants
// =============================================================================

namespace purposes {

constexpr uint32_t BIP44 = 44;   // Legacy addresses
constexpr uint32_t BIP49 = 49;   // P2SH-wrapped SegWit (P2WPKH-in-P2SH)
constexpr uint32_t BIP84 = 84;   // Native SegWit (P2WPKH)
constexpr uint32_t BIP86 = 86;   // Taproot (P2TR)

// Ethereum-specific
constexpr uint32_t EIP2334 = 2334;  // ETH2 validator keys

// Multi-account discovery
constexpr uint32_t BIP45 = 45;  // Multisig
constexpr uint32_t BIP48 = 48;  // Multi-account

} // namespace purposes

// =============================================================================
// Path Building Helpers
// =============================================================================

/**
 * Build a BIP-44 derivation path string
 *
 * @param purpose BIP purpose (44, 49, 84, 86)
 * @param coin_type SLIP-44 coin type
 * @param account Account index
 * @param change Change indicator (0 = external, 1 = internal)
 * @param index Address index
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @return Number of characters written, or required size if buffer too small
 */
size_t buildPath(uint32_t purpose, uint32_t coin_type, uint32_t account,
                 uint32_t change, uint32_t index,
                 char* output, size_t output_size) {
    // Format: m/purpose'/coin_type'/account'/change/index
    // All levels except change and index are hardened

    char buffer[128];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/%u'/%u'/%u'/%u/%u",
        purpose, coin_type, account, change, index);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

/**
 * Build a signing key path (external chain, change = 0)
 */
size_t buildSigningPath(uint32_t purpose, uint32_t coin_type, uint32_t account,
                        uint32_t index, char* output, size_t output_size) {
    return buildPath(purpose, coin_type, account, 0, index, output, output_size);
}

/**
 * Build an encryption key path (internal chain, change = 1)
 *
 * Note: Using change = 1 for encryption keys is a convention that keeps
 * signing and encryption key derivation separate while using the same master key.
 */
size_t buildEncryptionPath(uint32_t purpose, uint32_t coin_type, uint32_t account,
                           uint32_t index, char* output, size_t output_size) {
    return buildPath(purpose, coin_type, account, 1, index, output, output_size);
}

/**
 * Build path for a specific key purpose
 */
size_t buildPathForPurpose(uint32_t bip_purpose, uint32_t coin_type, uint32_t account,
                           KeyPurpose key_purpose, uint32_t index,
                           char* output, size_t output_size) {
    uint32_t change = (key_purpose == KeyPurpose::ENCRYPTION) ? 1 : 0;
    return buildPath(bip_purpose, coin_type, account, change, index, output, output_size);
}

// =============================================================================
// Coin Type Helpers
// =============================================================================

/**
 * Get the default BIP purpose for a coin type
 *
 * Most chains use BIP-44 (purpose 44'), but Bitcoin can use various purposes
 * depending on the address type desired.
 */
uint32_t getDefaultPurpose(CoinType coin) {
    switch (coin) {
        case CoinType::BITCOIN:
        case CoinType::BITCOIN_TESTNET:
        case CoinType::LITECOIN:
            // Default to native SegWit for Bitcoin-like chains
            return purposes::BIP84;

        case CoinType::ETHEREUM:
        case CoinType::ETHEREUM_CLASSIC:
        case CoinType::BINANCE:
            // Ethereum uses BIP-44
            return purposes::BIP44;

        default:
            return purposes::BIP44;
    }
}

/**
 * Get SLIP-44 coin type from CoinType enum
 */
uint32_t getCoinTypeValue(CoinType coin) {
    // Most CoinType enum values match SLIP-44 directly
    return static_cast<uint32_t>(coin);
}

/**
 * Get the elliptic curve for a coin type
 *
 * This is an alias for the function in types.h, provided here for convenience.
 */
Curve getCurveForCoin(CoinType coin) {
    return coinTypeToCurve(coin);
}

/**
 * Check if a coin type uses hardened derivation for all levels
 *
 * Some chains (especially Ed25519-based) require all derivation to be hardened.
 */
bool requiresHardenedDerivation(CoinType coin) {
    // Ed25519 doesn't support non-hardened derivation
    switch (coin) {
        case CoinType::SOLANA:
        case CoinType::STELLAR:
        case CoinType::CARDANO:
        case CoinType::POLKADOT:
        case CoinType::KUSAMA:
        case CoinType::TEZOS:
            return true;
        default:
            return coinTypeToCurve(coin) == Curve::ED25519;
    }
}

/**
 * Check if coin type is EVM-compatible
 *
 * EVM chains share the same address derivation and transaction format.
 */
bool isEvmCompatible(CoinType coin) {
    switch (coin) {
        case CoinType::ETHEREUM:
        case CoinType::ETHEREUM_CLASSIC:
        case CoinType::ROOTSTOCK:
        case CoinType::BINANCE:  // BSC uses same derivation
            return true;
        default:
            return false;
    }
}

/**
 * Check if coin type is a Bitcoin fork
 *
 * Bitcoin forks typically share the same derivation paths and transaction structure.
 */
bool isBitcoinFork(CoinType coin) {
    switch (coin) {
        case CoinType::BITCOIN:
        case CoinType::BITCOIN_TESTNET:
        case CoinType::LITECOIN:
        case CoinType::DOGECOIN:
        case CoinType::BITCOIN_CASH:
            return true;
        default:
            return false;
    }
}

/**
 * Check if coin type is in the Cosmos ecosystem
 */
bool isCosmosEcosystem(CoinType coin) {
    switch (coin) {
        case CoinType::COSMOS:
        case CoinType::TERRA:
            return true;
        default:
            return false;
    }
}

// =============================================================================
// Path Parsing
// =============================================================================

/**
 * Parse a BIP-44 style path and extract components
 *
 * @param path Path string (e.g., "m/44'/60'/0'/0/0")
 * @param purpose Output: purpose value
 * @param coin_type Output: coin type value
 * @param account Output: account index
 * @param change Output: change value
 * @param index Output: address index
 * @return Error::OK on success, error code on failure
 */
Error parsePath(const char* path, uint32_t* purpose, uint32_t* coin_type,
                uint32_t* account, uint32_t* change, uint32_t* index) {
    if (path == nullptr) {
        return Error::INVALID_ARGUMENT;
    }

    // Skip leading 'm' or 'M' and '/'
    const char* p = path;
    if (*p == 'm' || *p == 'M') {
        ++p;
    }
    if (*p == '/') {
        ++p;
    }

    // Parse up to 5 components
    uint32_t values[5] = {0};
    bool hardened[5] = {false};
    int component = 0;

    while (*p != '\0' && component < 5) {
        // Parse number
        char* end;
        unsigned long val = std::strtoul(p, &end, 10);
        if (end == p) {
            return Error::INVALID_PATH;
        }
        if (val > 0xFFFFFFFF) {
            return Error::INVALID_PATH;
        }

        values[component] = static_cast<uint32_t>(val);

        // Check for hardened indicator
        if (*end == '\'' || *end == 'h' || *end == 'H') {
            hardened[component] = true;
            ++end;
        }

        p = end;

        // Skip separator
        if (*p == '/') {
            ++p;
        }

        ++component;
    }

    // Must have at least purpose and coin_type
    if (component < 2) {
        return Error::INVALID_PATH;
    }

    // Extract values
    if (purpose) *purpose = values[0];
    if (coin_type) *coin_type = values[1];
    if (account) *account = (component >= 3) ? values[2] : 0;
    if (change) *change = (component >= 4) ? values[3] : 0;
    if (index) *index = (component >= 5) ? values[4] : 0;

    return Error::OK;
}

// =============================================================================
// Account Discovery Paths
// =============================================================================

/**
 * Generate standard account paths for discovery
 *
 * Used when scanning for existing accounts in a wallet.
 * Returns the account-level path (m/purpose'/coin'/account')
 *
 * @param purpose BIP purpose
 * @param coin_type SLIP-44 coin type
 * @param account Account index to generate path for
 * @param output Output buffer
 * @param output_size Size of output buffer
 * @return Number of characters written
 */
size_t buildAccountPath(uint32_t purpose, uint32_t coin_type, uint32_t account,
                        char* output, size_t output_size) {
    char buffer[64];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/%u'/%u'/%u'",
        purpose, coin_type, account);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

/**
 * Get the standard gap limit for address scanning
 *
 * The gap limit is the number of consecutive unused addresses to scan
 * before considering an account/chain exhausted.
 */
uint32_t getGapLimit(CoinType coin) {
    switch (coin) {
        case CoinType::BITCOIN:
        case CoinType::LITECOIN:
        case CoinType::BITCOIN_CASH:
            // Bitcoin uses 20 as standard gap limit
            return 20;
        case CoinType::ETHEREUM:
            // Ethereum typically uses only one address, but we scan more for
            // wallets that use multiple
            return 5;
        default:
            return 20;
    }
}

// =============================================================================
// Special Path Formats
// =============================================================================

/**
 * Build Ethereum 2.0 withdrawal path (EIP-2334)
 *
 * Format: m/12381/3600/account/0
 */
size_t buildEth2WithdrawalPath(uint32_t account, char* output, size_t output_size) {
    char buffer[64];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/12381/3600/%u/0", account);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

/**
 * Build Ethereum 2.0 signing path (EIP-2334)
 *
 * Format: m/12381/3600/account/0/0
 */
size_t buildEth2SigningPath(uint32_t account, char* output, size_t output_size) {
    char buffer[64];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/12381/3600/%u/0/0", account);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

/**
 * Build Solana derivation path
 *
 * Solana uses: m/44'/501'/account'/change'
 * Note: All levels are hardened for Ed25519
 */
size_t buildSolanaPath(uint32_t account, uint32_t change, char* output, size_t output_size) {
    char buffer[64];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/44'/501'/%u'/%u'", account, change);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

/**
 * Build Polkadot/Substrate derivation path
 *
 * Format: //network//account (or using BIP-44 style)
 * For BIP-44 compatibility: m/44'/354'/account'
 */
size_t buildPolkadotPath(uint32_t account, char* output, size_t output_size) {
    char buffer[64];
    int written = std::snprintf(buffer, sizeof(buffer),
        "m/44'/354'/%u'/0'/0'", account);

    if (written < 0) {
        return 0;
    }

    size_t len = static_cast<size_t>(written);
    if (output != nullptr && output_size > len) {
        std::strcpy(output, buffer);
    }

    return len;
}

} // namespace bip44

// =============================================================================
// C API Implementation
// =============================================================================

namespace bip32 {

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_path_build(char* out, size_t out_size,
                      uint32_t purpose, uint32_t coin_type,
                      uint32_t account, uint32_t change, uint32_t index) {
    size_t required = bip44::buildPath(purpose, coin_type, account, change, index,
                                        out, out_size);
    if (required == 0) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
    if (out == nullptr || out_size <= required) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_path_parse(const char* path,
                      uint32_t* purpose, uint32_t* coin_type,
                      uint32_t* account, uint32_t* change, uint32_t* index) {
    return static_cast<int32_t>(
        bip44::parsePath(path, purpose, coin_type, account, change, index)
    );
}

} // namespace bip32
} // namespace hd_wallet
