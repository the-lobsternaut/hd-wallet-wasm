/**
 * @file slip44.h
 * @brief SLIP-44 Coin Type Registry
 *
 * Complete registry of SLIP-44 coin types for BIP-44 derivation paths.
 * https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 *
 * Each coin type defines:
 * - Coin type number (used in BIP-44 path: m/44'/coin_type'/...)
 * - Name and symbol
 * - Elliptic curve used
 * - Default purpose (44, 49, 84, etc.)
 * - Network prefixes and address formats
 */

#ifndef HD_WALLET_SLIP44_H
#define HD_WALLET_SLIP44_H

#include "config.h"
#include "types.h"

#include <cstdint>
#include <string>

namespace hd_wallet {
namespace slip44 {

// =============================================================================
// SLIP-44 Coin Type Constants
// =============================================================================

/**
 * SLIP-44 registered coin types
 *
 * The coin type is used in BIP-44 derivation paths:
 *   m / purpose' / coin_type' / account' / change / address_index
 *
 * Values marked with 0x80000000 indicate hardened derivation.
 */

// Bitcoin and forks (secp256k1)
constexpr uint32_t BITCOIN             = 0;      ///< Bitcoin (BTC)
constexpr uint32_t TESTNET             = 1;      ///< Testnet (all coins)
constexpr uint32_t LITECOIN            = 2;      ///< Litecoin (LTC)
constexpr uint32_t DOGECOIN            = 3;      ///< Dogecoin (DOGE)
constexpr uint32_t REDDCOIN            = 4;      ///< Reddcoin (RDD)
constexpr uint32_t DASH                = 5;      ///< Dash (DASH)
constexpr uint32_t PEERCOIN            = 6;      ///< Peercoin (PPC)
constexpr uint32_t NAMECOIN            = 7;      ///< Namecoin (NMC)
constexpr uint32_t FEATHERCOIN         = 8;      ///< Feathercoin (FTC)
constexpr uint32_t COUNTERPARTY        = 9;      ///< Counterparty (XCP)
constexpr uint32_t BLACKCOIN           = 10;     ///< Blackcoin (BLK)
constexpr uint32_t VIACOIN             = 14;     ///< Viacoin (VIA)
constexpr uint32_t VERTCOIN            = 28;     ///< Vertcoin (VTC)
constexpr uint32_t MONACOIN            = 22;     ///< Monacoin (MONA)
constexpr uint32_t DIGIBYTE            = 20;     ///< DigiByte (DGB)
constexpr uint32_t ZCASH               = 133;    ///< Zcash (ZEC)
constexpr uint32_t BITCOIN_CASH        = 145;    ///< Bitcoin Cash (BCH)
constexpr uint32_t BITCOIN_GOLD        = 156;    ///< Bitcoin Gold (BTG)
constexpr uint32_t BITCOIN_SV          = 236;    ///< Bitcoin SV (BSV)

// Ethereum ecosystem (secp256k1)
constexpr uint32_t ETHEREUM            = 60;     ///< Ethereum (ETH)
constexpr uint32_t ETHEREUM_CLASSIC    = 61;     ///< Ethereum Classic (ETC)
constexpr uint32_t ROOTSTOCK           = 137;    ///< RSK (RBTC)
constexpr uint32_t EXPANSE             = 40;     ///< Expanse (EXP)
constexpr uint32_t UBIQ                = 108;    ///< Ubiq (UBQ)
constexpr uint32_t CALLISTO            = 820;    ///< Callisto (CLO)
constexpr uint32_t ELLAISM             = 163;    ///< Ellaism (ELLA)
constexpr uint32_t PIRL                = 164;    ///< Pirl (PIRL)
constexpr uint32_t GOCHAIN             = 6060;   ///< GoChain (GO)
constexpr uint32_t WANCHAIN            = 5718350;///< Wanchain (WAN)
constexpr uint32_t THUNDERTOKEN        = 1001;   ///< ThunderCore (TT)
constexpr uint32_t TOMOCHAIN           = 889;    ///< TomoChain (TOMO)
constexpr uint32_t BINANCE             = 714;    ///< BNB Beacon Chain (BNB)
constexpr uint32_t BINANCE_SMART_CHAIN = 9006;   ///< BNB Smart Chain (uses 60 in practice)
constexpr uint32_t POLYGON             = 966;    ///< Polygon (MATIC)
constexpr uint32_t AVALANCHE           = 9000;   ///< Avalanche C-Chain (AVAX)
constexpr uint32_t ARBITRUM            = 9001;   ///< Arbitrum One (uses 60 in practice)
constexpr uint32_t OPTIMISM            = 614;    ///< Optimism (uses 60 in practice)

// Cosmos ecosystem (secp256k1)
constexpr uint32_t COSMOS              = 118;    ///< Cosmos Hub (ATOM)
constexpr uint32_t TERRA               = 330;    ///< Terra (LUNA)
constexpr uint32_t TERRA2              = 330;    ///< Terra 2.0 (LUNA)
constexpr uint32_t KAVA                = 459;    ///< Kava (KAVA)
constexpr uint32_t SECRET              = 529;    ///< Secret Network (SCRT)
constexpr uint32_t AKASH               = 118;    ///< Akash (AKT) - same as Cosmos
constexpr uint32_t OSMOSIS             = 118;    ///< Osmosis (OSMO) - same as Cosmos
constexpr uint32_t JUNO                = 118;    ///< Juno (JUNO) - same as Cosmos
constexpr uint32_t EVMOS               = 60;     ///< Evmos (EVMOS) - uses ETH path
constexpr uint32_t INJECTIVE           = 60;     ///< Injective (INJ) - uses ETH path
constexpr uint32_t STARGAZE            = 118;    ///< Stargaze (STARS) - same as Cosmos

// Ripple ecosystem (secp256k1/Ed25519)
constexpr uint32_t RIPPLE              = 144;    ///< XRP Ledger (XRP)

// Ed25519 coins
constexpr uint32_t NEM                 = 43;     ///< NEM (XEM)
constexpr uint32_t STELLAR             = 148;    ///< Stellar (XLM)
constexpr uint32_t TEZOS               = 1729;   ///< Tezos (XTZ)
constexpr uint32_t HEDERA              = 3030;   ///< Hedera (HBAR)
constexpr uint32_t ALGORAND            = 283;    ///< Algorand (ALGO)
constexpr uint32_t NEAR                = 397;    ///< NEAR Protocol (NEAR)
constexpr uint32_t APTOS               = 637;    ///< Aptos (APT)
constexpr uint32_t SUI                 = 784;    ///< Sui (SUI)

// Solana (Ed25519)
constexpr uint32_t SOLANA              = 501;    ///< Solana (SOL)

// Cardano (Ed25519 + BIP32-Ed25519)
constexpr uint32_t CARDANO             = 1815;   ///< Cardano (ADA)

// Polkadot ecosystem (Sr25519/Ed25519)
constexpr uint32_t POLKADOT            = 354;    ///< Polkadot (DOT)
constexpr uint32_t KUSAMA              = 434;    ///< Kusama (KSM)
constexpr uint32_t MOONBEAM            = 1284;   ///< Moonbeam (GLMR) - EVM compatible

// Other notable coins
constexpr uint32_t MONERO              = 128;    ///< Monero (XMR)
constexpr uint32_t IOTA                = 4218;   ///< IOTA (MIOTA)
constexpr uint32_t EOS                 = 194;    ///< EOS (EOS)
constexpr uint32_t TRON                = 195;    ///< Tron (TRX)
constexpr uint32_t NEO                 = 888;    ///< Neo (NEO)
constexpr uint32_t ONTOLOGY            = 1024;   ///< Ontology (ONT)
constexpr uint32_t FILECOIN            = 461;    ///< Filecoin (FIL)
constexpr uint32_t THETA               = 500;    ///< Theta (THETA)
constexpr uint32_t VECHAIN             = 818;    ///< VeChain (VET)
constexpr uint32_t HARMONY             = 1023;   ///< Harmony (ONE)
constexpr uint32_t ZILLIQA             = 313;    ///< Zilliqa (ZIL)
constexpr uint32_t FANTOM              = 1007;   ///< Fantom (FTM)
constexpr uint32_t WAVES               = 5741564;///< Waves (WAVES)
constexpr uint32_t ELROND              = 508;    ///< MultiversX (EGLD)
constexpr uint32_t FLOW                = 539;    ///< Flow (FLOW)
constexpr uint32_t INTERNET_COMPUTER   = 223;    ///< Internet Computer (ICP)
constexpr uint32_t ICON                = 74;     ///< ICON (ICX)

// =============================================================================
// Coin Metadata
// =============================================================================

/**
 * Coin metadata structure
 */
struct CoinInfo {
    uint32_t coinType;           ///< SLIP-44 coin type number
    const char* name;            ///< Full coin name
    const char* symbol;          ///< Ticker symbol
    Curve curve;                 ///< Elliptic curve
    uint32_t purpose;            ///< Default BIP purpose (44, 49, 84, etc.)
    bool hasTestnet;             ///< Has testnet support
    const char* mainnetPrefix;   ///< Address prefix (mainnet)
    const char* testnetPrefix;   ///< Address prefix (testnet)
};

/**
 * Get coin information by coin type
 *
 * @param coinType SLIP-44 coin type
 * @return Pointer to CoinInfo, or nullptr if unknown
 */
const CoinInfo* getCoinInfo(uint32_t coinType);

/**
 * Get coin information by symbol
 *
 * @param symbol Ticker symbol (e.g., "BTC", "ETH")
 * @return Pointer to CoinInfo, or nullptr if unknown
 */
const CoinInfo* getCoinInfoBySymbol(const std::string& symbol);

/**
 * Get all registered coin types
 *
 * @return Array of all CoinInfo entries
 */
const CoinInfo* getAllCoins(size_t* count);

/**
 * Get curve for coin type
 *
 * @param coinType SLIP-44 coin type
 * @return Curve for the coin
 */
Curve getCurveForCoin(uint32_t coinType);

/**
 * Get default purpose for coin type
 *
 * @param coinType SLIP-44 coin type
 * @return Default BIP purpose (44, 49, 84, etc.)
 */
uint32_t getDefaultPurpose(uint32_t coinType);

// =============================================================================
// Purpose Constants
// =============================================================================

/**
 * BIP purpose constants for derivation paths
 */
constexpr uint32_t PURPOSE_BIP44 = 44;   ///< Standard BIP-44 (m/44'/coin'/...)
constexpr uint32_t PURPOSE_BIP49 = 49;   ///< P2SH-P2WPKH (m/49'/coin'/...)
constexpr uint32_t PURPOSE_BIP84 = 84;   ///< Native SegWit (m/84'/coin'/...)
constexpr uint32_t PURPOSE_BIP86 = 86;   ///< Taproot (m/86'/coin'/...)

// Non-standard purposes used by specific chains
constexpr uint32_t PURPOSE_SLIP10 = 10;  ///< SLIP-10 for Ed25519
constexpr uint32_t PURPOSE_CIP1852 = 1852; ///< Cardano CIP-1852

// =============================================================================
// Network Definitions
// =============================================================================

/**
 * Bitcoin network version bytes
 */
struct BitcoinNetworkParams {
    uint8_t p2pkhVersion;        ///< P2PKH address version
    uint8_t p2shVersion;         ///< P2SH address version
    uint8_t wifVersion;          ///< WIF private key version
    const char* bech32Hrp;       ///< Bech32 human-readable part
    uint32_t xpubVersion;        ///< Extended public key version
    uint32_t xprvVersion;        ///< Extended private key version
    uint32_t ypubVersion;        ///< BIP-49 extended public key version
    uint32_t yprvVersion;        ///< BIP-49 extended private key version
    uint32_t zpubVersion;        ///< BIP-84 extended public key version
    uint32_t zprvVersion;        ///< BIP-84 extended private key version
};

/// Bitcoin mainnet parameters
constexpr BitcoinNetworkParams BITCOIN_MAINNET = {
    0x00,       // P2PKH: starts with '1'
    0x05,       // P2SH: starts with '3'
    0x80,       // WIF
    "bc",       // Bech32
    0x0488B21E, // xpub
    0x0488ADE4, // xprv
    0x049D7CB2, // ypub
    0x049D7878, // yprv
    0x04B24746, // zpub
    0x04B2430C  // zprv
};

/// Bitcoin testnet parameters
constexpr BitcoinNetworkParams BITCOIN_TESTNET = {
    0x6F,       // P2PKH: starts with 'm' or 'n'
    0xC4,       // P2SH: starts with '2'
    0xEF,       // WIF
    "tb",       // Bech32
    0x043587CF, // tpub
    0x04358394, // tprv
    0x044A5262, // upub
    0x044A4E28, // uprv
    0x045F1CF6, // vpub
    0x045F18BC  // vprv
};

/**
 * Get Bitcoin network parameters
 *
 * @param network Network type
 * @return Network parameters
 */
const BitcoinNetworkParams& getBitcoinNetworkParams(Network network);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_slip44_get_coin_type(const char* symbol);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_slip44_get_coin_name(uint32_t coin_type);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_slip44_get_coin_symbol(uint32_t coin_type);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_slip44_get_curve(uint32_t coin_type);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_slip44_get_default_purpose(uint32_t coin_type);

} // namespace slip44
} // namespace hd_wallet

#endif // HD_WALLET_SLIP44_H
