/**
 * @file error.cpp
 * @brief Error Handling Implementation
 *
 * Provides error code to string conversions and helper functions
 * for the HD Wallet library's error handling system.
 */

#include "hd_wallet/types.h"
#include "hd_wallet/config.h"
#include "hd_wallet/bip39.h"

#include <cstdio>
#include <cstring>

namespace hd_wallet {

// =============================================================================
// Error Code to String Conversion
// =============================================================================

/**
 * Convert Error enum to human-readable string
 *
 * @param error Error code
 * @return Static string describing the error
 */
const char* errorToString(Error error) {
    switch (error) {
        // Success
        case Error::OK:
            return "Success";

        // General errors (1-99)
        case Error::UNKNOWN:
            return "Unknown error";
        case Error::INVALID_ARGUMENT:
            return "Invalid argument";
        case Error::NOT_SUPPORTED:
            return "Operation not supported";
        case Error::OUT_OF_MEMORY:
            return "Out of memory";
        case Error::INTERNAL:
            return "Internal error";

        // Entropy errors (100-199)
        case Error::NO_ENTROPY:
            return "No entropy source available";
        case Error::INSUFFICIENT_ENTROPY:
            return "Insufficient entropy for operation";

        // BIP-39 errors (200-299)
        case Error::INVALID_WORD:
            return "Invalid mnemonic word";
        case Error::INVALID_CHECKSUM:
            return "Invalid mnemonic checksum";
        case Error::INVALID_MNEMONIC_LENGTH:
            return "Invalid mnemonic length (must be 12, 15, 18, 21, or 24 words)";
        case Error::INVALID_ENTROPY_LENGTH:
            return "Invalid entropy length (must be 16, 20, 24, 28, or 32 bytes)";

        // BIP-32 errors (300-399)
        case Error::INVALID_SEED:
            return "Invalid seed length (must be 64 bytes)";
        case Error::INVALID_PATH:
            return "Invalid derivation path format";
        case Error::INVALID_CHILD_INDEX:
            return "Invalid child index";
        case Error::HARDENED_FROM_PUBLIC:
            return "Cannot derive hardened child from public key";
        case Error::INVALID_EXTENDED_KEY:
            return "Invalid extended key format";

        // Cryptographic errors (400-499)
        case Error::INVALID_PRIVATE_KEY:
            return "Invalid private key";
        case Error::INVALID_PUBLIC_KEY:
            return "Invalid public key";
        case Error::INVALID_SIGNATURE:
            return "Invalid signature format";
        case Error::VERIFICATION_FAILED:
            return "Signature verification failed";
        case Error::KEY_DERIVATION_FAILED:
            return "Key derivation failed";

        // Transaction errors (500-599)
        case Error::INVALID_TRANSACTION:
            return "Invalid transaction format";
        case Error::INSUFFICIENT_FUNDS:
            return "Insufficient funds for transaction";
        case Error::INVALID_ADDRESS:
            return "Invalid address format";

        // Hardware wallet errors (600-699)
        case Error::DEVICE_NOT_CONNECTED:
            return "Hardware wallet not connected";
        case Error::DEVICE_COMM_ERROR:
            return "Hardware wallet communication error";
        case Error::USER_CANCELLED:
            return "Operation cancelled by user";
        case Error::DEVICE_BUSY:
            return "Hardware wallet is busy";
        case Error::DEVICE_NOT_SUPPORTED:
            return "Operation not supported by this device";

        // WASI bridge errors (700-799)
        case Error::BRIDGE_NOT_SET:
            return "Bridge callback not configured";
        case Error::BRIDGE_FAILED:
            return "Bridge callback failed";
        case Error::NEEDS_BRIDGE:
            return "Feature requires bridge callback in WASI environment";

        // FIPS errors (800-899)
        case Error::FIPS_NOT_ALLOWED:
            return "Algorithm not allowed in FIPS mode";

        default:
            return "Unknown error code";
    }
}

// =============================================================================
// Curve Type to String Conversion
// =============================================================================

/**
 * Convert Curve enum to string name
 *
 * @param curve Curve type
 * @return Static string with curve name
 */
const char* curveToString(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1:
            return "secp256k1";
        case Curve::ED25519:
            return "Ed25519";
        case Curve::P256:
            return "P-256 (secp256r1)";
        case Curve::P384:
            return "P-384 (secp384r1)";
        case Curve::X25519:
            return "X25519";
        default:
            return "Unknown curve";
    }
}

// Note: curvePrivateKeySize, curvePublicKeyCompressedSize, curvePublicKeyUncompressedSize,
// coinTypeToString, and coinTypeToCurve are defined in curves.cpp

// =============================================================================
// WASI Warning to String Conversion
// =============================================================================

/**
 * Convert WasiWarning to human-readable string
 */
const char* wasiWarningToString(WasiWarning warning) {
    switch (warning) {
        case WasiWarning::NONE:
            return "No warning";
        case WasiWarning::NEEDS_ENTROPY:
            return "Feature requires entropy injection first";
        case WasiWarning::NEEDS_BRIDGE:
            return "Feature requires host bridge callback";
        case WasiWarning::NOT_AVAILABLE_WASI:
            return "Feature not available in WASI environment";
        case WasiWarning::DISABLED_FIPS:
            return "Feature disabled in FIPS mode";
        case WasiWarning::NEEDS_CAPABILITY:
            return "Feature requires specific WASI capability";
        default:
            return "Unknown warning";
    }
}

/**
 * Convert WasiFeature to string
 */
const char* wasiFeatureToString(WasiFeature feature) {
    switch (feature) {
        case WasiFeature::RANDOM:
            return "Random number generation";
        case WasiFeature::FILESYSTEM:
            return "Filesystem access";
        case WasiFeature::NETWORK:
            return "Network operations";
        case WasiFeature::USB_HID:
            return "USB/HID device access";
        case WasiFeature::CLOCK:
            return "Clock/time access";
        case WasiFeature::ENVIRONMENT:
            return "Environment variables";
        default:
            return "Unknown feature";
    }
}

// =============================================================================
// Network Type to String Conversion
// =============================================================================

/**
 * Convert Network enum to string
 */
const char* networkToString(Network network) {
    switch (network) {
        case Network::MAINNET:
            return "Mainnet";
        case Network::TESTNET:
            return "Testnet";
        default:
            return "Unknown network";
    }
}

// =============================================================================
// Bitcoin Address Type to String Conversion
// =============================================================================

/**
 * Convert BitcoinAddressType enum to string
 */
const char* bitcoinAddressTypeToString(BitcoinAddressType type) {
    switch (type) {
        case BitcoinAddressType::P2PKH:
            return "P2PKH (Legacy)";
        case BitcoinAddressType::P2SH:
            return "P2SH (Pay-to-Script-Hash)";
        case BitcoinAddressType::P2WPKH:
            return "P2WPKH (Native SegWit)";
        case BitcoinAddressType::P2WSH:
            return "P2WSH (SegWit Script)";
        case BitcoinAddressType::P2TR:
            return "P2TR (Taproot)";
        default:
            return "Unknown address type";
    }
}

// =============================================================================
// Key Purpose to String Conversion
// =============================================================================

/**
 * Convert KeyPurpose enum to string
 */
const char* keyPurposeToString(KeyPurpose purpose) {
    switch (purpose) {
        case KeyPurpose::SIGNING:
            return "Signing (external)";
        case KeyPurpose::ENCRYPTION:
            return "Encryption (internal)";
        default:
            return "Unknown purpose";
    }
}

// =============================================================================
// BIP-39 Language to String Conversion
// =============================================================================

namespace bip39 {

/**
 * Convert Language enum to string
 */
const char* languageToString(Language lang) {
    switch (lang) {
        case Language::ENGLISH:
            return "English";
        case Language::JAPANESE:
            return "Japanese";
        case Language::KOREAN:
            return "Korean";
        case Language::SPANISH:
            return "Spanish";
        case Language::CHINESE_SIMPLIFIED:
            return "Chinese (Simplified)";
        case Language::CHINESE_TRADITIONAL:
            return "Chinese (Traditional)";
        case Language::FRENCH:
            return "French";
        case Language::ITALIAN:
            return "Italian";
        case Language::CZECH:
            return "Czech";
        case Language::PORTUGUESE:
            return "Portuguese";
        default:
            return "Unknown language";
    }
}

} // namespace bip39

// =============================================================================
// Error Formatting Helpers
// =============================================================================

namespace error {

/**
 * Format an error with context
 *
 * @param error Error code
 * @param context Additional context string
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of characters written, or required size if buffer too small
 */
size_t formatError(Error error, const char* context,
                   char* buffer, size_t buffer_size) {
    const char* error_str = errorToString(error);

    if (context == nullptr || context[0] == '\0') {
        // No context, just copy error string
        size_t len = std::strlen(error_str);
        if (buffer != nullptr && buffer_size > 0) {
            // SECURITY FIX [HIGH-01]: Use snprintf instead of strcpy
            std::snprintf(buffer, buffer_size, "%s", error_str);
        }
        return len;
    }

    // Format as "context: error_string"
    size_t context_len = std::strlen(context);
    size_t error_len = std::strlen(error_str);
    size_t total_len = context_len + 2 + error_len;  // +2 for ": "

    if (buffer != nullptr && buffer_size > 0) {
        // SECURITY FIX [HIGH-01]: Use snprintf instead of strcpy/strcat
        std::snprintf(buffer, buffer_size, "%s: %s", context, error_str);
    }

    return total_len;
}

/**
 * Check if error is in a specific category
 */
bool isEntropyError(Error error) {
    int code = static_cast<int>(error);
    return code >= 100 && code < 200;
}

bool isBip39Error(Error error) {
    int code = static_cast<int>(error);
    return code >= 200 && code < 300;
}

bool isBip32Error(Error error) {
    int code = static_cast<int>(error);
    return code >= 300 && code < 400;
}

bool isCryptoError(Error error) {
    int code = static_cast<int>(error);
    return code >= 400 && code < 500;
}

bool isTransactionError(Error error) {
    int code = static_cast<int>(error);
    return code >= 500 && code < 600;
}

bool isHardwareError(Error error) {
    int code = static_cast<int>(error);
    return code >= 600 && code < 700;
}

bool isBridgeError(Error error) {
    int code = static_cast<int>(error);
    return code >= 700 && code < 800;
}

bool isFipsError(Error error) {
    int code = static_cast<int>(error);
    return code >= 800 && code < 900;
}

/**
 * Check if error is recoverable
 * Some errors indicate temporary conditions that may be resolved
 */
bool isRecoverableError(Error error) {
    switch (error) {
        case Error::NO_ENTROPY:
        case Error::INSUFFICIENT_ENTROPY:
        case Error::DEVICE_NOT_CONNECTED:
        case Error::DEVICE_BUSY:
        case Error::USER_CANCELLED:
        case Error::BRIDGE_NOT_SET:
            return true;
        default:
            return false;
    }
}

/**
 * Get suggested action for an error
 */
const char* getSuggestedAction(Error error) {
    switch (error) {
        case Error::NO_ENTROPY:
            return "Inject entropy using hd_inject_entropy() before cryptographic operations";
        case Error::INSUFFICIENT_ENTROPY:
            return "Provide more entropy bytes (at least 32 bytes recommended)";
        case Error::INVALID_MNEMONIC_LENGTH:
            return "Use 12, 15, 18, 21, or 24 words for the mnemonic phrase";
        case Error::INVALID_ENTROPY_LENGTH:
            return "Provide 16, 20, 24, 28, or 32 bytes of entropy";
        case Error::HARDENED_FROM_PUBLIC:
            return "Use the extended private key (xprv) for hardened derivation";
        case Error::DEVICE_NOT_CONNECTED:
            return "Connect the hardware wallet and try again";
        case Error::BRIDGE_NOT_SET:
            return "Register the required bridge callback before using this feature";
        case Error::FIPS_NOT_ALLOWED:
            return "Use FIPS-approved algorithms (P-256, P-384) or disable FIPS mode";
        default:
            return nullptr;
    }
}

} // namespace error

} // namespace hd_wallet
