/**
 * @file bip39.h
 * @brief BIP-39 Mnemonic Code Implementation
 *
 * Implementation of BIP-39: Mnemonic code for generating deterministic keys.
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 *
 * Features:
 * - Generate mnemonic phrases (12, 15, 18, 21, or 24 words)
 * - Validate mnemonic phrases
 * - Convert mnemonic to seed
 * - Support for English wordlist
 * - Word suggestion/autocomplete
 *
 * @note In WASI environments, entropy must be injected before mnemonic generation.
 */

#ifndef HD_WALLET_BIP39_H
#define HD_WALLET_BIP39_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hd_wallet {
namespace bip39 {

// =============================================================================
// Constants
// =============================================================================

/// Number of words in the BIP-39 wordlist
constexpr size_t WORDLIST_SIZE = 2048;

/// Supported mnemonic lengths (in words)
constexpr size_t MNEMONIC_LENGTHS[] = {12, 15, 18, 21, 24};

/// Entropy bits per word count: 12->128, 15->160, 18->192, 21->224, 24->256
constexpr size_t entropyBitsForWords(size_t word_count) {
  return (word_count * 11 * 32) / 33;
}

/// Checksum bits per word count
constexpr size_t checksumBitsForWords(size_t word_count) {
  return word_count * 11 - entropyBitsForWords(word_count);
}

// =============================================================================
// Wordlist
// =============================================================================

/**
 * Supported wordlist languages
 * - ENGLISH is currently compiled and supported.
 * - Other language codes are reserved and currently return NOT_SUPPORTED.
 */
enum class Language : uint8_t {
  ENGLISH = 0,
  JAPANESE = 1,
  KOREAN = 2,
  SPANISH = 3,
  CHINESE_SIMPLIFIED = 4,
  CHINESE_TRADITIONAL = 5,
  FRENCH = 6,
  ITALIAN = 7,
  CZECH = 8,
  PORTUGUESE = 9
};

/**
 * Get the wordlist for a language
 * @param lang Language
 * @return Pointer to array of 2048 words, or nullptr if not available
 */
const char* const* getWordlist(Language lang = Language::ENGLISH);

/**
 * Check if a word is in the wordlist
 * @param word Word to check
 * @param lang Language
 * @return Word index (0-2047), or -1 if not found
 */
int32_t findWord(const std::string& word, Language lang = Language::ENGLISH);

/**
 * Get word suggestions for autocomplete
 * @param prefix Word prefix
 * @param lang Language
 * @param max_suggestions Maximum suggestions to return
 * @return List of matching words
 */
std::vector<std::string> suggestWords(
  const std::string& prefix,
  Language lang = Language::ENGLISH,
  size_t max_suggestions = 5
);

// =============================================================================
// Mnemonic Generation
// =============================================================================

/**
 * Generate a random mnemonic phrase
 *
 * @param word_count Number of words (12, 15, 18, 21, or 24)
 * @param lang Wordlist language
 * @return Result containing mnemonic string or error
 *
 * @note In WASI environments, entropy must be injected first via WasiBridge.
 *       Returns Error::NO_ENTROPY if entropy is not available.
 *
 * @example
 * ```cpp
 * auto result = generateMnemonic(24);
 * if (result.ok()) {
 *   std::cout << "Mnemonic: " << result.value << std::endl;
 * }
 * ```
 */
Result<std::string> generateMnemonic(
  size_t word_count = 24,
  Language lang = Language::ENGLISH
);

/**
 * Generate mnemonic from provided entropy
 *
 * @param entropy Entropy bytes (16, 20, 24, 28, or 32 bytes)
 * @param lang Wordlist language
 * @return Result containing mnemonic string or error
 */
Result<std::string> entropyToMnemonic(
  const ByteVector& entropy,
  Language lang = Language::ENGLISH
);

/**
 * Convert mnemonic back to entropy
 *
 * @param mnemonic Mnemonic phrase (space-separated words)
 * @param lang Wordlist language
 * @return Result containing entropy bytes or error
 */
Result<ByteVector> mnemonicToEntropy(
  const std::string& mnemonic,
  Language lang = Language::ENGLISH
);

// =============================================================================
// Mnemonic Validation
// =============================================================================

/**
 * Validate a mnemonic phrase
 *
 * Checks:
 * - Word count is valid (12, 15, 18, 21, or 24)
 * - All words are in the wordlist
 * - Checksum is valid
 *
 * @param mnemonic Mnemonic phrase (space-separated words)
 * @param lang Wordlist language
 * @return Error::OK if valid, specific error code otherwise
 */
Error validateMnemonic(
  const std::string& mnemonic,
  Language lang = Language::ENGLISH
);

/**
 * Check if mnemonic is valid (convenience function)
 */
inline bool isValidMnemonic(
  const std::string& mnemonic,
  Language lang = Language::ENGLISH
) {
  return validateMnemonic(mnemonic, lang) == Error::OK;
}

// =============================================================================
// Seed Derivation
// =============================================================================

/**
 * Convert mnemonic to 64-byte seed using PBKDF2
 *
 * Uses PBKDF2-HMAC-SHA512 with:
 * - Password: mnemonic (UTF-8 NFKD normalized)
 * - Salt: "mnemonic" + passphrase (UTF-8 NFKD normalized)
 * - Iterations: 2048
 * - Output: 64 bytes
 *
 * @param mnemonic Mnemonic phrase (space-separated words)
 * @param passphrase Optional passphrase (default: empty)
 * @return Result containing 64-byte seed or error
 *
 * @note This function does NOT validate the mnemonic. Call validateMnemonic()
 *       first if you need validation.
 */
Result<Bytes64> mnemonicToSeed(
  const std::string& mnemonic,
  const std::string& passphrase = ""
);

/**
 * Convert mnemonic to seed, returning as vector
 */
Result<ByteVector> mnemonicToSeedVector(
  const std::string& mnemonic,
  const std::string& passphrase = ""
);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Split mnemonic string into word vector
 */
std::vector<std::string> splitMnemonic(const std::string& mnemonic);

/**
 * Join word vector into mnemonic string
 */
std::string joinMnemonic(const std::vector<std::string>& words);

/**
 * Normalize mnemonic (lowercase, single spaces, trim)
 */
std::string normalizeMnemonic(const std::string& mnemonic);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_generate(
  char* output,
  size_t output_size,
  size_t word_count,
  int32_t language
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_validate(
  const char* mnemonic,
  int32_t language
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_to_seed(
  const char* mnemonic,
  const char* passphrase,
  uint8_t* seed_out,
  size_t seed_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_to_entropy(
  const char* mnemonic,
  int32_t language,
  uint8_t* entropy_out,
  size_t* entropy_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_entropy_to_mnemonic(
  const uint8_t* entropy,
  size_t entropy_size,
  int32_t language,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_mnemonic_get_wordlist(int32_t language);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_suggest_word(
  const char* prefix,
  int32_t language,
  char* suggestions_out,
  size_t output_size,
  size_t max_suggestions
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_mnemonic_check_word(
  const char* word,
  int32_t language
);

} // namespace bip39
} // namespace hd_wallet

#endif // HD_WALLET_BIP39_H
