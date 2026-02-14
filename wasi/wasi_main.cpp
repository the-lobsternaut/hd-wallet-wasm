/**
 * HD Wallet WASI Implementation
 *
 * DEPRECATED: This standalone WASI build uses TweetNaCl primitives without the
 * full Crypto++ security hardening. Prefer the Emscripten WASI target
 * (hd_wallet_wasm_wasi in the main CMakeLists.txt) for production use.
 *
 * Provides: BIP-39 mnemonics, SLIP-10 Ed25519, X25519 ECDH
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "crypto.h"
}

// BIP-39 English wordlist (2048 words)
#include "../src/bip39_wordlist.inc"

// ============================================================================
// Memory Management
// ============================================================================

static uint8_t entropy_pool[64];
static int entropy_available = 0;

extern "C" {

void* hd_alloc(uint32_t size) {
    return malloc(size);
}

void hd_dealloc(void* ptr) {
    free(ptr);
}

void hd_secure_dealloc(void* ptr, uint32_t size) {
    if (ptr && size > 0) {
        hd_secure_wipe(ptr, size);
    }
    free(ptr);
}

void hd_secure_wipe(void* ptr, uint32_t size) {
    if (ptr && size > 0) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *p++ = 0;
        }
        // Compiler barrier: prevent optimizer from removing the writes
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#endif
    }
}

// ============================================================================
// Entropy Management
// ============================================================================

void hd_inject_entropy(const uint8_t* data, uint32_t len) {
    if (len > 64) len = 64;

    // HMAC-based mixing: pool = HMAC-SHA512(data, pool || 0x00)
    // This prevents a single weak injection from overwriting good entropy.
    uint8_t input[65];
    memcpy(input, entropy_pool, 64);
    input[64] = 0x00;
    uint8_t mixed[64];
    crypto_hmac_sha512(mixed, data, len, input, 65);
    memcpy(entropy_pool, mixed, 64);

    // Second update for additional mixing: pool = HMAC-SHA512(data, pool || 0x01)
    memcpy(input, entropy_pool, 64);
    input[64] = 0x01;
    crypto_hmac_sha512(mixed, data, len, input, 65);
    memcpy(entropy_pool, mixed, 64);

    hd_secure_wipe(mixed, sizeof(mixed));
    hd_secure_wipe(input, sizeof(input));
    entropy_available = 2; // SUFFICIENT
}

int32_t hd_get_entropy_status() {
    return entropy_available;
}

// Get random bytes from entropy pool using HMAC-DRBG-style extraction
// with backtracking resistance (pool state updated after each extraction).
static void get_random_bytes(uint8_t* out, size_t len) {
    uint8_t V[64];
    memcpy(V, entropy_pool, 64);

    while (len > 0) {
        // V = HMAC-SHA512(entropy_pool, V) — extract random output
        crypto_hmac_sha512(V, entropy_pool, 64, V, 64);

        size_t copy = len < 64 ? len : 64;
        memcpy(out, V, copy);
        out += copy;
        len -= copy;
    }

    // Backtracking resistance: update pool state so past outputs
    // cannot be recovered if pool is later compromised
    crypto_hmac_sha512(entropy_pool, entropy_pool, 64, V, 64);

    hd_secure_wipe(V, sizeof(V));
}

// ============================================================================
// Version
// ============================================================================

int32_t hd_get_version() {
    return 0x00010005; // 0.1.5
}

// ============================================================================
// BIP-39 Mnemonic
// ============================================================================

// Generate mnemonic (word_count: 12, 15, 18, 21, 24)
int32_t hd_mnemonic_generate(
    char* output,
    uint32_t output_size,
    int32_t word_count,
    int32_t language
) {
    if (!output || output_size < 256) return -2; // Invalid argument
    if (entropy_available < 2) return -100; // No entropy
    if (language != 0) return -3; // Only English supported

    // Determine entropy size from word count
    size_t entropy_bits;
    switch (word_count) {
        case 12: entropy_bits = 128; break;
        case 15: entropy_bits = 160; break;
        case 18: entropy_bits = 192; break;
        case 21: entropy_bits = 224; break;
        case 24: entropy_bits = 256; break;
        default: return -2;
    }

    size_t entropy_bytes = entropy_bits / 8;

    // Generate entropy
    uint8_t entropy[32];
    get_random_bytes(entropy, entropy_bytes);

    // Calculate checksum
    uint8_t hash[32];
    crypto_sha256(hash, entropy, entropy_bytes);

    // Combine entropy + checksum into bit array
    uint8_t combined[33];
    memcpy(combined, entropy, entropy_bytes);
    combined[entropy_bytes] = hash[0]; // First byte of hash contains checksum

    // Extract 11-bit indices
    char* out = output;
    for (int32_t i = 0; i < word_count; i++) {
        size_t bit_pos = i * 11;
        size_t byte_pos = bit_pos / 8;
        size_t bit_offset = bit_pos % 8;

        uint32_t index = 0;
        if (bit_offset <= 5) {
            index = (combined[byte_pos] << (bit_offset + 3)) |
                    (combined[byte_pos + 1] >> (5 - bit_offset));
        } else {
            index = (combined[byte_pos] << (bit_offset + 3)) |
                    (combined[byte_pos + 1] << (bit_offset - 5)) |
                    (combined[byte_pos + 2] >> (13 - bit_offset));
        }
        index &= 0x7FF; // 11 bits

        if (i > 0) *out++ = ' ';
        const char* word = ENGLISH_WORDLIST[index];
        size_t word_len = strlen(word);
        if (out + word_len >= output + output_size - 1) {
            return -4; // Buffer too small
        }
        memcpy(out, word, word_len);
        out += word_len;
    }
    *out = '\0';

    hd_secure_wipe(entropy, sizeof(entropy));
    hd_secure_wipe(combined, sizeof(combined));

    return static_cast<int32_t>(out - output);
}

// Validate mnemonic
int32_t hd_mnemonic_validate(const char* mnemonic, int32_t language) {
    if (!mnemonic) return -202;
    if (language != 0) return -3; // Only English

    // Count words and find indices
    int word_count = 0;
    uint16_t indices[24];
    const char* p = mnemonic;

    while (*p) {
        // Skip spaces
        while (*p == ' ') p++;
        if (!*p) break;

        // Find word end
        const char* word_start = p;
        while (*p && *p != ' ') p++;
        size_t word_len = p - word_start;

        if (word_count >= 24) return -202; // Too many words

        // Find word in wordlist
        int found = -1;
        for (int i = 0; i < 2048; i++) {
            if (strlen(ENGLISH_WORDLIST[i]) == word_len &&
                memcmp(ENGLISH_WORDLIST[i], word_start, word_len) == 0) {
                found = i;
                break;
            }
        }
        if (found < 0) return -200; // Invalid word

        indices[word_count++] = static_cast<uint16_t>(found);
    }

    // Check word count
    if (word_count != 12 && word_count != 15 && word_count != 18 &&
        word_count != 21 && word_count != 24) {
        return -202;
    }

    // Reconstruct entropy and verify checksum
    size_t entropy_bits = word_count * 11 - word_count * 11 / 33;
    size_t entropy_bytes = entropy_bits / 8;
    size_t checksum_bits = word_count * 11 / 33;

    uint8_t combined[33] = {0};
    for (int i = 0; i < word_count; i++) {
        size_t bit_pos = i * 11;
        for (int j = 0; j < 11; j++) {
            size_t pos = bit_pos + j;
            if (indices[i] & (1 << (10 - j))) {
                combined[pos / 8] |= (1 << (7 - pos % 8));
            }
        }
    }

    uint8_t entropy[32];
    memcpy(entropy, combined, entropy_bytes);

    uint8_t hash[32];
    crypto_sha256(hash, entropy, entropy_bytes);

    // Check checksum
    uint8_t expected_checksum = hash[0] >> (8 - checksum_bits);
    uint8_t actual_checksum = combined[entropy_bytes] >> (8 - checksum_bits);

    hd_secure_wipe(entropy, sizeof(entropy));

    if (expected_checksum != actual_checksum) {
        return -201; // Invalid checksum
    }

    return 0; // OK
}

// Convert mnemonic to 64-byte seed using PBKDF2
int32_t hd_mnemonic_to_seed(
    const char* mnemonic,
    const char* passphrase,
    uint8_t* seed_out,
    uint32_t seed_size
) {
    if (!mnemonic || !seed_out || seed_size < 64) return -2;

    // Build salt: "mnemonic" + passphrase
    const char* prefix = "mnemonic";
    size_t prefix_len = 8;
    size_t pass_len = passphrase ? strlen(passphrase) : 0;
    size_t salt_len = prefix_len + pass_len;

    uint8_t* salt = static_cast<uint8_t*>(malloc(salt_len + 1));
    if (!salt) return -4;

    memcpy(salt, prefix, prefix_len);
    if (pass_len > 0) {
        memcpy(salt + prefix_len, passphrase, pass_len);
    }

    // PBKDF2-HMAC-SHA512
    size_t mnemonic_len = strlen(mnemonic);
    crypto_pbkdf2_sha512(
        seed_out, 64,
        reinterpret_cast<const uint8_t*>(mnemonic), mnemonic_len,
        salt, salt_len,
        2048
    );

    hd_secure_wipe(salt, salt_len);
    free(salt);

    return 0;
}

// ============================================================================
// SLIP-10 Ed25519 Key Derivation
// ============================================================================

// Derive Ed25519 key using SLIP-10
int32_t hd_slip10_ed25519_derive_path(
    const uint8_t* seed,
    uint32_t seed_len,
    const char* path,
    uint8_t* key_out,       // 32 bytes
    uint8_t* chain_code_out // 32 bytes
) {
    if (!seed || seed_len < 16 || !path || !key_out || !chain_code_out) {
        return -2;
    }

    // Master key derivation: HMAC-SHA512(key="ed25519 seed", data=seed)
    const char* ed25519_key = "ed25519 seed";
    uint8_t I[64];
    crypto_hmac_sha512(
        I,
        reinterpret_cast<const uint8_t*>(ed25519_key), 12,
        seed, seed_len
    );

    uint8_t key[32], chain_code[32];
    memcpy(key, I, 32);
    memcpy(chain_code, I + 32, 32);

    // Parse path (must be m/...)
    if (path[0] != 'm') return -301;

    const char* p = path + 1;
    while (*p) {
        if (*p == '/') {
            p++;
            uint32_t index = 0;
            bool hardened = false;

            while (*p >= '0' && *p <= '9') {
                index = index * 10 + (*p - '0');
                p++;
            }

            if (*p == '\'') {
                hardened = true;
                index |= 0x80000000;
                p++;
            }

            // SLIP-10 Ed25519 only supports hardened derivation
            if (!hardened) {
                hd_secure_wipe(key, 32);
                hd_secure_wipe(chain_code, 32);
                return -302;
            }

            // Child key derivation
            uint8_t data[1 + 32 + 4];
            data[0] = 0x00;
            memcpy(data + 1, key, 32);
            data[33] = (index >> 24) & 0xFF;
            data[34] = (index >> 16) & 0xFF;
            data[35] = (index >> 8) & 0xFF;
            data[36] = index & 0xFF;

            crypto_hmac_sha512(I, chain_code, 32, data, sizeof(data));
            memcpy(key, I, 32);
            memcpy(chain_code, I + 32, 32);
        } else {
            break;
        }
    }

    memcpy(key_out, key, 32);
    memcpy(chain_code_out, chain_code, 32);

    hd_secure_wipe(key, 32);
    hd_secure_wipe(chain_code, 32);
    hd_secure_wipe(I, 64);

    return 0;
}

// Derive Ed25519 public key from 32-byte seed
int32_t hd_ed25519_pubkey_from_seed(
    const uint8_t* seed,
    uint8_t* pubkey_out,
    uint32_t pubkey_size
) {
    if (!seed || !pubkey_out || pubkey_size < 32) return -2;

    crypto_ed25519_pubkey(pubkey_out, seed);
    return 0;
}

// ============================================================================
// Ed25519 Signing
// ============================================================================

int32_t hd_ed25519_sign(
    const uint8_t* seed,
    uint32_t seed_len,
    const uint8_t* message,
    uint32_t message_len,
    uint8_t* signature_out,
    uint32_t signature_size
) {
    if (!seed || seed_len != 32 || !message || !signature_out || signature_size < 64) {
        return -2;
    }

    // Build secret key (64 bytes): seed || public key
    uint8_t sk[64];
    memcpy(sk, seed, 32);
    crypto_ed25519_pubkey(sk + 32, seed);

    crypto_ed25519_sign(signature_out, message, message_len, sk);

    hd_secure_wipe(sk, sizeof(sk));
    return 64;
}

int32_t hd_ed25519_verify(
    const uint8_t* pubkey,
    uint32_t pubkey_len,
    const uint8_t* message,
    uint32_t message_len,
    const uint8_t* signature,
    uint32_t signature_len
) {
    if (!pubkey || pubkey_len != 32 || !message || !signature || signature_len != 64) {
        return 0; // Invalid = not verified
    }

    int result = crypto_ed25519_verify(signature, message, message_len, pubkey);
    return (result == 0) ? 1 : 0;
}

// ============================================================================
// X25519 Key Exchange
// ============================================================================

int32_t hd_x25519_pubkey(
    const uint8_t* privkey,
    uint8_t* pubkey_out,
    uint32_t pubkey_size
) {
    if (!privkey || !pubkey_out || pubkey_size < 32) return -2;

    crypto_x25519_pubkey(pubkey_out, privkey);
    return 0;
}

int32_t hd_ecdh_x25519(
    const uint8_t* privkey,
    const uint8_t* pubkey,
    uint8_t* shared_out,
    uint32_t shared_size
) {
    if (!privkey || !pubkey || !shared_out || shared_size < 32) return -2;

    int result = crypto_x25519_shared(shared_out, privkey, pubkey);
    return result;
}

} // extern "C"
