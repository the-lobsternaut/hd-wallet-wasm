/**
 * @file secure_memory.h
 * @brief Secure Memory Handling for HD Wallet
 *
 * Provides secure memory utilities to protect sensitive cryptographic material:
 * - Secure memory wiping (prevents compiler optimization)
 * - SecureVector for automatic cleanup
 * - SecureAllocator for STL containers
 *
 * All private keys and seeds should use these utilities to ensure
 * sensitive data is properly cleared from memory when no longer needed.
 */

#ifndef HD_WALLET_SECURE_MEMORY_H
#define HD_WALLET_SECURE_MEMORY_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <type_traits>
#include <vector>

namespace hd_wallet {

// =============================================================================
// Secure Wiping
// =============================================================================

/**
 * Securely wipe memory
 *
 * Uses platform-specific methods to prevent compiler from optimizing away
 * the memory clearing operation. This is critical for sensitive data.
 *
 * @param ptr Pointer to memory to wipe
 * @param size Number of bytes to wipe
 *
 * @example
 * ```cpp
 * uint8_t privateKey[32];
 * // ... use private key ...
 * secureWipe(privateKey, sizeof(privateKey));
 * ```
 */
void secureWipe(void* ptr, size_t size);

/**
 * Template version for arrays
 */
template<typename T, size_t N>
void secureWipe(std::array<T, N>& arr) {
    secureWipe(arr.data(), sizeof(T) * N);
}

/**
 * Template version for vectors
 */
template<typename T>
void secureWipe(std::vector<T>& vec) {
    if (!vec.empty()) {
        secureWipe(vec.data(), sizeof(T) * vec.size());
    }
}

/**
 * Secure wipe with volatile access
 *
 * Forces write to actually occur by using volatile pointer.
 * This is the lowest-level implementation.
 *
 * @param ptr Pointer to memory
 * @param size Number of bytes to wipe
 */
void secureWipeVolatile(volatile void* ptr, size_t size);

// =============================================================================
// SecureAllocator
// =============================================================================

/**
 * Allocator that securely wipes memory on deallocation
 *
 * Can be used with STL containers to ensure all allocations are
 * securely wiped when freed.
 *
 * @tparam T Type to allocate
 *
 * @example
 * ```cpp
 * // Vector that wipes memory when destroyed
 * std::vector<uint8_t, SecureAllocator<uint8_t>> secureData;
 *
 * // String that wipes memory when destroyed
 * using SecureString = std::basic_string<char, std::char_traits<char>,
 *                                         SecureAllocator<char>>;
 * SecureString mnemonic = "abandon abandon ... about";
 * ```
 */
template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;

    template<typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };

    SecureAllocator() noexcept = default;

    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(size_type n) {
        if (n > std::size_t(-1) / sizeof(T)) {
            throw std::bad_alloc();
        }
        T* ptr = static_cast<T*>(::operator new(n * sizeof(T)));
        return ptr;
    }

    void deallocate(T* ptr, size_type n) noexcept {
        if (ptr != nullptr && n > 0) {
            secureWipe(ptr, n * sizeof(T));
        }
        ::operator delete(ptr);
    }

    template<typename U, typename... Args>
    void construct(U* ptr, Args&&... args) {
        ::new (static_cast<void*>(ptr)) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }

    bool operator==(const SecureAllocator&) const noexcept { return true; }
    bool operator!=(const SecureAllocator&) const noexcept { return false; }
};

// =============================================================================
// SecureVector
// =============================================================================

/**
 * Vector with secure memory wiping
 *
 * A std::vector that automatically wipes its memory when destroyed or resized.
 *
 * @tparam T Element type (typically uint8_t)
 *
 * @example
 * ```cpp
 * SecureVector<uint8_t> seed(64);
 * // ... fill seed ...
 * // Memory is automatically wiped when seed goes out of scope
 * ```
 */
template<typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

/// Secure byte vector alias
using SecureByteVector = SecureVector<uint8_t>;

/// Secure string alias
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

// =============================================================================
// SecureArray
// =============================================================================

/**
 * Fixed-size array with secure memory wiping
 *
 * Similar to std::array but automatically wipes memory on destruction.
 *
 * @tparam T Element type
 * @tparam N Array size
 *
 * @example
 * ```cpp
 * SecureArray<uint8_t, 32> privateKey;
 * // ... fill key ...
 * // Memory is automatically wiped when privateKey goes out of scope
 * ```
 */
template<typename T, size_t N>
class SecureArray {
public:
    using value_type = T;
    using size_type = size_t;
    using difference_type = ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    using iterator = T*;
    using const_iterator = const T*;

    SecureArray() noexcept {
        std::fill(data_.begin(), data_.end(), T{});
    }

    SecureArray(const SecureArray& other) {
        std::copy(other.data_.begin(), other.data_.end(), data_.begin());
    }

    SecureArray(SecureArray&& other) noexcept {
        std::copy(other.data_.begin(), other.data_.end(), data_.begin());
        secureWipe(other.data_);
    }

    ~SecureArray() {
        secureWipe(data_);
    }

    SecureArray& operator=(const SecureArray& other) {
        if (this != &other) {
            std::copy(other.data_.begin(), other.data_.end(), data_.begin());
        }
        return *this;
    }

    SecureArray& operator=(SecureArray&& other) noexcept {
        if (this != &other) {
            std::copy(other.data_.begin(), other.data_.end(), data_.begin());
            secureWipe(other.data_);
        }
        return *this;
    }

    // Element access
    reference operator[](size_type pos) { return data_[pos]; }
    const_reference operator[](size_type pos) const { return data_[pos]; }
    reference at(size_type pos) { return data_.at(pos); }
    const_reference at(size_type pos) const { return data_.at(pos); }
    reference front() { return data_.front(); }
    const_reference front() const { return data_.front(); }
    reference back() { return data_.back(); }
    const_reference back() const { return data_.back(); }
    pointer data() noexcept { return data_.data(); }
    const_pointer data() const noexcept { return data_.data(); }

    // Iterators
    iterator begin() noexcept { return data_.begin(); }
    const_iterator begin() const noexcept { return data_.begin(); }
    iterator end() noexcept { return data_.end(); }
    const_iterator end() const noexcept { return data_.end(); }

    // Capacity
    constexpr bool empty() const noexcept { return N == 0; }
    constexpr size_type size() const noexcept { return N; }
    constexpr size_type max_size() const noexcept { return N; }

    // Operations
    void fill(const T& value) { data_.fill(value); }
    void wipe() { secureWipe(data_); }

    // Conversion to std::array
    std::array<T, N>& array() { return data_; }
    const std::array<T, N>& array() const { return data_; }

private:
    std::array<T, N> data_;
};

/// Secure 32-byte array (private keys, chain codes)
using SecureBytes32 = SecureArray<uint8_t, 32>;

/// Secure 64-byte array (seeds)
using SecureBytes64 = SecureArray<uint8_t, 64>;

// =============================================================================
// Secure Memory Locking (Platform-Specific)
// =============================================================================

/**
 * Lock memory to prevent swapping to disk
 *
 * On supported platforms (Linux, macOS), this uses mlock() to prevent
 * the memory from being swapped to disk. In WASM environments, this
 * is a no-op.
 *
 * @param ptr Pointer to memory
 * @param size Size in bytes
 * @return true if locking succeeded (or not supported)
 */
bool lockMemory(void* ptr, size_t size);

/**
 * Unlock previously locked memory
 *
 * @param ptr Pointer to memory
 * @param size Size in bytes
 * @return true if unlocking succeeded (or not supported)
 */
bool unlockMemory(void* ptr, size_t size);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_secure_wipe(void* ptr, size_t size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void* hd_alloc(size_t size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_dealloc(void* ptr);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void* hd_secure_alloc(size_t size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_secure_dealloc(void* ptr, size_t size);

} // namespace hd_wallet

#endif // HD_WALLET_SECURE_MEMORY_H
