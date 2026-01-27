/**
 * @file secure_memory.cpp
 * @brief Secure Memory Operations Implementation
 *
 * Provides secure memory handling for cryptographic operations:
 * - Volatile memory wiping to prevent compiler optimization
 * - SecureVector class that auto-wipes on destruction
 * - Memory allocation helpers with secure defaults
 */

#include "hd_wallet/secure_memory.h"
#include "hd_wallet/config.h"
#include "hd_wallet/wasi_bridge.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <vector>

#if !HD_WALLET_IS_WASM
  #if defined(__unix__) || defined(__APPLE__)
    #include <sys/mman.h>
  #elif defined(_WIN32)
    #include <windows.h>
  #endif
#endif

namespace hd_wallet {

// =============================================================================
// Secure Memory Wiping (hd_wallet namespace - matches header declaration)
// =============================================================================

void secureWipe(void* ptr, size_t size) {
    if (ptr == nullptr || size == 0) {
        return;
    }

#if HD_WALLET_SECURE_WIPE
    volatile uint8_t* volatile_ptr = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        volatile_ptr[i] = 0;
    }
    #if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
    #elif defined(_MSC_VER)
        _ReadWriteBarrier();
    #endif
#else
    std::memset(ptr, 0, size);
#endif
}

void secureWipeVolatile(volatile void* ptr, size_t size) {
    if (ptr == nullptr || size == 0) {
        return;
    }
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

bool lockMemory(void* ptr, size_t size) {
#if HD_WALLET_IS_WASM
    (void)ptr;
    (void)size;
    return true;
#elif defined(__unix__) || defined(__APPLE__)
    return mlock(ptr, size) == 0;
#elif defined(_WIN32)
    return VirtualLock(ptr, size) != 0;
#else
    (void)ptr;
    (void)size;
    return false;
#endif
}

bool unlockMemory(void* ptr, size_t size) {
#if HD_WALLET_IS_WASM
    (void)ptr;
    (void)size;
    return true;
#elif defined(__unix__) || defined(__APPLE__)
    return munlock(ptr, size) == 0;
#elif defined(_WIN32)
    return VirtualUnlock(ptr, size) != 0;
#else
    (void)ptr;
    (void)size;
    return false;
#endif
}

// C API implementations
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_secure_wipe(void* ptr, size_t size) {
    secureWipe(ptr, size);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void* hd_alloc(size_t size) {
    return std::malloc(size);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_dealloc(void* ptr) {
    std::free(ptr);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void* hd_secure_alloc(size_t size) {
    void* ptr = std::malloc(size);
    if (ptr) {
        std::memset(ptr, 0, size);
    }
    return ptr;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_secure_dealloc(void* ptr, size_t size) {
    if (ptr) {
        secureWipe(ptr, size);
        std::free(ptr);
    }
}

namespace secure {

// =============================================================================
// Secure Memory Wiping (internal namespace - calls the hd_wallet::secureWipe)
// =============================================================================

/**
 * Wipe a specific type (convenience template)
 */
template<typename T>
void secureWipeType(T& obj) {
    hd_wallet::secureWipe(&obj, sizeof(T));
}

/**
 * Wipe an array (convenience template)
 */
template<typename T, size_t N>
void secureWipeArray(T (&arr)[N]) {
    hd_wallet::secureWipe(arr, sizeof(T) * N);
}

/**
 * Wipe a std::array (convenience template)
 */
template<typename T, size_t N>
void secureWipeStdArray(std::array<T, N>& arr) {
    hd_wallet::secureWipe(arr.data(), sizeof(T) * N);
}

// =============================================================================
// Secure Comparison
// =============================================================================

/**
 * Constant-time memory comparison
 *
 * Compares two memory regions in constant time to prevent timing attacks.
 * Traditional memcmp returns early on first difference, which can leak
 * information about the comparison through timing side-channels.
 *
 * @param a First memory region
 * @param b Second memory region
 * @param size Number of bytes to compare
 * @return true if equal, false otherwise
 */
bool secureCompare(const void* a, const void* b, size_t size) {
    if (size == 0) {
        return true;
    }
    if (a == nullptr || b == nullptr) {
        return false;
    }

    const volatile uint8_t* va = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* vb = static_cast<const volatile uint8_t*>(b);

    volatile uint8_t diff = 0;

    // XOR all bytes together - any difference will show up in diff
    for (size_t i = 0; i < size; ++i) {
        diff |= va[i] ^ vb[i];
    }

    // Return true only if no differences found
    return diff == 0;
}

// =============================================================================
// SecureVector Class
// =============================================================================

/**
 * A vector that automatically wipes its contents on destruction
 *
 * This class provides a drop-in replacement for std::vector<uint8_t>
 * that ensures sensitive data is securely erased when no longer needed.
 *
 * Usage:
 *   SecureVector key(32);
 *   // ... use key ...
 *   // Key is automatically wiped when it goes out of scope
 */
class SecureVector {
public:
    using value_type = uint8_t;
    using size_type = size_t;
    using iterator = uint8_t*;
    using const_iterator = const uint8_t*;

    // ----- Constructors -----

    SecureVector() = default;

    explicit SecureVector(size_t size)
        : data_(size, 0) {}

    SecureVector(size_t size, uint8_t value)
        : data_(size, value) {}

    SecureVector(const uint8_t* data, size_t size)
        : data_(data, data + size) {}

    SecureVector(std::initializer_list<uint8_t> init)
        : data_(init) {}

    // Copy constructor - copies data
    SecureVector(const SecureVector& other)
        : data_(other.data_) {}

    // Move constructor - takes ownership
    SecureVector(SecureVector&& other) noexcept
        : data_(std::move(other.data_)) {}

    // Construct from regular vector
    explicit SecureVector(const std::vector<uint8_t>& vec)
        : data_(vec) {}

    // ----- Destructor -----

    ~SecureVector() {
        wipe();
    }

    // ----- Assignment -----

    SecureVector& operator=(const SecureVector& other) {
        if (this != &other) {
            wipe();
            data_ = other.data_;
        }
        return *this;
    }

    SecureVector& operator=(SecureVector&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    // ----- Access -----

    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }

    uint8_t& operator[](size_t index) { return data_[index]; }
    const uint8_t& operator[](size_t index) const { return data_[index]; }

    uint8_t& at(size_t index) { return data_.at(index); }
    const uint8_t& at(size_t index) const { return data_.at(index); }

    uint8_t& front() { return data_.front(); }
    const uint8_t& front() const { return data_.front(); }

    uint8_t& back() { return data_.back(); }
    const uint8_t& back() const { return data_.back(); }

    // ----- Iterators -----

    iterator begin() { return data_.data(); }
    iterator end() { return data_.data() + data_.size(); }
    const_iterator begin() const { return data_.data(); }
    const_iterator end() const { return data_.data() + data_.size(); }
    const_iterator cbegin() const { return data_.data(); }
    const_iterator cend() const { return data_.data() + data_.size(); }

    // ----- Capacity -----

    bool empty() const { return data_.empty(); }
    size_t size() const { return data_.size(); }
    size_t capacity() const { return data_.capacity(); }

    void reserve(size_t new_cap) {
        // When reserving more space, the old buffer might be reallocated
        // We need to wipe the old buffer if it moves
        if (new_cap > data_.capacity()) {
            uint8_t* old_data = data_.data();
            size_t old_cap = data_.capacity();

            data_.reserve(new_cap);

            // If pointer changed, old memory was freed without wiping
            // Unfortunately we can't wipe it after reallocation
            // This is a limitation of std::vector
            (void)old_data;
            (void)old_cap;
        }
    }

    void shrink_to_fit() {
        // Similar issue - old memory freed without wiping
        data_.shrink_to_fit();
    }

    // ----- Modifiers -----

    void clear() {
        wipe();
        data_.clear();
    }

    void resize(size_t new_size) {
        if (new_size < data_.size()) {
            // Wipe the data being removed
            hd_wallet::secureWipe(data_.data() + new_size, data_.size() - new_size);
        }
        data_.resize(new_size);
    }

    void resize(size_t new_size, uint8_t value) {
        if (new_size < data_.size()) {
            hd_wallet::secureWipe(data_.data() + new_size, data_.size() - new_size);
        }
        data_.resize(new_size, value);
    }

    void push_back(uint8_t value) {
        data_.push_back(value);
    }

    void pop_back() {
        if (!data_.empty()) {
            hd_wallet::secureWipe(&data_.back(), 1);
            data_.pop_back();
        }
    }

    void assign(size_t count, uint8_t value) {
        wipe();
        data_.assign(count, value);
    }

    void assign(const uint8_t* first, const uint8_t* last) {
        wipe();
        data_.assign(first, last);
    }

    void insert(iterator pos, uint8_t value) {
        data_.insert(data_.begin() + (pos - begin()), value);
    }

    void insert(iterator pos, size_t count, uint8_t value) {
        data_.insert(data_.begin() + (pos - begin()), count, value);
    }

    iterator erase(iterator pos) {
        size_t index = pos - begin();
        hd_wallet::secureWipe(&data_[index], 1);
        data_.erase(data_.begin() + index);
        return begin() + index;
    }

    iterator erase(iterator first, iterator last) {
        size_t start = first - begin();
        size_t count = last - first;
        hd_wallet::secureWipe(&data_[start], count);
        data_.erase(data_.begin() + start, data_.begin() + start + count);
        return begin() + start;
    }

    void swap(SecureVector& other) noexcept {
        data_.swap(other.data_);
    }

    // ----- Secure Operations -----

    /**
     * Securely wipe all data
     */
    void wipe() {
        if (!data_.empty()) {
            hd_wallet::secureWipe(data_.data(), data_.size());
        }
    }

    /**
     * Convert to regular vector (copies data)
     */
    std::vector<uint8_t> toVector() const {
        return data_;
    }

    /**
     * Release ownership and return raw vector
     * WARNING: The returned vector will NOT be auto-wiped
     */
    std::vector<uint8_t> release() {
        std::vector<uint8_t> result = std::move(data_);
        data_.clear();
        return result;
    }

    /**
     * Compare securely (constant time)
     */
    bool secureEqual(const SecureVector& other) const {
        if (data_.size() != other.data_.size()) {
            return false;
        }
        return secureCompare(data_.data(), other.data_.data(), data_.size());
    }

private:
    std::vector<uint8_t> data_;
};

// Free function for secure comparison
inline bool operator==(const SecureVector& a, const SecureVector& b) {
    return a.secureEqual(b);
}

inline bool operator!=(const SecureVector& a, const SecureVector& b) {
    return !a.secureEqual(b);
}

// =============================================================================
// Secure Allocator
// =============================================================================

/**
 * Custom allocator that wipes memory on deallocation
 *
 * Can be used with STL containers:
 *   std::vector<uint8_t, SecureAllocator<uint8_t>> secure_vec;
 */
template<typename T>
class SecureAllocator {
public:
    using value_type = T;
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = size_t;
    using difference_type = ptrdiff_t;

    template<typename U>
    struct rebind {
        using other = SecureAllocator<U>;
    };

    SecureAllocator() noexcept = default;

    template<typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(size_t n) {
        if (n > static_cast<size_t>(-1) / sizeof(T)) {
#if defined(__wasi__) || defined(HD_WALLET_NO_EXCEPTIONS)
            std::abort();
#else
            throw std::bad_alloc();
#endif
        }
        T* ptr = static_cast<T*>(std::malloc(n * sizeof(T)));
        if (!ptr) {
#if defined(__wasi__) || defined(HD_WALLET_NO_EXCEPTIONS)
            std::abort();
#else
            throw std::bad_alloc();
#endif
        }
        return ptr;
    }

    void deallocate(T* ptr, size_t n) noexcept {
        if (ptr) {
            hd_wallet::secureWipe(ptr, n * sizeof(T));
            std::free(ptr);
        }
    }

    template<typename U, typename... Args>
    void construct(U* ptr, Args&&... args) {
        new (ptr) U(std::forward<Args>(args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
};

template<typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return true;
}

template<typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) noexcept {
    return false;
}

// =============================================================================
// Secure String
// =============================================================================

/**
 * A string that automatically wipes its contents on destruction
 */
class SecureString {
public:
    SecureString() = default;

    explicit SecureString(const char* str)
        : data_(str ? str : "") {}

    explicit SecureString(const std::string& str)
        : data_(str) {}

    SecureString(const char* str, size_t len)
        : data_(str, len) {}

    SecureString(size_t count, char ch)
        : data_(count, ch) {}

    SecureString(const SecureString& other)
        : data_(other.data_) {}

    SecureString(SecureString&& other) noexcept
        : data_(std::move(other.data_)) {}

    ~SecureString() {
        wipe();
    }

    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            wipe();
            data_ = other.data_;
        }
        return *this;
    }

    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    SecureString& operator=(const char* str) {
        wipe();
        data_ = str ? str : "";
        return *this;
    }

    SecureString& operator=(const std::string& str) {
        wipe();
        data_ = str;
        return *this;
    }

    // Access
    const char* c_str() const { return data_.c_str(); }
    const char* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    size_t length() const { return data_.length(); }
    bool empty() const { return data_.empty(); }

    char& operator[](size_t pos) { return data_[pos]; }
    const char& operator[](size_t pos) const { return data_[pos]; }

    // Modifiers
    void clear() {
        wipe();
        data_.clear();
    }

    void append(const char* str) {
        if (str) data_.append(str);
    }

    void append(const std::string& str) {
        data_.append(str);
    }

    SecureString& operator+=(char ch) {
        data_ += ch;
        return *this;
    }

    SecureString& operator+=(const char* str) {
        if (str) data_ += str;
        return *this;
    }

    // Conversion
    std::string toString() const {
        return data_;
    }

    // Secure operations
    void wipe() {
        if (!data_.empty()) {
            hd_wallet::secureWipe(&data_[0], data_.size());
        }
    }

private:
    std::string data_;
};

// Memory locking functions are defined in the hd_wallet namespace above

// =============================================================================
// SecureBytes - Fixed Size Secure Array
// =============================================================================

/**
 * Fixed-size secure byte array
 *
 * Automatically wipes on destruction and provides constant-time comparison.
 */
template<size_t N>
class SecureBytes {
public:
    static constexpr size_t SIZE = N;

    SecureBytes() {
        std::fill(data_.begin(), data_.end(), 0);
    }

    explicit SecureBytes(const uint8_t* data) {
        if (data) {
            std::copy(data, data + N, data_.begin());
        } else {
            std::fill(data_.begin(), data_.end(), 0);
        }
    }

    SecureBytes(const std::array<uint8_t, N>& arr)
        : data_(arr) {}

    SecureBytes(const SecureBytes& other)
        : data_(other.data_) {}

    SecureBytes(SecureBytes&& other) noexcept
        : data_(std::move(other.data_)) {
        other.data_.fill(0);
    }

    ~SecureBytes() {
        wipe();
    }

    SecureBytes& operator=(const SecureBytes& other) {
        if (this != &other) {
            wipe();
            data_ = other.data_;
        }
        return *this;
    }

    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.data_.fill(0);
        }
        return *this;
    }

    // Access
    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    constexpr size_t size() const { return N; }

    uint8_t& operator[](size_t index) { return data_[index]; }
    const uint8_t& operator[](size_t index) const { return data_[index]; }

    auto begin() { return data_.begin(); }
    auto end() { return data_.end(); }
    auto begin() const { return data_.begin(); }
    auto end() const { return data_.end(); }

    // Secure operations
    void wipe() {
        hd_wallet::secureWipe(data_.data(), N);
    }

    void fill(uint8_t value) {
        std::fill(data_.begin(), data_.end(), value);
    }

    bool secureEqual(const SecureBytes& other) const {
        return secureCompare(data_.data(), other.data_.data(), N);
    }

    // Conversion
    std::array<uint8_t, N> toArray() const {
        return data_;
    }

    std::vector<uint8_t> toVector() const {
        return std::vector<uint8_t>(data_.begin(), data_.end());
    }

private:
    std::array<uint8_t, N> data_;
};

template<size_t N>
bool operator==(const SecureBytes<N>& a, const SecureBytes<N>& b) {
    return a.secureEqual(b);
}

template<size_t N>
bool operator!=(const SecureBytes<N>& a, const SecureBytes<N>& b) {
    return !a.secureEqual(b);
}

// Common sizes
using SecureBytes32 = SecureBytes<32>;
using SecureBytes64 = SecureBytes<64>;

// =============================================================================
// Explicit Template Instantiations
// =============================================================================

// Force instantiation of common types
template void secureWipeType<uint8_t>(uint8_t&);
template void secureWipeType<uint16_t>(uint16_t&);
template void secureWipeType<uint32_t>(uint32_t&);
template void secureWipeType<uint64_t>(uint64_t&);

template class SecureBytes<32>;
template class SecureBytes<33>;
template class SecureBytes<64>;
template class SecureBytes<65>;

template class SecureAllocator<uint8_t>;
template class SecureAllocator<char>;

} // namespace secure

// =============================================================================
// MaskedKey Implementation (in hd_wallet namespace)
// =============================================================================

template<size_t N>
void MaskedKey<N>::initializeMask() {
    // Try to get entropy from the WASI bridge
    auto& bridge = WasiBridge::instance();
    int32_t result = bridge.getEntropy(mask_.data(), N);

    if (result != static_cast<int32_t>(N)) {
        // Fallback: Use a deterministic but unpredictable pattern
        // This is less secure but better than nothing
        // Mix in the address of this object for some entropy
        uintptr_t addr = reinterpret_cast<uintptr_t>(this);
        for (size_t i = 0; i < N; ++i) {
            // Simple PRNG-like mixing
            addr = addr * 6364136223846793005ULL + 1442695040888963407ULL;
            mask_[i] = static_cast<uint8_t>(addr >> 56);
        }
    }
}

// Explicit template instantiations for common sizes
template class MaskedKey<32>;
template class MaskedKey<64>;

} // namespace hd_wallet
