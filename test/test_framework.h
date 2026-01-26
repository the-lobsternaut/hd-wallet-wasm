/**
 * @file test_framework.h
 * @brief HD Wallet Test Framework - Header-Only Test Framework
 *
 * A minimal test framework that provides:
 * - Test registration and execution
 * - Assertion macros with detailed failure messages
 * - Test grouping by category
 * - Summary statistics
 */

#ifndef HD_WALLET_TEST_FRAMEWORK_H
#define HD_WALLET_TEST_FRAMEWORK_H

#include "hd_wallet/config.h"

#include "hd_wallet/types.h"
#include "hd_wallet/bip39.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// =============================================================================
// ostream operators for enum types (needed for test macros)
// =============================================================================

inline std::ostream& operator<<(std::ostream& os, hd_wallet::Error error) {
    os << hd_wallet::errorToString(error) << " (" << static_cast<int>(error) << ")";
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::Curve curve) {
    os << hd_wallet::curveToString(curve);
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::CoinType coin) {
    os << hd_wallet::coinTypeToString(coin);
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::bip39::Language lang) {
    const char* names[] = {
        "ENGLISH", "JAPANESE", "KOREAN", "SPANISH",
        "CHINESE_SIMPLIFIED", "CHINESE_TRADITIONAL",
        "FRENCH", "ITALIAN", "CZECH", "PORTUGUESE"
    };
    auto idx = static_cast<size_t>(lang);
    if (idx < sizeof(names) / sizeof(names[0])) {
        os << names[idx];
    } else {
        os << "UNKNOWN(" << static_cast<int>(lang) << ")";
    }
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::KeyPurpose purpose) {
    os << (purpose == hd_wallet::KeyPurpose::SIGNING ? "SIGNING" : "ENCRYPTION");
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::BitcoinAddressType addrType) {
    const char* names[] = {"P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR"};
    auto idx = static_cast<size_t>(addrType);
    if (idx < sizeof(names) / sizeof(names[0])) {
        os << names[idx];
    } else {
        os << "UNKNOWN(" << static_cast<int>(addrType) << ")";
    }
    return os;
}

inline std::ostream& operator<<(std::ostream& os, hd_wallet::Network network) {
    os << (network == hd_wallet::Network::MAINNET ? "MAINNET" : "TESTNET");
    return os;
}

// ostream operators for byte array types (Bytes32, Bytes33, Bytes64, Bytes65)
template<std::size_t N>
inline std::ostream& operator<<(std::ostream& os, const std::array<uint8_t, N>& arr) {
    os << std::hex << std::setfill('0');
    for (size_t i = 0; i < N && i < 32; ++i) {
        os << std::setw(2) << static_cast<int>(arr[i]);
    }
    if (N > 32) {
        os << "...(" << N << " bytes)";
    }
    os << std::dec;
    return os;
}

// =============================================================================
// Test Framework
// =============================================================================

namespace test {

/// Test result status
enum class Status {
    PASSED,
    FAILED,
    SKIPPED
};

/// Single test case result
struct TestResult {
    std::string name;
    std::string category;
    Status status;
    std::string message;
    double duration_ms;
};

/// Test case definition
struct TestCase {
    std::string name;
    std::string category;
    std::function<void()> func;
};

/// Skip exception
class SkipException : public std::exception {
public:
    explicit SkipException(const std::string& reason) : reason_(reason) {}
    const char* what() const noexcept override { return reason_.c_str(); }
private:
    std::string reason_;
};

/// Global test state
class TestRunner {
public:
    static TestRunner& instance() {
        static TestRunner runner;
        return runner;
    }

    void registerTest(const std::string& category, const std::string& name, std::function<void()> func) {
        tests_.push_back({name, category, func});
    }

    void setCurrentTest(const std::string& name) {
        current_test_ = name;
    }

    void fail(const std::string& message, const char* file, int line) {
        std::ostringstream oss;
        oss << message << " [" << file << ":" << line << "]";
        throw std::runtime_error(oss.str());
    }

    void skip(const std::string& reason = "") {
        throw SkipException(reason);
    }

    int run(const std::string& filter = "") {
        std::vector<TestResult> results;
        int passed = 0, failed = 0, skipped = 0;

        std::string current_category;

        for (const auto& test : tests_) {
            // Apply filter
            if (!filter.empty() && test.name.find(filter) == std::string::npos &&
                test.category.find(filter) == std::string::npos) {
                continue;
            }

            // Print category header
            if (test.category != current_category) {
                current_category = test.category;
                std::cout << "\n=== " << current_category << " ===\n";
            }

            setCurrentTest(test.name);
            TestResult result;
            result.name = test.name;
            result.category = test.category;

            auto start = std::chrono::high_resolution_clock::now();

            try {
                test.func();
                result.status = Status::PASSED;
                result.message = "OK";
                ++passed;
                std::cout << "  [PASS] " << test.name << "\n";
            } catch (const SkipException& e) {
                result.status = Status::SKIPPED;
                result.message = e.what();
                ++skipped;
                std::cout << "  [SKIP] " << test.name;
                if (!result.message.empty()) {
                    std::cout << " - " << result.message;
                }
                std::cout << "\n";
            } catch (const std::exception& e) {
                result.status = Status::FAILED;
                result.message = e.what();
                ++failed;
                std::cout << "  [FAIL] " << test.name << "\n";
                std::cout << "         " << result.message << "\n";
            }

            auto end = std::chrono::high_resolution_clock::now();
            result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            results.push_back(result);
        }

        // Print summary
        std::cout << "\n========================================\n";
        std::cout << "Test Summary\n";
        std::cout << "========================================\n";
        std::cout << "Passed:  " << passed << "\n";
        std::cout << "Failed:  " << failed << "\n";
        std::cout << "Skipped: " << skipped << "\n";
        std::cout << "Total:   " << results.size() << "\n";
        std::cout << "========================================\n";

        if (failed > 0) {
            std::cout << "\nFailed tests:\n";
            for (const auto& r : results) {
                if (r.status == Status::FAILED) {
                    std::cout << "  - " << r.category << "::" << r.name << "\n";
                    std::cout << "    " << r.message << "\n";
                }
            }
        }

        return failed > 0 ? 1 : 0;
    }

private:
    TestRunner() = default;

    std::vector<TestCase> tests_;
    std::string current_test_;
};

/// Auto-registration helper
struct TestRegistrar {
    TestRegistrar(const std::string& category, const std::string& name, std::function<void()> func) {
        TestRunner::instance().registerTest(category, name, func);
    }
};

} // namespace test

// =============================================================================
// Assertion Macros
// =============================================================================

#define TEST_CASE(category, name) \
    static void test_##category##_##name(); \
    static test::TestRegistrar registrar_##category##_##name(#category, #name, test_##category##_##name); \
    static void test_##category##_##name()

#define ASSERT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            test::TestRunner::instance().fail("ASSERT_TRUE failed: " #expr, __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_FALSE(expr) \
    do { \
        if (expr) { \
            test::TestRunner::instance().fail("ASSERT_FALSE failed: " #expr, __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_EQ(expected, actual) \
    do { \
        auto _e = (expected); \
        auto _a = (actual); \
        if (_e != _a) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_EQ failed: expected " << _e << ", got " << _a; \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_NE(expected, actual) \
    do { \
        auto _e = (expected); \
        auto _a = (actual); \
        if (_e == _a) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_NE failed: values are equal: " << _e; \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_STR_EQ(expected, actual) \
    do { \
        std::string _e = (expected); \
        std::string _a = (actual); \
        if (_e != _a) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_STR_EQ failed:\n  expected: \"" << _e << "\"\n  actual:   \"" << _a << "\""; \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_BYTES_EQ(expected, actual, len) \
    do { \
        const uint8_t* _e = (const uint8_t*)(expected); \
        const uint8_t* _a = (const uint8_t*)(actual); \
        size_t _len = (len); \
        bool _match = true; \
        for (size_t _i = 0; _i < _len; ++_i) { \
            if (_e[_i] != _a[_i]) { _match = false; break; } \
        } \
        if (!_match) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_BYTES_EQ failed at length " << _len << ":\n  expected: "; \
            for (size_t _i = 0; _i < _len && _i < 64; ++_i) _oss << std::hex << std::setw(2) << std::setfill('0') << (int)_e[_i]; \
            _oss << "\n  actual:   "; \
            for (size_t _i = 0; _i < _len && _i < 64; ++_i) _oss << std::hex << std::setw(2) << std::setfill('0') << (int)_a[_i]; \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_OK(result) \
    do { \
        auto _r = (result); \
        if (!_r.ok()) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_OK failed: error code " << static_cast<int>(_r.error); \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define ASSERT_ERROR(result, expected_error) \
    do { \
        auto _r = (result); \
        if (_r.error != (expected_error)) { \
            std::ostringstream _oss; \
            _oss << "ASSERT_ERROR failed: expected error " << static_cast<int>(expected_error) \
                 << ", got " << static_cast<int>(_r.error); \
            test::TestRunner::instance().fail(_oss.str(), __FILE__, __LINE__); \
        } \
    } while(0)

#define SKIP_TEST(reason) \
    do { \
        test::TestRunner::instance().skip(reason); \
    } while(0)

// =============================================================================
// Utility Functions
// =============================================================================

namespace test {

/// Convert hex string to bytes
inline std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    std::string cleanHex = hex;

    // Remove 0x prefix if present
    if (cleanHex.size() >= 2 && cleanHex[0] == '0' && (cleanHex[1] == 'x' || cleanHex[1] == 'X')) {
        cleanHex = cleanHex.substr(2);
    }

    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoul(cleanHex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

/// Convert bytes to hex string
inline std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

/// Convert bytes to hex string (vector version)
inline std::string bytesToHex(const std::vector<uint8_t>& data) {
    return bytesToHex(data.data(), data.size());
}

/// Convert array to hex string
template<size_t N>
inline std::string bytesToHex(const std::array<uint8_t, N>& data) {
    return bytesToHex(data.data(), N);
}

/// Fill array from hex
template<size_t N>
inline std::array<uint8_t, N> hexToArray(const std::string& hex) {
    std::array<uint8_t, N> arr{};
    auto bytes = hexToBytes(hex);
    if (bytes.size() >= N) {
        std::copy(bytes.begin(), bytes.begin() + N, arr.begin());
    } else {
        std::copy(bytes.begin(), bytes.end(), arr.begin());
    }
    return arr;
}

} // namespace test

#endif // HD_WALLET_TEST_FRAMEWORK_H
