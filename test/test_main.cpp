/**
 * @file test_main.cpp
 * @brief HD Wallet Test Runner - Main Entry Point
 *
 * This file contains only the main() function.
 * The test framework is defined in test_framework.h.
 * Individual test files include test_framework.h and register tests via TEST_CASE macro.
 */

#include "test_framework.h"

// =============================================================================
// Main
// =============================================================================

int main(int argc, char* argv[]) {
    std::cout << "HD Wallet WASM Test Suite\n";
    std::cout << "========================\n";
    std::cout << "Version: " << HD_WALLET_VERSION_STRING << "\n";

    std::string filter;
    if (argc > 1) {
        filter = argv[1];
        std::cout << "Filter: " << filter << "\n";
    }

    return test::TestRunner::instance().run(filter);
}
