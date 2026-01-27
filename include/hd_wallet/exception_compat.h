#ifndef HD_WALLET_EXCEPTION_COMPAT_H
#define HD_WALLET_EXCEPTION_COMPAT_H

/**
 * Exception compatibility layer for WASI builds
 *
 * WASI runtimes like wazero don't support C++ exceptions.
 * This header provides macros to conditionally handle errors.
 */

#include <cstdlib>

#if defined(__wasi__) || defined(HD_WALLET_NO_EXCEPTIONS)

// In WASI mode, we can't throw exceptions. Use early returns with error codes.
// Functions should use HD_WALLET_CHECK_* macros and return error codes.

#define HD_WALLET_THROW_BAD_ALLOC() std::abort()
#define HD_WALLET_THROW_INVALID_ARG(msg) return -1
#define HD_WALLET_THROW_RUNTIME_ERROR(msg) return -1

// For functions that must return a value, use these
#define HD_WALLET_THROW_BAD_ALLOC_RET(ret) do { std::abort(); return ret; } while(0)
#define HD_WALLET_THROW_INVALID_ARG_RET(msg, ret) return ret
#define HD_WALLET_THROW_RUNTIME_ERROR_RET(msg, ret) return ret

// Disable exception specifications
#define HD_WALLET_NOEXCEPT

#else

// Normal exception mode
#include <stdexcept>
#include <new>

#define HD_WALLET_THROW_BAD_ALLOC() throw std::bad_alloc()
#define HD_WALLET_THROW_INVALID_ARG(msg) throw std::invalid_argument(msg)
#define HD_WALLET_THROW_RUNTIME_ERROR(msg) throw std::runtime_error(msg)

#define HD_WALLET_THROW_BAD_ALLOC_RET(ret) throw std::bad_alloc()
#define HD_WALLET_THROW_INVALID_ARG_RET(msg, ret) throw std::invalid_argument(msg)
#define HD_WALLET_THROW_RUNTIME_ERROR_RET(msg, ret) throw std::runtime_error(msg)

#define HD_WALLET_NOEXCEPT noexcept

#endif // __wasi__

#endif // HD_WALLET_EXCEPTION_COMPAT_H
