# CMake toolchain file for wasi-sdk
# Usage: cmake -DCMAKE_TOOLCHAIN_FILE=cmake/wasi-sdk.cmake ..

# Detect wasi-sdk location
if(NOT DEFINED WASI_SDK_PREFIX)
  if(DEFINED ENV{WASI_SDK_PREFIX})
    set(WASI_SDK_PREFIX $ENV{WASI_SDK_PREFIX})
  elseif(EXISTS "$ENV{HOME}/wasi-sdk")
    set(WASI_SDK_PREFIX "$ENV{HOME}/wasi-sdk")
  elseif(EXISTS "/opt/wasi-sdk")
    set(WASI_SDK_PREFIX "/opt/wasi-sdk")
  else()
    message(FATAL_ERROR "wasi-sdk not found. Set WASI_SDK_PREFIX or install to ~/wasi-sdk or /opt/wasi-sdk")
  endif()
endif()

message(STATUS "Using wasi-sdk from: ${WASI_SDK_PREFIX}")

# System settings
set(CMAKE_SYSTEM_NAME WASI)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR wasm32)
set(WASI TRUE)

# Compiler settings
set(CMAKE_C_COMPILER "${WASI_SDK_PREFIX}/bin/clang")
set(CMAKE_CXX_COMPILER "${WASI_SDK_PREFIX}/bin/clang++")
set(CMAKE_AR "${WASI_SDK_PREFIX}/bin/llvm-ar")
set(CMAKE_RANLIB "${WASI_SDK_PREFIX}/bin/llvm-ranlib")
set(CMAKE_C_COMPILER_TARGET "wasm32-wasi")
set(CMAKE_CXX_COMPILER_TARGET "wasm32-wasi")

# Sysroot
set(CMAKE_SYSROOT "${WASI_SDK_PREFIX}/share/wasi-sysroot")

# Compiler flags
set(CMAKE_C_FLAGS_INIT "-fno-exceptions")
set(CMAKE_CXX_FLAGS_INIT "-fno-exceptions -fno-rtti")

# Don't look for programs on the host
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Output format
set(CMAKE_EXECUTABLE_SUFFIX ".wasm")
