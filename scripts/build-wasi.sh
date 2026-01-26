#!/bin/bash
# Build hd-wallet-wasm for WASI (Go/Rust/Python compatibility)
# This build disables C++ exceptions for pure WASI compatibility

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build-wasi"

echo "=== Building hd-wallet-wasm for WASI ==="
echo "Build directory: $BUILD_DIR"

# Check for Emscripten
if ! command -v emcc &> /dev/null; then
    echo "Error: Emscripten not found. Please run 'source emsdk_env.sh' first."
    exit 1
fi

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cd "$BUILD_DIR"

# Configure with CMake using Emscripten
emcmake cmake "$PROJECT_DIR" \
    -DHD_WALLET_BUILD_WASM=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DHD_WALLET_WASI_PURE=ON

# Build the WASI target
cmake --build . --target hd_wallet_wasm_wasi -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

echo ""
echo "=== Build complete ==="
echo "WASI WASM: $BUILD_DIR/wasm/hd-wallet-wasi.wasm"
