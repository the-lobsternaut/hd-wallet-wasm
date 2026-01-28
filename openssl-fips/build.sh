#!/bin/bash
set -e

# OpenSSL FIPS Provider - WebAssembly Build Script for hd-wallet-wasm
# Compiles OpenSSL 3.0.9 with FIPS Provider to WebAssembly using Emscripten
#
# Based on the reference implementation from flatbuffers/wasm/openssl-fips/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
DIST_DIR="${SCRIPT_DIR}/dist"
OPENSSL_VERSION="3.0.9"  # FIPS 140-3 validated version (Certificate #4282)
OPENSSL_DIR="${BUILD_DIR}/openssl-${OPENSSL_VERSION}"

# Local Emscripten SDK path (installed via CMake FetchContent)
EMSDK_DIR="${SCRIPT_DIR}/../build-wasm/_deps/emsdk-src"
EMSCRIPTEN_DIR="${EMSDK_DIR}/upstream/emscripten"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for local Emscripten first, then system PATH
    if [ -f "${EMSCRIPTEN_DIR}/emcc" ]; then
        log_info "Using local Emscripten from build directory"
        export PATH="${EMSCRIPTEN_DIR}:${PATH}"
        export EMSDK="${EMSDK_DIR}"
        export EM_CONFIG="${EMSDK_DIR}/.emscripten"
    elif ! command -v emcc &> /dev/null; then
        log_error "Emscripten (emcc) not found."
        log_error "Expected at: ${EMSCRIPTEN_DIR}/emcc"
        log_error "Run the main CMake build first to download Emscripten, or activate emsdk manually."
        exit 1
    fi

    if ! command -v perl &> /dev/null; then
        log_error "Perl not found. Required for OpenSSL configure."
        exit 1
    fi

    EMCC_VERSION=$(emcc --version | head -n1)
    log_info "Using $EMCC_VERSION"
}

# Download OpenSSL source
download_openssl() {
    mkdir -p "${BUILD_DIR}"

    if [ -d "${OPENSSL_DIR}" ]; then
        log_info "OpenSSL ${OPENSSL_VERSION} already downloaded"
        return
    fi

    log_info "Downloading OpenSSL ${OPENSSL_VERSION}..."
    cd "${BUILD_DIR}"

    OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
    curl -L -o "openssl-${OPENSSL_VERSION}.tar.gz" "${OPENSSL_URL}"
    tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz"
    rm "openssl-${OPENSSL_VERSION}.tar.gz"

    log_info "Downloaded and extracted OpenSSL ${OPENSSL_VERSION}"
}

# Configure OpenSSL for Emscripten
configure_openssl() {
    log_info "Configuring OpenSSL for WebAssembly..."
    cd "${OPENSSL_DIR}"

    # Clean previous build if exists
    if [ -f "Makefile" ]; then
        make clean || true
    fi

    # Configure for Emscripten
    # Key flags:
    #   no-asm       - No assembly (required for WASM)
    #   no-threads   - No pthread (simplifies WASM build)
    #   no-shared    - Static libraries only
    #   no-dso       - No dynamic shared objects
    #   no-engine    - No engine support (deprecated in 3.x anyway)
    #   no-async     - No async support (avoids pthread requirements)
    #   enable-fips  - Enable FIPS provider

    # Set environment variables for emconfigure
    export CC=emcc
    export AR=emar
    export RANLIB=emranlib
    export CFLAGS="-Os -fno-exceptions -DOPENSSL_NO_SECURE_MEMORY -DOPENSSL_SMALL_FOOTPRINT -D__STDC_NO_ATOMICS__"

    ./Configure linux-generic32 \
        --prefix="${DIST_DIR}" \
        --openssldir="${DIST_DIR}/ssl" \
        no-asm \
        no-threads \
        no-shared \
        no-dso \
        no-engine \
        no-async \
        no-sock \
        no-dgram \
        no-tests \
        no-ui-console \
        enable-fips

    log_info "OpenSSL configured for WebAssembly build"
}

# Build OpenSSL
build_openssl() {
    log_info "Building OpenSSL (this may take a while)..."
    cd "${OPENSSL_DIR}"

    # Build only libcrypto and the FIPS provider
    # We don't need libssl for our encryption use case
    emmake make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4) build_libs

    log_info "OpenSSL libraries built successfully"
}

# Install to dist directory
install_openssl() {
    log_info "Installing OpenSSL to dist directory..."
    mkdir -p "${DIST_DIR}/lib" "${DIST_DIR}/include"

    cd "${OPENSSL_DIR}"

    # Copy libraries
    cp libcrypto.a "${DIST_DIR}/lib/"

    # Copy FIPS provider if built
    if [ -f "providers/fips.a" ]; then
        cp providers/fips.a "${DIST_DIR}/lib/"
    fi

    # Copy headers
    cp -r include/openssl "${DIST_DIR}/include/"

    log_info "Installation complete"
}

# Verify build
verify_build() {
    log_info "Verifying build artifacts..."

    if [ ! -f "${DIST_DIR}/lib/libcrypto.a" ]; then
        log_error "libcrypto.a not found!"
        exit 1
    fi

    local size=$(ls -lh "${DIST_DIR}/lib/libcrypto.a" | awk '{print $5}')
    log_info "libcrypto.a: ${size}"

    if [ -f "${DIST_DIR}/lib/fips.a" ]; then
        local fips_size=$(ls -lh "${DIST_DIR}/lib/fips.a" | awk '{print $5}')
        log_info "fips.a: ${fips_size}"
    fi

    log_info "Build verification complete"
}

# Main build sequence
main() {
    log_info "Starting OpenSSL FIPS WebAssembly build for hd-wallet-wasm"
    log_info "Version: ${OPENSSL_VERSION}"

    check_prerequisites
    download_openssl
    configure_openssl
    build_openssl
    install_openssl
    verify_build

    log_info ""
    log_info "Build complete!"
    log_info "Output files:"
    log_info "  ${DIST_DIR}/lib/libcrypto.a - OpenSSL crypto library (WASM)"
    log_info "  ${DIST_DIR}/lib/fips.a      - FIPS provider module (if built)"
    log_info "  ${DIST_DIR}/include/        - OpenSSL headers"
    log_info ""
    log_info "To use with CMake build:"
    log_info "  cmake -B build-wasm -S . -DHD_WALLET_BUILD_WASM=ON -DHD_WALLET_USE_OPENSSL=ON"
    log_info ""
}

main "$@"
