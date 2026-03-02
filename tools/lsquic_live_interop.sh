#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
LSQUIC_SRC="${ROOT_DIR}/xtra/lsquic"
BUILD_DIR="${LIBFAST_LSQUIC_BUILD_DIR:-${ROOT_DIR}/.zig-cache/lsquic-interop}"
STRICT_MODE="${LIBFAST_INTEROP_STRICT:-0}"
TEST_FILTER="${LIBFAST_LSQUIC_TEST_FILTER:-varint|ver_nego|packno_len|ackparse_ietf|parse_packet_in}"

skip_or_fail() {
    reason="$1"
    echo "[libfast][interop-live] ${reason}"
    if [ "${STRICT_MODE}" = "1" ]; then
        exit 1
    fi
    exit 0
}

if ! command -v cmake >/dev/null 2>&1; then
    skip_or_fail "cmake not found; skipping live LSQUIC interop"
fi

if [ ! -d "${LSQUIC_SRC}" ]; then
    skip_or_fail "xtra/lsquic not found; skipping live LSQUIC interop"
fi

SSL_INCLUDE="${SSLLIB_INCLUDE:-}"
if [ -z "${SSL_INCLUDE}" ] && command -v pkg-config >/dev/null 2>&1; then
    SSL_INCLUDE="$(pkg-config --variable=includedir openssl 2>/dev/null || true)"
fi

if [ -z "${SSL_INCLUDE}" ] || [ ! -f "${SSL_INCLUDE}/openssl/ssl.h" ]; then
    skip_or_fail "OpenSSL headers missing (set SSLLIB_INCLUDE to include path containing openssl/ssl.h)"
fi

SSL_LIB_NAME="${LIBSSL_LIB_ssl:-ssl}"
CRYPTO_LIB_NAME="${LIBSSL_LIB_crypto:-crypto}"

echo "[libfast][interop-live] configuring LSQUIC in ${BUILD_DIR}"
if ! cmake -S "${LSQUIC_SRC}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug -DLSQUIC_BIN=OFF -DLSQUIC_TESTS=ON -DSSLLIB_INCLUDE="${SSL_INCLUDE}" -DLIBSSL_LIB_ssl="${SSL_LIB_NAME}" -DLIBSSL_LIB_crypto="${CRYPTO_LIB_NAME}"; then
    skip_or_fail "LSQUIC configure failed (set LIBFAST_INTEROP_STRICT=1 to make this fatal)"
fi

echo "[libfast][interop-live] building LSQUIC interop tests"
cmake --build "${BUILD_DIR}" --target test_varint test_ver_nego test_packno_len test_ackparse_ietf test_parse_packet_in

echo "[libfast][interop-live] running filtered CTest suite: ${TEST_FILTER}"
ctest --test-dir "${BUILD_DIR}" --output-on-failure -R "${TEST_FILTER}"

echo "[libfast][interop-live] live LSQUIC interop checks passed"
