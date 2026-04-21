#!/usr/bin/env bash
# Build OpenSSL with release defaults and explicitly enable legacy/weak options.

set -euo pipefail
IFS=$'\n\t'

print_usage() {
  cat <<EOF
Usage: ${0##*/} [--clean] [--run-tests]

Options:
  --clean      Run 'make distclean' first and remove prior local install output.
  --run-tests  Run 'make test' after build (recommended, but slower).
  -h, --help   Show this help and exit.

Environment:
  OPENSSL_BUILD_PREFIX  Override install prefix (default: openssl/tmp.pqcrecon)
EOF
}

DO_CLEAN=0
RUN_TESTS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      DO_CLEAN=1
      ;;
    --run-tests)
      RUN_TESTS=1
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      print_usage
      exit 2
      ;;
  esac
  shift
done

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not installed or not on PATH." >&2
  exit 1
fi

if ! command -v perl >/dev/null 2>&1; then
  echo "Error: perl is required by OpenSSL Configure but is not on PATH." >&2
  exit 1
fi

if command -v make >/dev/null 2>&1; then
  MAKE_CMD="make"
elif command -v gmake >/dev/null 2>&1; then
  MAKE_CMD="gmake"
else
  echo "Error: neither 'make' nor 'gmake' is available on PATH." >&2
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z "$REPO_ROOT" ]]; then
  echo "Error: not inside a Git repository." >&2
  exit 1
fi

OPENSSL_DIR="$REPO_ROOT/openssl"
if [[ ! -x "$OPENSSL_DIR/Configure" ]]; then
  echo "Error: OpenSSL Configure script not found at $OPENSSL_DIR/Configure" >&2
  echo "Hint: run scripts/init-openssl-submodules.sh --openssl-only first." >&2
  exit 1
fi

BUILD_PREFIX="${OPENSSL_BUILD_PREFIX:-$OPENSSL_DIR/tmp.pqcrecon}"
OPENSSL_DIR_CFG="$BUILD_PREFIX/ssl"
OPENSSL_CONF_PATH="$OPENSSL_DIR_CFG/openssl-all.cnf"

if command -v nproc >/dev/null 2>&1; then
  CPU_COUNT=$(nproc)
elif command -v getconf >/dev/null 2>&1; then
  CPU_COUNT=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
elif command -v sysctl >/dev/null 2>&1; then
  CPU_COUNT=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
else
  CPU_COUNT=4
fi

echo "Repository root: $REPO_ROOT"
echo "OpenSSL source dir: $OPENSSL_DIR"
echo "Build/install prefix: $BUILD_PREFIX"
echo "Build tool: $MAKE_CMD"
echo "Parallel jobs: $CPU_COUNT"

cd "$OPENSSL_DIR"

if [[ $DO_CLEAN -eq 1 ]]; then
  echo "Cleaning previous OpenSSL build artifacts and local install output..."
  "$MAKE_CMD" distclean >/dev/null 2>&1 || true
  rm -rf -- "$BUILD_PREFIX"
  rm -rf -- "$OPENSSL_DIR/build"
fi

echo "Configuring OpenSSL..."
# Keep release/default optimization, while explicitly enabling weak/deprecated options.
./Configure \
  --prefix="$BUILD_PREFIX" \
  --openssldir="$OPENSSL_DIR_CFG" \
  --release \
  enable-weak-ssl-ciphers \
  enable-md2 \
  enable-rc5 \
  enable-tls-deprecated-ec \
  enable-unstable-qlog

echo "Building OpenSSL..."
"$MAKE_CMD" -j"$CPU_COUNT"

if [[ $RUN_TESTS -eq 1 ]]; then
  echo "Running OpenSSL test suite..."
  "$MAKE_CMD" test
fi

echo "Installing software artifacts to local prefix..."
"$MAKE_CMD" install_sw

echo "Building oqs-provider..."
OQS_DIR="$REPO_ROOT/oqs-provider"
cd "$OQS_DIR"
if [[ $DO_CLEAN -eq 1 ]]; then
  rm -rf _build liboqs .local
fi
env OPENSSL_INSTALL="$BUILD_PREFIX" \
    LIBOQS_BRANCH=0.15.0 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    OQSPROV_CMAKE_PARAMS="-DBUILD_TESTING=OFF" \
    bash scripts/fullbuild.sh -f
cmake --install _build

mkdir -p "$OPENSSL_DIR_CFG"
cat >"$OPENSSL_CONF_PATH" <<'EOF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOF

# Ensure module path is correct
if [ -d "$BUILD_PREFIX/lib64/ossl-modules" ]; then
  mkdir -p "$BUILD_PREFIX/lib"
  ln -sfn ../lib64/ossl-modules "$BUILD_PREFIX/lib/ossl-modules"
elif [ -d "$BUILD_PREFIX/lib/ossl-modules" ]; then
  mkdir -p "$BUILD_PREFIX/lib64"
  ln -sfn ../lib/ossl-modules "$BUILD_PREFIX/lib64/ossl-modules"
fi

if ls "$BUILD_PREFIX/lib/ossl-modules/oqsprovider."* >/dev/null 2>&1 || ls "$BUILD_PREFIX/lib64/ossl-modules/oqsprovider."* >/dev/null 2>&1; then
  echo "oqs-provider successfully installed."
else
  echo "Warning: oqsprovider might not be in modules path..."
fi

echo
echo "Build complete."
echo "OpenSSL binary: $BUILD_PREFIX/bin/openssl"
echo "Provider config (default + legacy + oqsprovider): $OPENSSL_CONF_PATH"
echo
echo "Try:"
echo "  $BUILD_PREFIX/bin/openssl version -a"
echo "  OPENSSL_MODULES=$BUILD_PREFIX/lib/ossl-modules OPENSSL_CONF=$OPENSSL_CONF_PATH $BUILD_PREFIX/bin/openssl list -providers"
echo "  OPENSSL_CONF=$OPENSSL_CONF_PATH $BUILD_PREFIX/bin/openssl help"

exit 0
