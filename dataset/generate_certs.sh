#!/usr/bin/env bash
set -euo pipefail

umask 077

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
CERT_DIR="${CERT_DIR:-/certs}"
CERT_DAYS="${CERT_DAYS:-365}"
CERT_SUBJECT="${CERT_SUBJECT:-/C=US/ST=Georgia/L=Kennesaw/O=PQCRecon/OU=TLS/CN=localhost}"
USE_OQS_PROVIDER="${USE_OQS_PROVIDER:-1}"

OPENSSL_PROVIDER_ARGS=()
if [[ "${USE_OQS_PROVIDER}" == "1" ]]; then
    OPENSSL_PROVIDER_ARGS=(-provider default -provider oqsprovider)
fi

mkdir -p "${CERT_DIR}"

openssl_cmd() {
    local subcommand="$1"
    shift

    "${OPENSSL_BIN}" "${subcommand}" "${OPENSSL_PROVIDER_ARGS[@]}" "$@"
}



if [[ "${USE_OQS_PROVIDER}" == "1" ]]; then
    if ! openssl_cmd list -providers >/dev/null 2>&1; then
        echo "ERROR: oqsprovider is not available (verify OPENSSL_MODULES and provider build)." >&2
        exit 1
    fi
fi

gen_self_signed() {
    local key_file="$1"
    local cert_file="$2"

    openssl_cmd req \
        -new \
        -x509 \
        -key "${key_file}" \
        -out "${cert_file}" \
        -days "${CERT_DAYS}" \
        -subj "${CERT_SUBJECT}"
}

echo "[1/5] Generating RSA-2048 key/certificate"
openssl_cmd genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${CERT_DIR}/rsa-2048.key.pem"
gen_self_signed "${CERT_DIR}/rsa-2048.key.pem" "${CERT_DIR}/rsa-2048.cert.pem"

echo "[2/5] Generating ECDSA (prime256v1) key/certificate"
openssl_cmd genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -pkeyopt ec_param_enc:named_curve \
    -out "${CERT_DIR}/ecdsa-prime256v1.key.pem"
gen_self_signed "${CERT_DIR}/ecdsa-prime256v1.key.pem" "${CERT_DIR}/ecdsa-prime256v1.cert.pem"

echo "[3/5] Generating Ed25519 key/certificate"
openssl_cmd genpkey \
    -algorithm ED25519 \
    -out "${CERT_DIR}/ed25519.key.pem"
gen_self_signed "${CERT_DIR}/ed25519.key.pem" "${CERT_DIR}/ed25519.cert.pem"

echo "[4/5] Generating oqs-provider ML-DSA-65 key/certificate"
openssl_cmd genpkey \
    -algorithm mldsa65 \
    -out "${CERT_DIR}/oqs-mldsa65.key.pem"
gen_self_signed "${CERT_DIR}/oqs-mldsa65.key.pem" "${CERT_DIR}/oqs-mldsa65.cert.pem"

echo "[5/5] Generating oqs-provider SLH-DSA-SHA2-128f key/certificate"
openssl_cmd genpkey \
    -algorithm slhdsasha2128f \
    -out "${CERT_DIR}/oqs-slhdsasha2128f.key.pem"
gen_self_signed "${CERT_DIR}/oqs-slhdsasha2128f.key.pem" "${CERT_DIR}/oqs-slhdsasha2128f.cert.pem"

echo "Generated files in ${CERT_DIR}:"
ls -1 "${CERT_DIR}"