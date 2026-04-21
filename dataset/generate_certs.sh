#!/usr/bin/env bash
set -euo pipefail

umask 077

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
CERT_DIR="${CERT_DIR:-/certs}"
CERT_DAYS="${CERT_DAYS:-365}"
CERT_SUBJECT="${CERT_SUBJECT:-/C=US/ST=Georgia/L=Kennesaw/O=PQCRecon/OU=TLS/CN=localhost}"

mkdir -p "${CERT_DIR}"

openssl_version="$("${OPENSSL_BIN}" version)"
if [[ "${openssl_version}" != OpenSSL\ 4.0.0* ]]; then
    echo "ERROR: expected OpenSSL 4.0.0, got: ${openssl_version}" >&2
    exit 1
fi

gen_self_signed() {
    local key_file="$1"
    local cert_file="$2"

    "${OPENSSL_BIN}" req \
        -new \
        -x509 \
        -key "${key_file}" \
        -out "${cert_file}" \
        -days "${CERT_DAYS}" \
        -subj "${CERT_SUBJECT}"
}

echo "[1/5] Generating RSA-2048 key/certificate"
"${OPENSSL_BIN}" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${CERT_DIR}/rsa-2048.key.pem"
gen_self_signed "${CERT_DIR}/rsa-2048.key.pem" "${CERT_DIR}/rsa-2048.cert.pem"

echo "[2/5] Generating ECDSA (prime256v1) key/certificate"
"${OPENSSL_BIN}" genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -pkeyopt ec_param_enc:named_curve \
    -out "${CERT_DIR}/ecdsa-prime256v1.key.pem"
gen_self_signed "${CERT_DIR}/ecdsa-prime256v1.key.pem" "${CERT_DIR}/ecdsa-prime256v1.cert.pem"

echo "[3/5] Generating Ed25519 key/certificate"
"${OPENSSL_BIN}" genpkey \
    -algorithm ED25519 \
    -out "${CERT_DIR}/ed25519.key.pem"
gen_self_signed "${CERT_DIR}/ed25519.key.pem" "${CERT_DIR}/ed25519.cert.pem"

echo "[4/5] Generating ML-DSA-65 key/certificate"
"${OPENSSL_BIN}" genpkey \
    -algorithm ML-DSA-65 \
    -out "${CERT_DIR}/ml-dsa-65.key.pem"
gen_self_signed "${CERT_DIR}/ml-dsa-65.key.pem" "${CERT_DIR}/ml-dsa-65.cert.pem"

echo "[5/5] Generating SLH-DSA-SHA2-128s key/certificate"
"${OPENSSL_BIN}" genpkey \
    -algorithm SLH-DSA-SHA2-128s \
    -out "${CERT_DIR}/slh-dsa-sha2-128s.key.pem"
gen_self_signed "${CERT_DIR}/slh-dsa-sha2-128s.key.pem" "${CERT_DIR}/slh-dsa-sha2-128s.cert.pem"

echo "Generated files in ${CERT_DIR}:"
ls -1 "${CERT_DIR}"