#!/usr/bin/env bash
set -euo pipefail

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
CERT_DIR="${CERT_DIR:-/certs}"
LOG_DIR="${LOG_DIR:-/workspace/logs}"
BIND_HOST="${BIND_HOST:-0.0.0.0}"
STRICT_CERT_TYPES="${STRICT_CERT_TYPES:-0}"
USE_OQS_PROVIDER="${USE_OQS_PROVIDER:-1}"

OPENSSL_PROVIDER_ARGS=()
if [[ "${USE_OQS_PROVIDER}" == "1" ]]; then
    OPENSSL_PROVIDER_ARGS=(-provider default -provider oqsprovider)
fi

SERVER_NAMES=(
    "rsa"
    "ecdsa-p256"
    "ed25519"
    "ml-dsa-65"
    "oqs-sphincssha2128fsimple"
)

SERVER_PORTS=(4431 4432 4433 4434 4435)

SERVER_CERTS=(
    "${CERT_DIR}/rsa-2048.cert.pem"
    "${CERT_DIR}/ecdsa-prime256v1.cert.pem"
    "${CERT_DIR}/ed25519.cert.pem"
    "${CERT_DIR}/ml-dsa-65.cert.pem"
    "${CERT_DIR}/oqs-sphincssha2128fsimple.cert.pem"
)

SERVER_KEYS=(
    "${CERT_DIR}/rsa-2048.key.pem"
    "${CERT_DIR}/ecdsa-prime256v1.key.pem"
    "${CERT_DIR}/ed25519.key.pem"
    "${CERT_DIR}/ml-dsa-65.key.pem"
    "${CERT_DIR}/oqs-sphincssha2128fsimple.key.pem"
)

PIDS=()
RUNNING_SUMMARY=()
SKIPPED_SUMMARY=()
cleanup_done=0

cleanup() {
    local reason="${1:-exit}"
    if [[ "${cleanup_done}" -eq 1 ]]; then
        return
    fi
    cleanup_done=1

    if [[ "${#PIDS[@]}" -gt 0 ]]; then
        echo
        echo "Stopping TLS servers (${reason})..."
        kill "${PIDS[@]}" 2>/dev/null || true
        wait "${PIDS[@]}" 2>/dev/null || true
    fi
}

trap 'cleanup "interrupt"; exit 0' INT
trap 'cleanup "termination"; exit 0' TERM
trap 'cleanup "exit"' EXIT

require_file() {
    local file_path="$1"
    if [[ ! -f "${file_path}" ]]; then
        echo "ERROR: required file not found: ${file_path}" >&2
        exit 1
    fi
}

wait_for_server() {
    local pid="$1"
    local port="$2"
    local name="$3"
    local server_log="$4"
    local attempts=80

    while [[ "${attempts}" -gt 0 ]]; do
        if ! kill -0 "${pid}" 2>/dev/null; then
            echo "ERROR: ${name} server exited early. Check ${server_log}" >&2
            return 1
        fi

        if (echo >"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1; then
            return 0
        fi

        attempts=$((attempts - 1))
        sleep 0.25
    done

    echo "ERROR: ${name} server did not start listening on port ${port}. Check ${server_log}" >&2
    return 1
}

if ! command -v "${OPENSSL_BIN}" >/dev/null 2>&1; then
    echo "ERROR: OpenSSL binary not found: ${OPENSSL_BIN}" >&2
    exit 1
fi

if [[ "${USE_OQS_PROVIDER}" == "1" ]]; then
    if ! "${OPENSSL_BIN}" list -providers "${OPENSSL_PROVIDER_ARGS[@]}" >/dev/null 2>&1; then
        echo "ERROR: oqsprovider is not available (verify OPENSSL_MODULES and provider build)." >&2
        exit 1
    fi
fi

for cert_file in "${SERVER_CERTS[@]}"; do
    require_file "${cert_file}"
done

for key_file in "${SERVER_KEYS[@]}"; do
    require_file "${key_file}"
done

mkdir -p "${LOG_DIR}"

for idx in "${!SERVER_NAMES[@]}"; do
    name="${SERVER_NAMES[${idx}]}"
    port="${SERVER_PORTS[${idx}]}"
    cert_file="${SERVER_CERTS[${idx}]}"
    key_file="${SERVER_KEYS[${idx}]}"

    server_log="${LOG_DIR}/${name}.s_server.log"
    key_log="${LOG_DIR}/${name}.sslkeys.log"

    echo "Starting ${name} TLS server on ${BIND_HOST}:${port}"

    "${OPENSSL_BIN}" s_server \
        "${OPENSSL_PROVIDER_ARGS[@]}" \
        -accept "${BIND_HOST}:${port}" \
        -tls1_3 \
        -cert "${cert_file}" \
        -key "${key_file}" \
        -www \
        -keylogfile "${key_log}" \
        >"${server_log}" 2>&1 &

    pid="$!"

    if wait_for_server "${pid}" "${port}" "${name}" "${server_log}"; then
        PIDS+=("${pid}")
        RUNNING_SUMMARY+=("${port}:${name}")
        continue
    fi

    if grep -q "unknown certificate type" "${server_log}"; then
        if [[ "${STRICT_CERT_TYPES}" == "1" ]]; then
            echo "ERROR: ${name} certificate is not supported by s_server in this OpenSSL build (STRICT_CERT_TYPES=1)." >&2
            exit 1
        fi

        SKIPPED_SUMMARY+=("${port}:${name}")
        echo "WARNING: skipping ${name} on port ${port} due to unsupported TLS certificate type in this OpenSSL build."
        continue
    fi

    echo "ERROR: ${name} failed to start for an unexpected reason. Check ${server_log}" >&2
    exit 1
done

echo
echo "TLS 1.3 startup summary:"
for item in "${RUNNING_SUMMARY[@]}"; do
    echo "  running ${item}"
done
for item in "${SKIPPED_SUMMARY[@]}"; do
    echo "  skipped ${item}"
done
echo "Server logs: ${LOG_DIR}/*.s_server.log"
echo "TLS key logs: ${LOG_DIR}/*.sslkeys.log"
echo ""
echo "Process stays active until container stop/restart or Ctrl+C."

if [[ "${#PIDS[@]}" -eq 0 ]]; then
    echo "ERROR: no TLS servers are running." >&2
    exit 1
fi

set +e
wait -n "${PIDS[@]}"
first_exit_code="$?"
set -e

echo "A TLS server exited with code ${first_exit_code}. Shutting down remaining servers." >&2
exit "${first_exit_code}"
