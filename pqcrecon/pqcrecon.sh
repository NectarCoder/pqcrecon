#!/bin/bash
# PQCRecon Docker Wrapper
# Run from anywhere — resolves paths relative to this script's location.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile"
IMAGE_NAME="pqcrecon"

function show_help() {
    echo "Usage: pqcrecon/pqcrecon.sh [build | run <domain>]"
    echo ""
    echo "Commands:"
    echo "  build         Build the PQCRecon docker image (includes OpenSSL+OQS)"
    echo "  run <domain>  Run the reconnaissance on a target domain"
    echo ""
    echo "Examples:"
    echo "  pqcrecon/pqcrecon.sh build"
    echo "  pqcrecon/pqcrecon.sh run cloudflare.com"
}

if [[ "${1:-}" == "build" ]]; then
    echo "[*] Building PQCRecon Docker image..."
    echo "    Context : ${PROJECT_ROOT}"
    echo "    File    : ${DOCKERFILE}"
    docker build -f "${DOCKERFILE}" -t "${IMAGE_NAME}" "${PROJECT_ROOT}"

elif [[ "${1:-}" == "run" ]]; then
    if [[ -z "${2:-}" ]]; then
        show_help
        exit 1
    fi
    # --privileged   → tcpdump needs NET_RAW/NET_ADMIN
    # --network host → share host network namespace so tcpdump sees real traffic
    docker run --rm --privileged --network host -v "${PROJECT_ROOT}:/workspace" "${IMAGE_NAME}" "${2}"

else
    show_help
    exit 0
fi
