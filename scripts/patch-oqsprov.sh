#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OQS_DIR="$REPO_ROOT/oqs-provider"
PATCH_FILE="$REPO_ROOT/scripts/oqs-provider-openssl4-compat.patch"

if [ ! -e "$OQS_DIR/.git" ]; then
    echo "oqs-provider is missing. Ensure submodules are initialized."
    exit 1
fi

cd "$OQS_DIR"
if git apply --reverse --check "$PATCH_FILE" >/dev/null 2>&1; then
    echo "Patch already applied."
else
    echo "Applying oqs-provider-openssl4-compat.patch..."
    git apply "$PATCH_FILE"
fi
