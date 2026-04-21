#!/usr/bin/env bash
# Manage the OpenSSL dependency submodule in exactly three modes:
# 1) sync only openssl
# 2) sync openssl + all nested submodules recursively
# 3) reset openssl to fresh-clone (uninitialized) local state

set -euo pipefail
IFS=$'\n\t'

SUBMODULE_NAME="openssl"
MODE="openssl-only"

print_usage() {
  cat <<EOF
Usage: ${0##*/} [--openssl-only|--recursive|--fresh]

Options:
  --openssl-only  Sync and initialize only the openssl submodule (default)
  --recursive     Sync and initialize openssl plus all nested submodules recursively
  --fresh         Reset openssl to a fresh-clone local state (uninitialized)
  -h, --help      Show this help and exit
EOF
}

if [[ $# -gt 1 ]]; then
  echo "Error: provide at most one option." >&2
  print_usage
  exit 2
fi

if [[ $# -eq 1 ]]; then
  case "$1" in
    --openssl-only)
      MODE="openssl-only"
      ;;
    --recursive)
      MODE="recursive"
      ;;
    --fresh)
      MODE="fresh"
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
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is not installed or not on PATH." >&2
  exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [[ -z "$REPO_ROOT" ]]; then
  echo "Error: not inside a Git repository." >&2
  exit 1
fi

GITMODULES_PATH="$REPO_ROOT/.gitmodules"
if [[ ! -f "$GITMODULES_PATH" ]]; then
  echo "Error: .gitmodules not found at repository root ($GITMODULES_PATH)." >&2
  exit 1
fi

SUBMODULE_PATH=$(git config -f "$GITMODULES_PATH" --get "submodule.$SUBMODULE_NAME.path" || true)
if [[ -z "$SUBMODULE_PATH" ]]; then
  echo "Could not find submodule '$SUBMODULE_NAME' in $GITMODULES_PATH" >&2
  echo "Available submodules:" >&2
  git config -f "$GITMODULES_PATH" --get-regexp '^submodule\..*\.path' || true
  exit 1
fi

# Keep any cleanup path operations constrained to repository-relative paths.
if [[ "$SUBMODULE_PATH" = /* || "$SUBMODULE_PATH" == *".."* ]]; then
  echo "Error: refusing unsafe submodule path '$SUBMODULE_PATH'." >&2
  exit 1
fi

sync_openssl_only() {
  echo "Syncing and initializing '$SUBMODULE_PATH' only..."
  git -C "$REPO_ROOT" submodule sync -- "$SUBMODULE_PATH"
  git -C "$REPO_ROOT" submodule update --init -- "$SUBMODULE_PATH"
  echo "Done: '$SUBMODULE_PATH' is synced and initialized (no nested sync)."
}

sync_recursive() {
  echo "Syncing and initializing '$SUBMODULE_PATH' recursively..."
  git -C "$REPO_ROOT" submodule sync -- "$SUBMODULE_PATH"
  git -C "$REPO_ROOT" submodule update --init --recursive -- "$SUBMODULE_PATH"
  if [[ -d "$REPO_ROOT/$SUBMODULE_PATH" ]]; then
    git -C "$REPO_ROOT/$SUBMODULE_PATH" submodule sync --recursive || true
  fi
  echo "Done: '$SUBMODULE_PATH' and all nested submodules are synced and initialized."
}

fresh_reset() {
  echo "Resetting '$SUBMODULE_PATH' to fresh-clone local state..."
  git -C "$REPO_ROOT" submodule deinit -f -- "$SUBMODULE_PATH" || true
  rm -rf -- "$REPO_ROOT/$SUBMODULE_PATH"
  rm -rf -- "$REPO_ROOT/.git/modules/$SUBMODULE_PATH"
  echo "Done: '$SUBMODULE_PATH' is now uninitialized locally."
  echo "The submodule remains registered in .gitmodules and the index."
}

echo "Repository root: $REPO_ROOT"
echo "OpenSSL submodule path: $SUBMODULE_PATH"

case "$MODE" in
  openssl-only)
    sync_openssl_only
    ;;
  recursive)
    sync_recursive
    ;;
  fresh)
    fresh_reset
    ;;
esac

exit 0
