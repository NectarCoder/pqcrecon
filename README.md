# PQCRecon
Source code for the PQCRecon project for 'Automated Passive Identification of PQC Posture in TLS 1.3'.

## Setup

### Init OpenSSL Submodules

- **Objective:** Manage the `openssl` dependency submodule in three local-only modes.
- **Usage:** `scripts/init-openssl-submodules.sh --openssl-only` (openssl only), `scripts/init-openssl-submodules.sh --recursive` (openssl + nested recursively), `scripts/init-openssl-submodules.sh --fresh` (reset to fresh-clone local state).

### Build OpenSSL

- **Objective:** Build OpenSSL 4.0.0 for cryptographic operations.
- **Script:** `scripts/build-openssl.sh`
- **Usage:** `scripts/build-openssl.sh` (build + local install), `scripts/build-openssl.sh --clean` (clean and rebuild), `scripts/build-openssl.sh --run-tests` (also run `make test`).
- **Platform support:** UNIX-like environments (macOS, Ubuntu/Linux, and other systems with `bash`, `perl`, and `make`/`gmake`).
- **Build profile:** Uses OpenSSL release defaults and explicitly enables: weak SSL ciphers (`enable-weak-ssl-ciphers`), disabled-by-default legacy algorithms (`enable-md2`, `enable-rc5`), deprecated TLS EC groups (`enable-tls-deprecated-ec`), and draft QUIC qlog support (`enable-unstable-qlog`).
- **Output binary:** `openssl/tmp.pqcrecon/bin/openssl` (placed under an OpenSSL-ignored path to keep submodule status clean)
- **Legacy provider config:** `openssl/tmp.pqcrecon/ssl/openssl-all.cnf` (auto-loads both `default` and `legacy` providers)

#### Using the shortcut script

- **Project-root shortcut:** `./openssl-local <openssl args>` (passes through arguments to the local binary and auto-uses the local provider config when present)
- **Auto-build shortcut:** `./openssl-local --build-if-missing <openssl args>`
- **Verify build:** `./openssl-local version -a`, `./openssl-local help`, `./openssl-local list -providers`.
