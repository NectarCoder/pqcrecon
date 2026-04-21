# PQCRecon
Source code for the PQCRecon project for 'Automated Passive Identification of PQC Posture in TLS 1.3'.

## Setup

### Init OpenSSL Submodules

- **Objective:** Manage the `openssl` dependency submodule in three local-only modes.
- **Usage:** `scripts/init-openssl-submodules.sh --openssl-only` (openssl only), `scripts/init-openssl-submodules.sh --recursive` (openssl + nested recursively), `scripts/init-openssl-submodules.sh --fresh` (reset to fresh-clone local state).


