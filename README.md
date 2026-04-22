# PQCRecon: Automated Identification of PQC Posture in TLS 1.3

PQCRecon is a tool that can help identify the PQC adoption in a endpoint that uses TLS 1.3.  
As of now, it is specifically geared to look at TLS 1.3 in a HTTPS web-traffic context - though the objective is to extend it to other protocols that utilize TLS and beyond TLS itself.

## Architecture

### Dataset

TODO: Add a section that explains how the dataset is generated and what it contains.

## Setup

### Init OpenSSL Submodules

- **Objective:** Manage the `openssl` dependency submodule in three local-only modes.
- **Usage:** `scripts/init-openssl-submodules.sh --openssl-only` (openssl only), `scripts/init-openssl-submodules.sh --recursive` (openssl + nested recursively), `scripts/init-openssl-submodules.sh --fresh` (reset to fresh-clone local state).

### Init oqs-provider Submodules

- **Objective:** Manage the `oqs-provider` dependency submodule in three local-only modes.
- **Usage:** `scripts/init-oqs-submodules.sh --oqs-provider-only` (oqs-provider only), `scripts/init-oqs-submodules.sh --recursive` (oqs-provider + nested recursively), `scripts/init-oqs-submodules.sh --fresh` (reset to fresh-clone local state).

