# PQC TLS Dataset Environment

This folder provides a Dockerized OpenSSL 4.0.0 environment that builds from local source in `../openssl` and generates self-signed certs for TLS testing.

## Files

- `Dockerfile`: builds OpenSSL 4.0.0 from local source.
- `docker-compose.yml`: runs certificate generation in a container and can run test TLS servers.
- `generate_certs.sh`: creates classic, modern, and PQC key/cert pairs in `/certs`.
- `start_servers.sh`: starts five TLS 1.3 `openssl s_server` processes on ports 4431-4435.
- `certs/`: output directory on the host.
- `logs/`: runtime output for server logs and TLS key log files.

## Generate certificates

From this `dataset/` directory:

```bash
docker compose run --rm --build openssl-pqc
```

Generated outputs:

- `certs/rsa-2048.key.pem` and `certs/rsa-2048.cert.pem`
- `certs/ecdsa-prime256v1.key.pem` and `certs/ecdsa-prime256v1.cert.pem`
- `certs/ed25519.key.pem` and `certs/ed25519.cert.pem`
- `certs/ml-dsa-65.key.pem` and `certs/ml-dsa-65.cert.pem`
- `certs/slh-dsa-sha2-128s.key.pem` and `certs/slh-dsa-sha2-128s.cert.pem`

## Customization

You can override defaults with environment variables in `docker-compose.yml`:

- `CERT_DAYS`
- `CERT_SUBJECT`
- `CERT_DIR` (inside container; default `/certs`)

The script enforces OpenSSL 4.0.0 at runtime to prevent use of a system OpenSSL binary.

## Run TLS 1.3 test servers

After certificates are generated, start all five servers:

From this `dataset/` directory:

```bash
docker compose run --rm --build --service-ports openssl-pqc bash /usr/local/bin/start_servers.sh
```

The server process is long-lived and remains active until the container is stopped.

Ports:

- `4431`: RSA
- `4432`: ECDSA-P256
- `4433`: Ed25519
- `4434`: ML-DSA-65
- `4435`: SLH-DSA-SHA2-128s

Runtime outputs are written under `logs/`:

- `*.s_server.log`: OpenSSL server stdout/stderr per algorithm
- `*.sslkeys.log`: TLS key material (for packet decryption workflows)

### Notes on PQC certificate support in TLS

Some certificate algorithms may be available for key generation/signing but not yet accepted by `openssl s_server` for TLS endpoints in a given OpenSSL/libssl build.

- Default behavior (`STRICT_CERT_TYPES=0`): unsupported cert types are skipped with a warning, while supported servers remain running.
- Strict behavior (`STRICT_CERT_TYPES=1`): launcher exits with an error if any configured cert type is unsupported.

Example strict run:

```bash
STRICT_CERT_TYPES=1 docker compose run --rm --build --service-ports openssl-pqc bash /usr/local/bin/start_servers.sh
```
