# PQC TLS Dataset Environment

This folder provides a Dockerized OpenSSL 4.0.0 environment that builds from local source in `../openssl` and generates self-signed certs for TLS testing.

## Files

- `Dockerfile`: builds OpenSSL 4.0.0 from local source.
- `docker-compose.yml`: runs certificate generation in a container.
- `generate_certs.sh`: creates classic, modern, and PQC key/cert pairs in `/certs`.
- `certs/`: output directory on the host.

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
