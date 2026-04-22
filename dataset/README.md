# PQC TLS Dataset Environment

This directory provides the Docker environment for generating certificates and running TLS 1.3 servers for the dataset. It runs OpenSSL 3.4.5 with `oqs-provider` to enable Post-Quantum Cryptography (PQC) algorithms.

## Quick Start

> **Note:** If you get a "Conflict" error stating the name `/pqc-servers` is already in use, simply remove the old container first:
>
> ```bash
> docker rm -f pqc-servers
> ```

### 1. Generate Certificates

Run this command to generate fresh cryptographic keys and certificates. The output will be saved in the `certs/` folder on your host machine.

```bash
docker compose run --rm --build openssl-pqc
```

### 2. Start the TLS Servers

Once certificates are generated, start all five TLS 1.3 servers in the background using the `-d` flag so your terminal remains free:

```bash
docker compose run -d --rm --name pqc-servers --service-ports openssl-pqc bash /usr/local/bin/start_servers.sh
```

_(To stop the servers later, run `docker stop pqc-servers`)_

### 3. Automate Traffic Capture (PCAPs & Session Keys)

With the TLS servers actively running, open a new terminal and execute the Python traffic generator. This command runs the script in the _same container_ as the servers so it can capture the loopback traffic directly:

```bash
docker exec pqc-servers python3 /workspace/generate_traffic.py
```

> **Note on Decryption:**  
> The script instructs OpenSSL to save the session keys locally for each handshake. You will find matching `.keylog` files alongside your `.pcap` files in the newly generated `pcaps/` directory.  
> _To decrypt the packets in Wireshark: Go to `Edit -> Preferences -> Protocols -> TLS` and set the `(Pre)-Master-Secret log filename` to the matching `.keylog` file._

---

## One-Liner: Reset & Regenerate

If you want to wipe the current state and perform the entire process (Build -> Start -> Generate) in one go, use this command:

```bash
docker rm -f pqc-servers 2>/dev/null; \
docker compose run --rm --build openssl-pqc && \
docker compose run -d --rm --name pqc-servers --service-ports openssl-pqc bash /usr/local/bin/start_servers.sh && \
sleep 5 && \
docker exec pqc-servers python3 /workspace/generate_traffic.py
```

---

## TLS Servers Overview

When you run `start_servers.sh`, it spins up 5 standalone OpenSSL `s_server` instances on different ports, each using a specific cryptographic algorithm:

| Port     | Algorithm          | Type         | Filenames                                  |
| -------- | ------------------ | ------------ | ------------------------------------------ |
| **4431** | RSA (2048-bit)     | Classic      | `rsa-2048.key.pem` / `.cert.pem`           |
| **4432** | ECDSA (prime256v1) | Classic      | `ecdsa-prime256v1.key.pem` / `.cert.pem`   |
| **4433** | Ed25519            | Modern       | `ed25519.key.pem` / `.cert.pem`            |
| **4434** | ML-DSA-65          | Post-Quantum | `oqs-mldsa65.key.pem` / `.cert.pem`        |
| **4435** | SLH-DSA-SHA2-128f  | Post-Quantum | `oqs-slhdsasha2128f.key.pem` / `.cert.pem` |

All servers automatically log their output to the `logs/` directory. This includes:

- `*.s_server.log`: Server standard output/errors.
- `*.sslkeys.log`: TLS key material logs (extremely useful for Wireshark/PCAP decryption).

---

## Docker Debugging & Maintenance

If you run into issues, need a fresh environment, or want to wipe the slate clean, use these commands:

**Rebuild the Docker Image from Scratch (No Cache)**
If you updated the `openssl` or `oqs-provider` submodules on the host, you need to rebuild the image so it copies the new code:

```bash
docker compose build --no-cache openssl-pqc
```

**Clean Up Stale Containers**
If a previous container crashed or is lingering:

```bash
docker compose down
```

**Purge Everything (Images, Volumes, Networks)**
To completely nuke the Docker setup for this project and start fresh:

```bash
docker compose down --rmi all --volumes --remove-orphans
```

**Enter the Container Interactively**
If you want to poke around inside the container and run OpenSSL commands manually:

```bash
docker compose run --rm --entrypoint bash openssl-pqc
```

_(Once inside, you can run `openssl list -providers` or `openssl list -signature-algorithms` to verify the environment)._
