# PQCRecon Scanner (Phase 3)

PQCRecon is an automated TLS 1.3 reconnaissance tool designed to identify the Post-Quantum Cryptography (PQC) posture of live internet endpoints. It performs active fingerprinting by initiating a handshake and analyzing the resulting traffic without requiring decryption or server-side access.

## Quick Start

The scanner is containerized to ensure it has access to the specialized OpenSSL+OQS environment required to negotiate PQC handshakes and a custom packet parser.

### 1. Build the Scanner
Build the Docker image from the project root. This step compiles OpenSSL with the OQS provider and installs the necessary Python analysis tools.

```bash
pqcrecon/pqcrecon.sh build
```

### 2. Run Reconnaissance
Run the scanner against any target domain. The tool will initiate a handshake, capture the packets, extract features, and use the Phase 2 classifier to report the PQC posture.

```bash
pqcrecon/pqcrecon.sh run <domain>
```

**Example:**
```bash
pqcrecon/pqcrecon.sh run cloudflare.com
```

### 3. Output
The tool will display a detailed report showing:
- **Negotiated Group**: The key exchange algorithm (e.g., `X25519`, `X25519+Kyber768`).
- **Key Share Size**: The byte length of the client's public key share.
- **Certificate OID**: The signature algorithm OID used by the server's leaf certificate.
- **Final Posture**: The classification result (**Classical**, **KE-PQC**, **Cert-PQC**, or **Full-PQC**).

## Internals
- **Active Probing**: Uses a custom OpenSSL build to support PQC `supported_groups`.
- **Packet Inspection**: Uses `tcpdump` and `pyshark` to isolate and parse the handshake even when encrypted extensions are present.
- **Inference**: Loads the model trained in Phase 2 (`classification/pqcrecon_model.pkl`) to perform real-time classification.

## Requirements
- **Docker**: Must be installed and running.
- **Privileges**: The wrapper runs the container with `--privileged` and `--network host` to allow packet capture on the host interface.
