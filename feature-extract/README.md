# Feature Extraction & Training Data Generation

This directory contains the tools to extract cryptographic features from captured TLS 1.3 traffic and compile them into a CSV dataset for machine learning.

## Files

- `extract_features.py`: The main Python script that parses PCAP files.
- `pcaps-keylogs/`: A symlink to the dataset's PCAP directory.
- `training_data.csv`: The current extracted features.
- `training_data*.csv`: Backups of previous extraction runs.

## Prerequisites

The script requires `pyshark` to be installed:

```bash
pip install pyshark --break-system-packages
# Or use a virtual environment:
# python3 -m venv .venv
# source .venv/bin/activate
# pip install pyshark
```

## How to Run

1. Ensure the TLS servers in the `dataset/` directory have been run and traffic has been captured.
2. Run the extraction script:
   ```bash
   python3 extract_features.py
   ```

## Script Logic

The script performs the following:

1. **Classification**: Labels each PCAP based on its filename (Classical, KE-PQC, Cert-PQC, or Full-PQC).
2. **KEX Extraction**: Extracts the `key_share` extension size from the `ClientHello` and the negotiated group ID from the `ServerHello`.
3. **Certificate Extraction**: Extracts the leaf certificate's signature algorithm OID and public key size from the decrypted `Certificate` message.
4. **Backup**: If a `training_data.csv` already exists, it is automatically renamed with an incrementing suffix (e.g., `training_data1.csv`) to preserve history.

## Output Format

The resulting `training_data.csv` contains:

- `filename`: Source PCAP.
- `key_share_size`: Integer byte size of the key_share extension.
- `supported_group_id`: Hex ID of the negotiated group.
- `leaf_cert_pubkey_size`: Integer byte size of the leaf certificate's public key.
- `leaf_cert_oid`: OID string of the certificate's signature algorithm.
- `label`: One of the four PQC/Classical classes.
