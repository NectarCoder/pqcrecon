#!/usr/bin/env python3
"""
extract_features.py
===================
Parses a directory of TLS 1.3 .pcap files (with matching keylog files) and
extracts cryptographic handshake features into training_data.csv.

PCAPs must follow the naming convention:  [KEX]_[CERT].pcap
Matching keylogs must follow:            [KEX]_[CERT].keylog

Usage:
    python3 extract_features.py

Output:
    feature-extract/training_data.csv
"""

import csv
import os
import sys
import pyshark

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PCAP_DIR     = os.path.join(SCRIPT_DIR, "pcaps-keylogs")
OUTPUT_CSV   = os.path.join(SCRIPT_DIR, "training_data.csv")

CSV_COLUMNS  = [
    "filename",
    "key_share_size",
    "supported_group_id",
    "leaf_cert_pubkey_size",
    "leaf_cert_sig_size",
    "leaf_cert_oid",
    "cert_chain_length",
    "label",
]

# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------
PQC_KEX_ALGORITHMS  = {"MLKEM768", "X25519MLKEM768"}
PQC_CERT_ALGORITHMS = {"ML-DSA-65", "SLH-DSA-SHA2-128s"}


def classify_label(filename: str) -> str:
    """
    Derive a 4-class label from the PCAP filename.

    Format: [KEX]_[CERT].pcap
    Classes:
        Classical  – Classical KEX + Classical Cert
        KE-PQC     – PQC KEX    + Classical Cert
        Cert-PQC   – Classical KEX + PQC Cert
        Full-PQC   – PQC KEX    + PQC Cert
    """
    stem = os.path.splitext(filename)[0]   # e.g. "X25519_RSA"
    parts = stem.split("_", 1)             # split on first underscore only
    if len(parts) != 2:
        return "Unknown"

    kex, cert = parts[0], parts[1]

    is_pqc_kex  = kex  in PQC_KEX_ALGORITHMS
    is_pqc_cert = cert in PQC_CERT_ALGORITHMS

    if is_pqc_kex and is_pqc_cert:
        return "Full-PQC"
    elif is_pqc_kex:
        return "KE-PQC"
    elif is_pqc_cert:
        return "Cert-PQC"
    else:
        return "Classical"


# ---------------------------------------------------------------------------
# Hex-colon byte string → byte count
# ---------------------------------------------------------------------------
def _hex_colon_to_bytes(raw: str) -> int:
    """
    pyshark returns byte fields as 'aa:bb:cc:…' strings (possibly with
    embedded newlines).  Count the number of colon-delimited hex octets.
    """
    cleaned = raw.replace("\n", "").replace(" ", "")
    return len(cleaned.replace(":", "")) // 2


# ---------------------------------------------------------------------------
# Feature extraction for a single PCAP
# ---------------------------------------------------------------------------
def extract_features(pcap_path: str, keylog_path: str) -> dict:
    """
    Returns a dict with extracted features, or None-valued fields on failure.
    """
    features = {
        "key_share_size":        None,
        "supported_group_id":    None,
        "leaf_cert_pubkey_size": None,
        "leaf_cert_sig_size":    None,
        "leaf_cert_oid":         None,
        "cert_chain_length":     None,
    }

    tls_prefs = {"tls.keylog_file": keylog_path}

    # ------------------------------------------------------------------ #
    # Pass 1: ClientHello → key_share extension payload size
    #         ServerHello → negotiated supported_group
    # ------------------------------------------------------------------ #
    # Fallback: if ClientHello has only one supported_group, use that as the
    # group identifier when the ServerHello is absent (e.g., truncated PCAP).
    _client_hello_group_fallback = None

    try:
        cap_hello = pyshark.FileCapture(
            pcap_path,
            override_prefs=tls_prefs,
            display_filter="tls.handshake.type == 1 or tls.handshake.type == 2",
        )

        for pkt in cap_hello:
            try:
                tls = pkt.tls
                handshake_type = getattr(tls, "handshake_type", None)

                if handshake_type is None:
                    # multi-value field: fall back to string-based check
                    raw_types = str(tls.get_field("handshake_type") or "")
                    if "1" in raw_types.split(","):
                        handshake_type = "1"
                    elif "2" in raw_types.split(","):
                        handshake_type = "2"

                ht = str(handshake_type)

                # ClientHello: record the key_share group as a fallback.
                if "1" in ht:
                    try:
                        # Fallback: ClientHello's offered key_share group.
                        grp_raw = getattr(tls, "handshake_extensions_key_share_group", None)
                        if grp_raw is not None:
                            _client_hello_group_fallback = hex(int(grp_raw))
                    except Exception:
                        pass

                    try:
                        # Secondary fallback: first supported_group list entry.
                        if _client_hello_group_fallback is None:
                            sg_raw = getattr(tls, "handshake_extensions_supported_group", None)
                            if sg_raw is not None:
                                _client_hello_group_fallback = hex(int(str(sg_raw), 16))
                    except Exception:
                        pass

                # ServerHello: the single negotiated group is the canonical one
                if "2" in ht:
                    if features["supported_group_id"] is None:
                        try:
                            grp_raw = getattr(tls, "handshake_extensions_key_share_group", None)
                            if grp_raw is not None:
                                features["supported_group_id"] = hex(int(grp_raw))
                        except Exception:
                            pass
                    
                    if features["key_share_size"] is None:
                        try:
                            ks_len = int(getattr(tls, "handshake_extensions_key_share_key_exchange_length", 0))
                            if ks_len > 0:
                                features["key_share_size"] = ks_len
                        except Exception:
                            pass

            except Exception:
                continue

            # Stop early once both are found
            if features["key_share_size"] is not None and features["supported_group_id"] is not None:
                break

        cap_hello.close()

    except Exception as exc:
        print(f"  [WARN] Hello pass failed for {os.path.basename(pcap_path)}: {exc}")

    # If ServerHello was absent, use the ClientHello group as best-effort.
    if features["supported_group_id"] is None and _client_hello_group_fallback is not None:
        features["supported_group_id"] = _client_hello_group_fallback

    # ------------------------------------------------------------------ #
    # Pass 2: Certificate message (type 11) → leaf cert OID + pubkey size
    # Attempt 1: use a display filter so only Certificate frames are parsed.
    # Attempt 2 (fallback): scan ALL packets – needed when the cert is large
    #   enough to be TCP-reassembled into a non-Certificate-typed TLS record
    #   (tshark labels these as "[Certificate Fragment]" instead).
    # ------------------------------------------------------------------ #
    def _scan_for_cert(cap) -> None:
        """Scan packets from an open capture for x509 OID and pubkey size."""
        for pkt in cap:
            try:
                tls = pkt.tls

                # OID of the leaf certificate's signature algorithm
                # Use get_field to handle potential multiple certificates in chain
                oids = tls.get_field("x509af_algorithm_id")
                if oids:
                    oids_list = str(oids).split(",")
                    if features["leaf_cert_oid"] is None:
                        features["leaf_cert_oid"] = oids_list[0].strip()
                    if features["cert_chain_length"] is None:
                        features["cert_chain_length"] = len(oids_list)

                # Public key bytes (subjectPublicKey bit string content)
                pubkeys = tls.get_field("x509af_subjectpublickey")
                if pubkeys and features["leaf_cert_pubkey_size"] is None:
                    pubkeys_list = str(pubkeys).split(",")
                    features["leaf_cert_pubkey_size"] = _hex_colon_to_bytes(pubkeys_list[0].strip())

                # Signature Value bytes
                sigs = tls.get_field("x509af_encrypted")
                if sigs and features["leaf_cert_sig_size"] is None:
                    sigs_list = str(sigs).split(",")
                    features["leaf_cert_sig_size"] = _hex_colon_to_bytes(sigs_list[0].strip())

            except Exception:
                continue

            if (features["leaf_cert_oid"] is not None and 
                features["leaf_cert_pubkey_size"] is not None and
                features["leaf_cert_sig_size"] is not None):
                break

    try:
        cap_cert = pyshark.FileCapture(
            pcap_path,
            override_prefs=tls_prefs,
            display_filter="tls.handshake.type == 11",
        )
        _scan_for_cert(cap_cert)
        cap_cert.close()
    except Exception as exc:
        print(f"  [WARN] Cert (filtered) pass failed for {os.path.basename(pcap_path)}: {exc}")

    # Fallback: full scan without display filter for fragmented/reassembled certs.
    if features["leaf_cert_oid"] is None or features["leaf_cert_pubkey_size"] is None:
        try:
            cap_full = pyshark.FileCapture(
                pcap_path,
                override_prefs=tls_prefs,
            )
            _scan_for_cert(cap_full)
            cap_full.close()
        except Exception as exc:
            print(f"  [WARN] Cert (full scan) pass failed for {os.path.basename(pcap_path)}: {exc}")

    return features


# ---------------------------------------------------------------------------
# Backup existing CSV
# ---------------------------------------------------------------------------
def backup_existing_csv(csv_path: str) -> None:
    """
    If the target CSV already exists, rename it to training_data1.csv,
    training_data2.csv, etc., to preserve old results.
    """
    if not os.path.exists(csv_path):
        return

    base, ext = os.path.splitext(csv_path)
    i = 1
    while True:
        # Check for training_data1.csv, etc.
        new_name = f"{base}{i}{ext}"
        if not os.path.exists(new_name):
            os.rename(csv_path, new_name)
            print(f"[INFO] Existing CSV found. Backed up to: {os.path.basename(new_name)}")
            break
        i += 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if not os.path.isdir(PCAP_DIR):
        print(f"[ERROR] PCAP directory not found: {PCAP_DIR}", file=sys.stderr)
        sys.exit(1)

    pcap_files = sorted(
        f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")
    )

    if not pcap_files:
        print(f"[ERROR] No .pcap files found in {PCAP_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Found {len(pcap_files)} PCAP file(s) in {PCAP_DIR}")
    
    # Backup existing results if any
    backup_existing_csv(OUTPUT_CSV)
    
    print(f"[INFO] Writing output to: {OUTPUT_CSV}\n")

    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for pcap_name in pcap_files:
            pcap_path   = os.path.join(PCAP_DIR, pcap_name)
            keylog_name = os.path.splitext(pcap_name)[0] + ".keylog"
            keylog_path = os.path.join(PCAP_DIR, keylog_name)

            label = classify_label(pcap_name)
            print(f"[{label:10s}]  Processing: {pcap_name}")

            if not os.path.isfile(keylog_path):
                print(f"  [WARN] Keylog not found ({keylog_name}), skipping.")
                continue

            features = extract_features(pcap_path, keylog_path)

            row = {
                "filename":              pcap_name,
                "key_share_size":        features["key_share_size"],
                "supported_group_id":    features["supported_group_id"],
                "leaf_cert_pubkey_size": features["leaf_cert_pubkey_size"],
                "leaf_cert_sig_size":    features["leaf_cert_sig_size"],
                "leaf_cert_oid":         features["leaf_cert_oid"],
                "cert_chain_length":     features["cert_chain_length"],
                "label":                 label,
            }
            writer.writerow(row)

            print(
                f"  key_share_size={row['key_share_size']}  "
                f"group={row['supported_group_id']}  "
                f"pubkey_size={row['leaf_cert_pubkey_size']}  "
                f"sig_size={row['leaf_cert_sig_size']}  "
                f"chain_len={row['cert_chain_length']}  "
                f"oid={row['leaf_cert_oid']}"
            )

    print(f"\n[DONE] training_data.csv written with {len(pcap_files)} row(s).")


if __name__ == "__main__":
    main()
