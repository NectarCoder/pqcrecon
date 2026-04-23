#!/usr/bin/env python3
"""
pqcrecon.py
===========
PQCRecon — Active TLS 1.3 PQC Posture Classifier
=================================================
Connects to a target domain, captures the TLS 1.3 handshake via tcpdump +
openssl s_client, extracts cryptographic features using pyshark, and
classifies the PQC posture using a pre-trained Decision Tree.

Usage:
    python3 pqcrecon/pqcrecon.py <domain>
    python3 pqcrecon/pqcrecon.py cloudflare.com

Dependencies:
    rich, pyshark, joblib, scikit-learn
System deps:
    tcpdump (cap_net_raw or sudo), openssl
"""

import argparse
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import joblib
import numpy as np
import pyshark

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR   = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent
MODEL_PATH   = PROJECT_ROOT / "classification" / "pqcrecon_model.pkl"
LOOKUPS_PATH = PROJECT_ROOT / "classification" / "pqcrecon_lookups.pkl"

# ---------------------------------------------------------------------------
# Rich console with custom theme
# ---------------------------------------------------------------------------
THEME = Theme({
    "banner":      "bold cyan",
    "label.classical": "bold red",
    "label.ke_pqc":    "bold yellow",
    "label.cert_pqc":  "bold yellow",
    "label.full_pqc":  "bold green",
    "info":        "dim cyan",
    "warn":        "bold yellow",
    "error":       "bold red",
    "success":     "bold green",
    "header":      "bold white on dark_blue",
    "field":       "cyan",
    "value":       "white",
})
console = Console(theme=THEME)

# ---------------------------------------------------------------------------
# Known group/OID metadata for human-readable output
# ---------------------------------------------------------------------------
KEM_NAMES = {
    0x0200: "ML-KEM-512",
    0x0201: "ML-KEM-768",
    0x0202: "ML-KEM-1024",
    0x11eb: "X25519+ML-KEM-512 (Hybrid)",
    0x11ec: "X25519+ML-KEM-768 (Hybrid)",
    0x11ed: "X25519+ML-KEM-1024 (Hybrid)",
    0x6399: "Kyber768 Draft00",
    0x639a: "P256+Kyber768 (Hybrid)",
    0x001d: "X25519 (Classical)",
    0x0017: "secp256r1 (Classical)",
    0x0018: "secp384r1 (Classical)",
    0x0019: "secp521r1 (Classical)",
    0x001e: "X448 (Classical)",
}

OID_NAMES = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "1.2.840.113549.1.1.11":   "RSA (SHA-256)",
    "1.2.840.113549.1.1.1":    "RSA",
    "1.2.840.10045.4.3.2":     "ECDSA P-256",
    "1.2.840.10045.4.3.3":     "ECDSA P-384",
    "1.3.101.112":             "Ed25519",
    "1.3.101.113":             "Ed448",
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def print_banner():
    banner = Text()
    banner.append("██████╗  ██████╗  ██████╗", style="bold cyan")
    banner.append("██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗\n", style="bold blue")
    banner.append("██╔══██╗██╔═══██╗██╔════╝", style="bold cyan")
    banner.append("██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║\n", style="bold blue")
    banner.append("██████╔╝██║   ██║██║     ", style="bold cyan")
    banner.append("██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║\n", style="bold blue")
    banner.append("██╔═══╝ ██║▄▄ ██║██║     ", style="bold cyan")
    banner.append("██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║\n", style="bold blue")
    banner.append("██║     ╚██████╔╝╚██████╗", style="bold cyan")
    banner.append("██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║\n", style="bold blue")
    banner.append("╚═╝      ╚══▀▀═╝  ╚═════╝", style="bold cyan")
    banner.append("╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝\n", style="bold blue")

    subtitle = Text.assemble(
        ("  Active TLS 1.3 Post-Quantum Cryptography Posture Classifier", "bold white"),
        ("  │  ", "dim white"),
        ("Kennesaw State University  ·  CS PhD Research", "dim cyan"),
    )
    console.print(Panel(
        subtitle,
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def load_artifacts():
    """Load the pre-trained model and lookup sets. Exits cleanly on failure."""
    missing = [p for p in (MODEL_PATH, LOOKUPS_PATH) if not p.exists()]
    if missing:
        console.print(Panel(
            "\n".join([
                "[error]❌  Required model artifact(s) not found:[/error]",
                *[f"  [warn]•[/warn] [field]{p}[/field]" for p in missing],
                "",
                "[info]Run the classifier training first:[/info]",
                "  [value]python3 classification/classifier.py[/value]",
            ]),
            title="[error]Model Load Error[/error]",
            border_style="red",
            padding=(1, 2),
        ))
        sys.exit(1)

    try:
        model   = joblib.load(MODEL_PATH)
        lookups = joblib.load(LOOKUPS_PATH)
        pqc_kem_ids  = lookups["PQC_KEM_GROUP_IDS"]
        pqc_cert_oids = lookups["PQC_CERT_OIDS"]
        console.print(f"  [success]✓[/success] [info]Model loaded:[/info] [field]{MODEL_PATH.name}[/field]")
        return model, pqc_kem_ids, pqc_cert_oids
    except Exception as exc:
        console.print(Panel(
            f"[error]Failed to deserialize model:[/error]\n  [warn]{exc}[/warn]",
            title="[error]Artifact Error[/error]",
            border_style="red",
        ))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Network interface detection
# ---------------------------------------------------------------------------

def get_default_interface() -> str:
    """Return the default external network interface."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "8.8.8.8"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for token in out.split():
            if token == "dev":
                idx = out.split().index(token)
                return out.split()[idx + 1]
    except Exception:
        pass
    return "eth0"


# ---------------------------------------------------------------------------
# Feature extraction  (mirrors extract_features.py logic)
# ---------------------------------------------------------------------------

def _hex_colon_to_bytes(raw: str) -> int:
    cleaned = raw.replace("\n", "").replace(" ", "")
    return len(cleaned.replace(":", "")) // 2


def extract_features_from_pcap(pcap_path: str, keylog_path: str) -> dict:
    """
    Mirror of extract_features.py — two-pass pyshark extraction.
    Returns dict with: key_share_size, supported_group_id, leaf_cert_pubkey_size,
                       leaf_cert_sig_size, leaf_cert_oid, cert_chain_length
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
    _ch_group_fallback = None

    # --- Pass 1: ClientHello / ServerHello ---
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
                    raw_types = str(tls.get_field("handshake_type") or "")
                    if "1" in raw_types.split(","):
                        handshake_type = "1"
                    elif "2" in raw_types.split(","):
                        handshake_type = "2"

                ht = str(handshake_type)

                # ClientHello
                if "1" in ht and features["key_share_size"] is None:
                    try:
                        ks_len = int(getattr(tls, "handshake_extensions_key_share_client_length", 0))
                        features["key_share_size"] = ks_len
                    except Exception:
                        pass
                    try:
                        grp = getattr(tls, "handshake_extensions_key_share_group", None)
                        if grp is not None:
                            _ch_group_fallback = hex(int(grp))
                    except Exception:
                        pass
                    try:
                        if _ch_group_fallback is None:
                            sg = getattr(tls, "handshake_extensions_supported_group", None)
                            if sg is not None:
                                _ch_group_fallback = hex(int(str(sg), 16))
                    except Exception:
                        pass

                # ServerHello
                if "2" in ht and features["supported_group_id"] is None:
                    try:
                        grp = getattr(tls, "handshake_extensions_key_share_group", None)
                        if grp is not None:
                            features["supported_group_id"] = hex(int(grp))
                    except Exception:
                        pass

            except Exception:
                continue

            if features["key_share_size"] is not None and features["supported_group_id"] is not None:
                break

        cap_hello.close()
    except Exception:
        pass

    if features["supported_group_id"] is None and _ch_group_fallback is not None:
        features["supported_group_id"] = _ch_group_fallback

    # --- Pass 2: Certificate ---
    def _scan_cert(cap):
        for pkt in cap:
            try:
                tls = pkt.tls
                oids = tls.get_field("x509af_algorithm_id")
                if oids:
                    oids_list = str(oids).split(",")
                    if features["leaf_cert_oid"] is None:
                        features["leaf_cert_oid"] = oids_list[0].strip()
                    if features["cert_chain_length"] is None:
                        features["cert_chain_length"] = len(oids_list)

                pubkeys = tls.get_field("x509af_subjectpublickey")
                if pubkeys and features["leaf_cert_pubkey_size"] is None:
                    features["leaf_cert_pubkey_size"] = _hex_colon_to_bytes(str(pubkeys).split(",")[0].strip())

                sigs = tls.get_field("x509af_encrypted")
                if sigs and features["leaf_cert_sig_size"] is None:
                    features["leaf_cert_sig_size"] = _hex_colon_to_bytes(str(sigs).split(",")[0].strip())
            except Exception:
                continue

            if all(features[k] is not None for k in
                   ["leaf_cert_oid", "leaf_cert_pubkey_size", "leaf_cert_sig_size"]):
                break

    try:
        cap_cert = pyshark.FileCapture(
            pcap_path, override_prefs=tls_prefs,
            display_filter="tls.handshake.type == 11",
        )
        _scan_cert(cap_cert)
        cap_cert.close()
    except Exception:
        pass

    # Fallback: full scan (handles TCP-reassembled huge PQC certs)
    if features["leaf_cert_oid"] is None or features["leaf_cert_pubkey_size"] is None:
        try:
            cap_full = pyshark.FileCapture(pcap_path, override_prefs=tls_prefs)
            _scan_cert(cap_full)
            cap_full.close()
        except Exception:
            pass

    return features


# ---------------------------------------------------------------------------
# Feature engineering  (mirrors classifier.py logic)
# ---------------------------------------------------------------------------

def engineer_features(features: dict, pqc_kem_ids: set, pqc_cert_oids: set) -> np.ndarray:
    """
    Transform extracted raw features into the 6-element vector the model expects:
      [ke_pqc, cert_pqc, key_share_size, leaf_cert_pubkey_size,
       leaf_cert_sig_size, cert_chain_length]
    """
    def parse_group_id(val):
        if val is None:
            return None
        if isinstance(val, int):
            return val
        s = str(val).strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None

    group_id  = parse_group_id(features.get("supported_group_id"))
    cert_oid  = str(features.get("leaf_cert_oid") or "").strip()

    ke_pqc   = 1 if (group_id is not None and group_id in pqc_kem_ids) else 0
    cert_pqc = 1 if (cert_oid and cert_oid in pqc_cert_oids) else 0

    key_share_size        = int(features.get("key_share_size")        or 0)
    leaf_cert_pubkey_size = int(features.get("leaf_cert_pubkey_size") or 0)
    leaf_cert_sig_size    = int(features.get("leaf_cert_sig_size")    or 0)
    cert_chain_length     = int(features.get("cert_chain_length")     or 0)

    return np.array([[ke_pqc, cert_pqc, key_share_size,
                      leaf_cert_pubkey_size, leaf_cert_sig_size,
                      cert_chain_length]], dtype=float)


# ---------------------------------------------------------------------------
# Posture colouring
# ---------------------------------------------------------------------------

POSTURE_STYLE = {
    "Classical":  ("label.classical", "🔴"),
    "KE-PQC":     ("label.ke_pqc",   "🟡"),
    "Cert-PQC":   ("label.cert_pqc", "🟡"),
    "Full-PQC":   ("label.full_pqc", "🟢"),
}

POSTURE_DESC = {
    "Classical":  "No PQC — fully vulnerable to harvest-now-decrypt-later attacks",
    "KE-PQC":     "Hybrid PQC key exchange; classical certificate chain",
    "Cert-PQC":   "Classical key exchange; PQC-signed certificate chain",
    "Full-PQC":   "Full PQC — quantum-resistant key exchange AND certificate chain",
}


# ---------------------------------------------------------------------------
# Main scan orchestration
# ---------------------------------------------------------------------------

def run_scan(domain: str, model, pqc_kem_ids: set, pqc_cert_oids: set):
    iface = get_default_interface()
    tmp_dir = tempfile.mkdtemp(prefix="pqcrecon_")
    pcap_path   = os.path.join(tmp_dir, "capture.pcap")
    keylog_path = os.path.join(tmp_dir, "sslkeys.log")

    features = {}
    tcpdump_proc = None

    try:
        with console.status(
            f"[bold cyan]⚡ Scanning [white]{domain}[/white] "
            f"on interface [white]{iface}[/white] …[/bold cyan]",
            spinner="dots",
            spinner_style="cyan",
        ):
            # ── 1. Start tcpdump ────────────────────────────────────────────
            tcpdump_cmd = [
                "tcpdump", "-U", "-i", iface,
                "host", domain, "and", "port", "443",
                "-w", pcap_path,
            ]
            tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1.2)  # Let tcpdump initialise

            # ── 2. TLS 1.3 handshake via openssl s_client ──────────────────
            openssl_cmd = [
                "openssl", "s_client",
                "-connect", f"{domain}:443",
                "-tls1_3",
                "-keylogfile", keylog_path,
            ]
            try:
                subprocess.run(
                    openssl_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except subprocess.TimeoutExpired:
                console.print("[warn]⚠  openssl s_client timed out — partial capture may still work[/warn]")

            # Give tcpdump time to flush TCP teardown packets (esp. large PQC certs)
            time.sleep(3)

            # ── 3. Stop tcpdump ─────────────────────────────────────────────
            if tcpdump_proc and tcpdump_proc.poll() is None:
                tcpdump_proc.send_signal(signal.SIGTERM)
                try:
                    tcpdump_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    tcpdump_proc.kill()
                    tcpdump_proc.wait()
            tcpdump_proc = None

            # ── 4. Feature extraction ───────────────────────────────────────
            if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) == 0:
                raise RuntimeError(
                    f"PCAP file empty or missing ({pcap_path}). "
                    "Ensure tcpdump has the required privileges (e.g. sudo / cap_net_raw)."
                )
            if not os.path.exists(keylog_path):
                raise RuntimeError(
                    "TLS key log not written — the handshake likely failed. "
                    "Check that the domain supports TLS 1.3."
                )

            features = extract_features_from_pcap(pcap_path, keylog_path)

    finally:
        # Always kill tcpdump if still alive
        if tcpdump_proc and tcpdump_proc.poll() is None:
            tcpdump_proc.kill()
            tcpdump_proc.wait()
        # Secure cleanup
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return features


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------

def classify(features: dict, model, pqc_kem_ids: set, pqc_cert_oids: set) -> str:
    X = engineer_features(features, pqc_kem_ids, pqc_cert_oids)
    prediction = model.predict(X)[0]
    return prediction


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def render_results(domain: str, features: dict, posture: str):
    style, emoji = POSTURE_STYLE.get(posture, ("white", "⚪"))

    # ── Raw features table ─────────────────────────────────────────────────
    def parse_gid(val):
        if val is None:
            return None
        s = str(val).strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None

    group_id_int = parse_gid(features.get("supported_group_id"))
    kem_name     = KEM_NAMES.get(group_id_int, f"Unknown (0x{group_id_int:04x})" if group_id_int else "N/A")
    cert_oid     = str(features.get("leaf_cert_oid") or "N/A").strip()
    cert_name    = OID_NAMES.get(cert_oid, f"Unknown ({cert_oid})")

    features_table = Table(
        show_header=True, header_style="bold white on dark_blue",
        border_style="cyan", box=box.ROUNDED, padding=(0, 1),
        title="[bold white]Extracted TLS 1.3 Handshake Features[/bold white]",
        title_style="bold cyan",
    )
    features_table.add_column("Feature",        style="field", no_wrap=True, width=30)
    features_table.add_column("Raw Value",       style="value", width=22)
    features_table.add_column("Interpretation",  style="dim white", width=38)

    features_table.add_row(
        "Key Exchange Group",
        str(features.get("supported_group_id") or "N/A"),
        kem_name,
    )
    features_table.add_row(
        "Key Share Size",
        f"{features.get('key_share_size') or 'N/A'} bytes",
        "PQC hybrid ≥ 1,088 B  |  Classical ≤ 97 B",
    )
    features_table.add_row(
        "Cert Signature OID",
        cert_oid,
        cert_name,
    )
    features_table.add_row(
        "Cert Public Key Size",
        f"{features.get('leaf_cert_pubkey_size') or 'N/A'} bytes",
        "PQC ≥ 1,312 B  |  Classical ≤ 270 B",
    )
    features_table.add_row(
        "Cert Signature Size",
        f"{features.get('leaf_cert_sig_size') or 'N/A'} bytes",
        "PQC ≥ 2,420 B  |  Classical ≤ 256 B",
    )
    features_table.add_row(
        "Certificate Chain Length",
        str(features.get("cert_chain_length") or "N/A"),
        "",
    )

    # ── Verdict table ──────────────────────────────────────────────────────
    verdict_table = Table(
        show_header=False,
        border_style=style.split(".")[1] if "." in style else "white",
        box=box.HEAVY,
        padding=(0, 2),
    )
    verdict_table.add_column("", style="bold white", width=22)
    verdict_table.add_column("", style="bold white", width=60)

    verdict_table.add_row("Target Domain",        f"[bold white]{domain}[/bold white]")
    verdict_table.add_row(
        "PQC Posture",
        f"[{style}]{emoji}  {posture}[/{style}]",
    )
    verdict_table.add_row(
        "Assessment",
        f"[dim white]{POSTURE_DESC.get(posture, '')}[/dim white]",
    )

    console.print()
    console.rule("[bold cyan]PQCRecon — Scan Results[/bold cyan]", style="cyan")
    console.print()
    console.print(features_table)
    console.print()
    console.print(Panel(
        verdict_table,
        title=f"[bold white]Classification Verdict[/bold white]",
        border_style=style.split(".")[1] if "." in style else "white",
        padding=(1, 2),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        prog="pqcrecon",
        description="PQCRecon — Active TLS 1.3 Post-Quantum Cryptography Posture Classifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 pqcrecon/pqcrecon.py cloudflare.com\n"
            "  sudo python3 pqcrecon/pqcrecon.py pq.cloudflareresearch.com\n\n"
            "Note: tcpdump requires cap_net_raw privilege or sudo."
        ),
    )
    parser.add_argument("domain", help="Target domain to scan (e.g. cloudflare.com)")
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()
    domain = args.domain.strip().lstrip("https://").lstrip("http://").rstrip("/")

    console.print(f"  [info]Target  :[/info] [bold white]{domain}[/bold white]")
    console.print(f"  [info]Model   :[/info] [field]{MODEL_PATH}[/field]")
    console.print()

    # Load model artifacts
    model, pqc_kem_ids, pqc_cert_oids = load_artifacts()
    console.print()

    # Capture + extract
    try:
        features = run_scan(domain, model, pqc_kem_ids, pqc_cert_oids)
    except RuntimeError as exc:
        console.print(Panel(
            f"[error]Scan failed:[/error]\n  [warn]{exc}[/warn]",
            title="[error]Capture Error[/error]",
            border_style="red",
            padding=(1, 2),
        ))
        sys.exit(1)
    except Exception as exc:
        console.print(Panel(
            f"[error]Unexpected error during scan:[/error]\n  [warn]{exc}[/warn]",
            title="[error]Error[/error]",
            border_style="red",
            padding=(1, 2),
        ))
        sys.exit(1)

    # Check that we extracted at least the minimum viable features
    if features.get("supported_group_id") is None and features.get("leaf_cert_oid") is None:
        console.print(Panel(
            "[warn]⚠  No TLS 1.3 handshake features could be extracted.[/warn]\n"
            "[info]Possible causes:[/info]\n"
            "  • The domain does not support TLS 1.3\n"
            "  • A firewall or CDN blocked the connection\n"
            "  • tcpdump lacked capture privileges (try [value]sudo[/value])\n"
            "  • The PCAP was too short to contain certificate data",
            title="[warn]Extraction Warning[/warn]",
            border_style="yellow",
            padding=(1, 2),
        ))
        sys.exit(1)

    # Classify
    posture = classify(features, model, pqc_kem_ids, pqc_cert_oids)

    # Render
    render_results(domain, features, posture)


if __name__ == "__main__":
    main()
