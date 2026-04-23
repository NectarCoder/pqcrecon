#!/usr/bin/env python3
import sys
import csv
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

# Make sure we can import pqcrecon
SCRIPT_DIR = Path(__file__).parent.resolve()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

try:
    import pqcrecon
    from pqcrecon import load_artifacts, run_scan, classify, KEM_NAMES, OID_NAMES
    import contextlib
    
    @contextlib.contextmanager
    def dummy_status(*args, **kwargs):
        yield
        
    pqcrecon.console.status = dummy_status
except ImportError as e:
    print(f"Error importing pqcrecon: {e}")
    sys.exit(1)

def process_domain(domain, model, pqc_kem_ids, pqc_cert_oids):
    """
    Scan a single domain using PQCRecon's functions.
    """
    try:
        features = run_scan(domain, model, pqc_kem_ids, pqc_cert_oids)
        if features.get("supported_group_id") is None and features.get("leaf_cert_oid") is None:
            posture = "Error (No valid TLS 1.3 features)"
        else:
            posture = classify(features, model, pqc_kem_ids, pqc_cert_oids)
            
        def parse_gid(val):
            if val is None:
                return None
            s = str(val).strip()
            try:
                return int(s, 16) if s.lower().startswith("0x") else int(s)
            except ValueError:
                return None

        group_id_int = parse_gid(features.get("supported_group_id"))
        kem_name = KEM_NAMES.get(group_id_int, f"Unknown (0x{group_id_int:04x})" if group_id_int else "N/A")
        cert_oid = str(features.get("leaf_cert_oid") or "N/A").strip()
        cert_name = OID_NAMES.get(cert_oid, f"Unknown ({cert_oid})")

        return {
            "domain": domain,
            "posture": posture,
            "key_exchange_group": str(features.get("supported_group_id") or "N/A"),
            "key_exchange_name": kem_name,
            "cert_signature_oid": cert_oid,
            "cert_signature_name": cert_name
        }
    except Exception as e:
        return {
            "domain": domain,
            "posture": f"Error ({str(e)})",
            "key_exchange_group": "N/A",
            "key_exchange_name": "N/A",
            "cert_signature_oid": "N/A",
            "cert_signature_name": "N/A"
        }

def main():
    tranco_csv = SCRIPT_DIR / "tranco_X4Y2N.csv"
    output_csv = SCRIPT_DIR / "top100_pqc_posture.csv"
    
    # Load model and lookups via PQCRecon artifact loader
    try:
        model, pqc_kem_ids, pqc_cert_oids = load_artifacts()
    except Exception as e:
        print(f"Failed to load artifacts: {e}")
        sys.exit(1)

    all_domains = []
    if not tranco_csv.exists():
        print(f"Could not find {tranco_csv}")
        sys.exit(1)
        
    with open(tranco_csv, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                all_domains.append(row[1])

    print(f"Loaded {len(all_domains)} domains from Tranco list. Scanning until 100 successes...")

    results = []
    successful_count = 0
    domain_idx = 0

    # Setting max_workers cautiously to avoid overwhelming the system
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {}
        
        # Initial batch
        while len(future_to_domain) < 5 and domain_idx < len(all_domains):
            domain = all_domains[domain_idx]
            future_to_domain[executor.submit(process_domain, domain, model, pqc_kem_ids, pqc_cert_oids)] = domain
            domain_idx += 1
            
        while future_to_domain and successful_count < 100:
            done, not_done = wait(future_to_domain.keys(), return_when=FIRST_COMPLETED)
            
            for future in done:
                domain = future_to_domain.pop(future)
                try:
                    res = future.result()
                    if not res['posture'].startswith("Error"):
                        results.append(res)
                        successful_count += 1
                        print(f"[{successful_count}/100] Success: {domain} -> {res['posture']}")
                    else:
                        print(f"Failed/Skipped: {domain} -> {res['posture']}")
                except Exception as e:
                    print(f"Failed/Skipped: {domain} generated an exception: {e}")
                
                if successful_count >= 100:
                    break
                    
                # Replenish queue
                if domain_idx < len(all_domains):
                    next_domain = all_domains[domain_idx]
                    future_to_domain[executor.submit(process_domain, next_domain, model, pqc_kem_ids, pqc_cert_oids)] = next_domain
                    domain_idx += 1

    # Write results to CSV
    fieldnames = [
        "domain", 
        "posture", 
        "key_exchange_group", 
        "key_exchange_name", 
        "cert_signature_oid", 
        "cert_signature_name"
    ]
    with open(output_csv, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in results:
            writer.writerow(res)
            
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
