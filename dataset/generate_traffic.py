import os
import time
import subprocess

# Define the target ports and their corresponding certificates
PORTS_CERTS = {
    4431: "RSA",
    4432: "ECDSA-P256",
    4433: "Ed25519",
    4434: "ML-DSA-65",
    4435: "SLH-DSA-SHA2-128s",
}

# Define the KEX algorithms mapping display name to OpenSSL group name
KEX_ALGORITHMS = {
    "X25519": "X25519",
    "MLKEM768": "mlkem768",
    "X25519MLKEM768": "X25519MLKEM768"
}

PCAPS_DIR = "pcaps"

def main():
    if not os.path.exists(PCAPS_DIR):
        os.makedirs(PCAPS_DIR)

    for port, cert_name in PORTS_CERTS.items():
        for kex_display, kex_group in KEX_ALGORITHMS.items():
            pcap_filename = f"{kex_display}_{cert_name}.pcap"
            pcap_path = os.path.join(PCAPS_DIR, pcap_filename)
            
            print(f"[*] Testing Combination - Port: {port} ({cert_name}), KEX: {kex_display}")
            print(f"    -> Capturing to {pcap_path}")

            # 1. Start tcpdump
            # listen on local loopback interface and filter strictly for current target port
            # use -U to make it packet-buffered
            tcpdump_cmd = [
                "tcpdump", "-U", "-i", "lo", "port", str(port),
                "-w", pcap_path
            ]
            tcpdump_proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # 2. Synchronization pause
            time.sleep(1)

            keylog_path = os.path.join(PCAPS_DIR, f"{kex_display}_{cert_name}.keylog")

            # 3. Handshake Trigger
            openssl_cmd = [
                "openssl", "s_client",
                "-connect", f"127.0.0.1:{port}",
                "-groups", kex_group,
                "-provider", "oqsprovider",
                "-provider", "default",
                "-keylogfile", keylog_path
            ]
            
            try:
                # use subprocess.run with timeout and feed /dev/null equivalently via stdin=subprocess.DEVNULL
                result = subprocess.run(
                    openssl_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10
                )
                if result.returncode == 0:
                    print(f"    [+] Handshake successful for {kex_display} + {cert_name}")
                else:
                    print(f"    [-] Handshake failed (return code {result.returncode}) for {kex_display} + {cert_name}")
            except subprocess.TimeoutExpired:
                print(f"    [-] Handshake timed out for {kex_display} + {cert_name}")
            except Exception as e:
                print(f"    [-] Error running openssl: {e}")

            # Wait a little for TCP teardown packets to be captured
            # Increased wait time to ensure large PQC certs are fully captured
            time.sleep(4)

            # 4. Clean Teardown
            tcpdump_proc.terminate()
            try:
                tcpdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tcpdump_proc.kill()
                tcpdump_proc.wait()
                
            print("    -> Packet capture saved.\n")

if __name__ == "__main__":
    main()
