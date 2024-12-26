#!/usr/bin/env python3
import os
import sys
import ssl
import time
import random
import socket
import string
import argparse
import subprocess

def generate_random_code(num_digits=6):
    """Generate a random numeric code of length num_digits."""
    return "".join(str(random.randint(0, 9)) for _ in range(num_digits))

def generate_certificate(certfile="server-cert.pem", keyfile="server-key.pem"):
    """
    Generate a self-signed certificate and private key using openssl.
    This overwrites any existing files with the same names.
    """
    print("[*] Generating ephemeral self-signed certificate...")
    cmd = [
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-keyout", keyfile,
        "-out", certfile,
        "-days", "1",
        "-subj", "/CN=localhost"
    ]
    subprocess.run(cmd, check=True)

def human_readable_size(num_bytes):
    """Return a human-readable string for byte sizes (e.g., KB, MB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"

def run_server(port=None):
    # Step 1: Generate random 6-digit code
    secret_code = generate_random_code(6)
    print(f"[*] Generated code for client authentication: {secret_code}")

    # Step 2: Generate certificate/key pair using openssl
    certfile = "server-cert.pem"
    keyfile = "server-key.pem"
    generate_certificate(certfile, keyfile)

    # Step 3: Create listening TCP socket
    if port is None:
        # Random ephemeral port: 0 means OS picks a free port
        port = 0  
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", port))
    sock.listen(1)

    # If the system assigned a random port, retrieve it
    assigned_port = sock.getsockname()[1]
    print(f"[*] Server listening on port {assigned_port} (TLS enabled).")

    # Step 4: Wrap socket with TLS
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    try:
        # Only allow a single connection
        while True:
            print("[*] Waiting for a single connection...")
            conn, addr = sock.accept()
            print(f"[+] Connection from {addr}. Wrapping with TLS...")
            with context.wrap_socket(conn, server_side=True) as tls_conn:
                # Step 5: Validate code
                received_code_bytes = tls_conn.recv(6)
                if not received_code_bytes:
                    print("[!] No code received, closing connection.")
                    tls_conn.close()
                    continue
                received_code = received_code_bytes.decode("utf-8", errors="ignore")

                if received_code != secret_code:
                    print("[!] Invalid code from client. Closing connection.")
                    tls_conn.close()
                    continue
                else:
                    print("[+] Client authenticated successfully.")

                # Step 6: Receive file metadata
                #   We'll expect: filename length (4 bytes, big-endian), then filename,
                #   then 8 bytes for file size (big-endian unsigned long long).
                meta = tls_conn.recv(4)
                if len(meta) < 4:
                    print("[!] Invalid metadata. Closing.")
                    tls_conn.close()
                    continue
                filename_len = int.from_bytes(meta, "big")
                filename_bytes = tls_conn.recv(filename_len)
                filename = filename_bytes.decode("utf-8", errors="ignore")

                size_bytes = tls_conn.recv(8)
                file_size = int.from_bytes(size_bytes, "big")

                print(f"[+] Receiving file: '{filename}' ({human_readable_size(file_size)})")

                # Step 7: Receive file data
                received = 0
                chunk_size = 4096
                start_time = time.time()

                with open(filename, "wb") as f:
                    while received < file_size:
                        chunk = tls_conn.recv(min(chunk_size, file_size - received))
                        if not chunk:
                            break
                        f.write(chunk)
                        received += len(chunk)

                        # Calculate progress
                        elapsed = max(time.time() - start_time, 0.001)
                        speed = received / elapsed  # bytes per second
                        percent = (received / file_size) * 100

                        # Display progress
                        bar_len = 30
                        filled = int(bar_len * percent / 100)
                        bar = "#" * filled + "-" * (bar_len - filled)
                        sys.stdout.write(
                            f"\r    [{bar}] {percent:6.2f}% | "
                            f"{human_readable_size(speed)}/s"
                        )
                        sys.stdout.flush()

                print("\n[+] File transfer complete.")
                print("[+] Closing connection.")
                tls_conn.close()
                break  # Only one connection allowed
    finally:
        sock.close()
        # Clean up the generated cert/key if desired
        os.remove(certfile)
        os.remove(keyfile)

def main():
    parser = argparse.ArgumentParser(description="Simple TLS-secured file-receiving server.")
    parser.add_argument("-p", "--port", type=int, help="Port to listen on (random if not specified).")
    args = parser.parse_args()
    run_server(args.port)

if __name__ == "__main__":
    main()
