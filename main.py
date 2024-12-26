#!/usr/bin/env python3
import os
import sys
import ssl
import time
import socket
import argparse
import subprocess
import random

buffer_size = (8 * 1024)
speed_probe_size = 64
progress_bar_width = 45

# Main Functions
def client_main(host,port,code,file_path):
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    print(f"[*] Sending file '{filename}' ({size_string(file_size)})")
    print(f"[*] Connecting to {host}:{port} over TLS...")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host,port)) as raw_socket:
        with context.wrap_socket(raw_socket,server_hostname = host) as tls_socket:
            tls_socket.sendall(int(code).to_bytes(3,"big"))

            filename_bytes = filename.encode("utf-8")
            filename_len = len(filename_bytes)
            tls_socket.sendall(filename_len.to_bytes(1,"big"))
            tls_socket.sendall(filename_bytes)
            tls_socket.sendall(file_size.to_bytes(8,"big"))

            if (tls_socket.recv(1) != 0x01.to_bytes(1,"big")):
                print("[!] The server has declined file transfer.")
                return

            local_cursor = 0
            probe_cursor = 0
            transfer_probes = ([None] * speed_probe_size)

            with open(file_path,"rb") as input_file:
                while True:
                    buffer = input_file.read(4096)
                    if (not buffer):
                        break

                    tls_socket.sendall(buffer)
                    transmit_time = time.perf_counter()
                    local_cursor += len(buffer)

                    transfer_probes[probe_cursor] = [transmit_time,local_cursor]
                    probe_cursor += 1
                    if (probe_cursor >= speed_probe_size):
                        probe_cursor = 0

                    print_progress(
                        speed = probes_to_speed(transfer_probes),
                        transmitted = local_cursor,
                        total = file_size
                    )

            print("\n[+] File transfer complete, waiting for confirmation...")
            if (tls_socket.recv(1) == 0x01.to_bytes(1,"big")):
                print("[+] The server has confirmed file transfer.")
    print("[+] Connection closed.")

def server_main(port = None):
    secret_code = random_digits(6)
    print(f"[*] Generated 6-digit code: {secret_code}")

    certfile = "transfer-cert.pem"
    keyfile = "transfer-key.pem"
    generate_cert(certfile,keyfile)

    if (not port):
        port = 0

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as raw_socket:
        raw_socket.bind(("0.0.0.0",port))
        raw_socket.listen(1)

        assigned_port = raw_socket.getsockname()[1]
        print(f"[*] Server listening on port {assigned_port}.")

        tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
        tls_context.load_cert_chain(
            certfile = certfile,
            keyfile = keyfile
        )

        while True:
            print("[*] Waiting for connection...")
            connection,address = raw_socket.accept()
            with tls_context.wrap_socket(connection,server_side = True) as tls_connection:
                recv_code = tls_connection.recv(3)
                if (not recv_code):
                    print("[!] No code received, closing connection.")
                    tls_connection.close()
                    continue
                print("[+] Client authenticated successfully.")

                file_name_length = int.from_bytes(tls_connection.recv(1),"big")
                file_name = tls_connection.recv(file_name_length).decode("utf-8")
                file_size = int.from_bytes(tls_connection.recv(8),"big")

                tls_connection.sendall(0x01.to_bytes(1,"big"))
                print(f"[+] Receiving file: '{file_name}' ({size_string(file_size)})")
                local_cursor = 0
                probe_cursor = 0
                transfer_probes = ([None] * speed_probe_size)

                if (not os.path.abspath(file_name).startswith(os.path.abspath(""))):
                    print("[!] Client provided an invalid path.")
                    tls_connection.close()
                    continue

                with open(file_name,"wb") as file_handle:
                    while (local_cursor < file_size):
                        buffer = tls_connection.recv(min((file_size - local_cursor),buffer_size))
                        if (not buffer):
                            print("[!] Connection was interrupted.")
                            break
                        file_handle.write(buffer)
                        transmit_time = time.perf_counter()
                        local_cursor += len(buffer)
                        
                        transfer_probes[probe_cursor] = [transmit_time,local_cursor]
                        probe_cursor += 1
                        if (probe_cursor >= speed_probe_size):
                            probe_cursor = 0

                        print_progress(
                            speed = probes_to_speed(transfer_probes),
                            transmitted = local_cursor,
                            total = file_size
                        )

                tls_connection.sendall(0x01.to_bytes(1,"big"))
                print("\n[+] File transfer complete, confimed.")
                tls_connection.close()
                print("[+] Closed connection.")
                continue

# Utility
def size_string(num_bytes):
    for unit in ["B","KB","MB","GB","TB"]:
        if (num_bytes < 1024):
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.2f} PB"

def time_string(seconds):
    hours = (seconds // 3600)
    minutes = ((seconds % 3600) // 60)
    remaining_seconds = int(seconds % 60)
    
    if (hours > 0):
        return f"{hours}h {minutes}m {remaining_seconds}s"
    else:
        return f"{minutes}m {remaining_seconds}s"
    
def random_digits(digits):
    return "".join(str(random.randint(0,9)) for _ in range(digits))

def probes_to_speed(probe_list):
    if (len(probe_list) <= 1):
        return 0

    probe_list = [probe for probe in probe_list if probe is not None]
    sorted_probes = sorted(probe_list, key=lambda x: x[0])

    total_time = (sorted_probes[-1][0] - sorted_probes[0][0])
    total_bytes = (sorted_probes[-1][1] - sorted_probes[0][1])

    if (total_time == 0):
        return 0

    speed = (total_bytes / total_time)
    return speed

last_progress_length = 0
def print_progress(speed,transmitted,total):
    global last_progress_length

    progress = (transmitted / total)
    if (speed != 0):
        seconds_left = ((total - transmitted) / speed)
    else:
        seconds_left = 0
    bar_fill = (progress * progress_bar_width)
    progress_text = f"\r    [{'#' * int(bar_fill)}{'-' * (progress_bar_width - int(bar_fill))}] {(progress * 100):6.2f}% {size_string(speed):>7}/s {time_string(seconds_left)}"
    next_progress_length = len(progress_text)
    progress_text = (progress_text + (" " * (last_progress_length - next_progress_length)))
    last_progress_length = next_progress_length

    sys.stdout.write(progress_text)
    sys.stdout.flush()

def generate_cert(certfile,keyfile):
    print("[*] Generating self-signed certificate...")
    subprocess.run(
        args = [
            "openssl","req","-x509","-nodes","-newkey","rsa:2048",
            "-keyout",keyfile,
            "-out",certfile,
            "-days","1",
            "-subj","/CN=localhost"
        ],
        check = True
    )

# Main
def main():
    is_server = ((len(sys.argv) >= 2) and (sys.argv[1] == "-s"))
    if (is_server):
        sys.argv.pop(1)
        parser = argparse.ArgumentParser(description="Simple TLS-secured file-transmitting tool (-s).")
        parser.add_argument("-p","--port",help = "Port to listen on (random if not specified).",type = int)

        args = parser.parse_args()
        server_main()
    else:
        parser = argparse.ArgumentParser(description = "Simple TLS-secured file-transmitting tool.")
        parser.add_argument("host",help = "Server hostname or IP.")
        parser.add_argument("port",help = "Server port.",type = int)
        parser.add_argument("code",help = "6-digit code provided by the server.")
        parser.add_argument("file",help = "Path to the file to send.")

        args = parser.parse_args()
        client_main(args.host,args.port,args.code,args.file)

if (__name__ == "__main__"):
    main()
