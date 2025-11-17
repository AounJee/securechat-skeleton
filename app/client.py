#!/usr/bin/env python3
"""
client.py - connects to server and exchanges certificates
"""
import socket
import os
from cryptography import x509

BASE = os.path.dirname(os.path.dirname(__file__))
CERTS_DIR = os.path.join(BASE, "certs")
CLIENT_CERT = os.path.join(CERTS_DIR, "client_cert.pem")
CA_CERT = os.path.join(CERTS_DIR, "ca_cert.pem")

def main():
    host = "127.0.0.1"
    port = 9000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Receive server cert
    size_bytes = s.recv(4)
    size = int.from_bytes(size_bytes, 'big')
    server_pem = b''
    while len(server_pem) < size:
        server_pem += s.recv(size - len(server_pem))
    print("Received server cert")
    # Send client cert
    with open(CLIENT_CERT, "rb") as f:
        client_pem = f.read()
    s.sendall(len(client_pem).to_bytes(4, 'big') + client_pem)
    # Read server response
    resp = s.recv(1024)
    print("Server response:", resp.decode())
    s.close()

if __name__ == "__main__":
    main()
