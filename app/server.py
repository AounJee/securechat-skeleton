#!/usr/bin/env python3
"""
server.py - simple TCP server that performs certificate exchange and validation.
"""
import socket
import json
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

BASE = os.path.dirname(os.path.dirname(__file__))
CERTS_DIR = os.path.join(BASE, "certs")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca_cert.pem")
SERVER_CERT = os.path.join(CERTS_DIR, "server_cert.pem")
SERVER_KEY = os.path.join(CERTS_DIR, "server_key.pem")

def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def verify_cert(cert_pem):
    ca = load_cert(CA_CERT_PATH)
    cert = x509.load_pem_x509_certificate(cert_pem)
    # verify issuer matches CA subject
    if cert.issuer != ca.subject:
        print("BAD CERT: issuer mismatch")
        return False
    # expiry check
    from datetime import datetime
    now = datetime.utcnow()
    if cert.not_valid_before > now or cert.not_valid_after < now:
        print("BAD CERT: expired or not yet valid")
        return False
    # signature verify
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        print("BAD CERT: signature verify failed", e)
        return False
    return True

def main():
    host = "0.0.0.0"
    port = 9000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print(f"Server listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        print("Connection from", addr)
        # Send server cert
        with open(SERVER_CERT, "rb") as f:
            server_cert_pem = f.read()
        conn.sendall(len(server_cert_pem).to_bytes(4, 'big') + server_cert_pem)
        # Receive client cert
        size_bytes = conn.recv(4)
        if not size_bytes:
            conn.close(); continue
        size = int.from_bytes(size_bytes, 'big')
        client_pem = b''
        while len(client_pem) < size:
            client_pem += conn.recv(size - len(client_pem))
        print("Received client cert, verifying...")
        ok = verify_cert(client_pem)
        if not ok:
            conn.sendall(b"BAD CERT")
            conn.close()
            continue
        conn.sendall(b"OK")
        # After this point, we would proceed to registration/login
        print("Client cert OK, ready for next phases.")
        conn.close()

if __name__ == "__main__":
    main()
