#!/usr/bin/env python3
"""
gen_cert.py
Usage:
  python3 scripts/gen_cert.py --cn server --out certs/server_cert.pem --key-out certs/server_key.pem
Creates an RSA keypair and issues an X.509 certificate signed by the root CA.

"""
import os
import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CA_KEY_PATH = os.path.join(CERTS_DIR, "ca_key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca_cert.pem")

def create_cert(common_name: str, out_cert: str, out_key: str):
    # load CA key and cert
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # write key
    with open(out_key, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # write certificate
    with open(out_cert, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated {out_cert}, {out_key}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name (CN) for the cert")
    parser.add_argument("--out", required=True, help="Path to output cert PEM")
    parser.add_argument("--key-out", required=True, help="Path to output private key PEM")
    args = parser.parse_args()

    os.makedirs(CERTS_DIR, exist_ok=True)
    create_cert(args.cn, args.out, args.key_out)

if __name__ == "__main__":
    main()
