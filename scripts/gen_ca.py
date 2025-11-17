#!/usr/bin/env python3
"""
gen_ca.py
Generates a root CA private key and self-signed certificate.
Outputs:
 - certs/ca_key.pem   (PEM, private)  -> DO NOT commit
 - certs/ca_cert.pem  (PEM, public)
"""
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
os.makedirs(OUT_DIR, exist_ok=True)
KEY_PATH = os.path.join(OUT_DIR, "ca_key.pem")
CERT_PATH = os.path.join(OUT_DIR, "ca_cert.pem")

def main():
    # Generate key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Name
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES-CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FAST-NUCES Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    # Write key (PEM) - keep local, DO NOT commit this file
    with open(KEY_PATH, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Write cert (PEM) - safe to share
    with open(CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"CA key written to {KEY_PATH}")
    print(f"CA cert written to {CERT_PATH}")

if __name__ == "__main__":
    main()
