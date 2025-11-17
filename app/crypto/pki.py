# app/crypto/pki.py
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_cert(path: str):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def validate_certificate(cert_bytes: bytes, ca_cert_path: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_bytes)
    ca = load_cert(ca_cert_path)

    # Check issuer
    if cert.issuer != ca.subject:
        return False

    # Check validity
    from datetime import datetime
    now = datetime.utcnow()
    if not (cert.not_valid_before <= now <= cert.not_valid_after):
        return False

    # Verify signature
    try:
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False
