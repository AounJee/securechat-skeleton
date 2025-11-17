# app/crypto/sign.py
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def sign_msg(private_key_pem: bytes, data: bytes) -> str:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()

def verify_msg(cert_bytes: bytes, data: bytes, sig_b64: str) -> bool:
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_bytes)
    pub = cert.public_key()
    sig = base64.b64decode(sig_b64)
    try:
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
