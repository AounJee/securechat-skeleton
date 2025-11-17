# scripts/gen_ca.py
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

os.makedirs("certs", exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("certs/ca_key.pem","wb") as f:
    f.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    )

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    .sign(key, hashes.SHA256())
)

with open("certs/ca_cert.pem","wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("CA generated.")
