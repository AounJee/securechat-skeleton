# scripts/gen_cert.py
import sys, os
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

entity = sys.argv[1]  # "client" or "server"

ca_key = serialization.load_pem_private_key(open("certs/ca_key.pem","rb").read(), None)
ca_cert = x509.load_pem_x509_certificate(open("certs/ca_cert.pem","rb").read())

key = rsa.generate_private_key(65537,2048)
with open(f"certs/{entity}_key.pem","wb") as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, entity),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow()+timedelta(days=365))
    .sign(ca_key, hashes.SHA256())
)

with open(f"certs/{entity}_cert.pem","wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"{entity} certificate generated.")
