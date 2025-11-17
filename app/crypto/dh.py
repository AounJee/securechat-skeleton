# app/crypto/dh.py
import secrets
import hashlib

# Small DH prime for assignment demonstration
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1", 16
)
G = 2

def dh_generate_keypair():
    priv = secrets.randbelow(P - 2) + 2
    pub = pow(G, priv, P)
    return priv, pub

def dh_compute_shared(pub_other: int, priv_self: int) -> bytes:
    shared_int = pow(pub_other, priv_self, P)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    return hashlib.sha256(shared_bytes).digest()[:16]   # 128-bit session key
