# app/common/utils.py
import base64
import hashlib
import time

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def now_ms() -> int:
    return int(time.time() * 1000)
