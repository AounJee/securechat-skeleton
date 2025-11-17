# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def pkcs7_pad(data: bytes, block=16) -> bytes:
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if not (1 <= pad_len <= 16):
        raise ValueError("Bad PKCS#7 padding")
    return data[:-pad_len]

def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded = pkcs7_pad(plaintext)
    return encryptor.update(padded) + encryptor.finalize()

def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(decrypted)
