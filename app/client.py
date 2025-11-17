# app/client.py
import socket, json
from app.crypto.aes import aes_encrypt_ecb
from app.crypto.dh import dh_generate_keypair, dh_compute_shared
from app.common.utils import b64e, now_ms
from app.crypto.sign import sign_msg
from app.common.protocol import Hello, DHParams, Login, ChatMsg

def sendjson(conn, obj):
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, "big") + data)

def recvjson(conn):
    size = int.from_bytes(conn.recv(4), "big")
    return json.loads(conn.recv(size).decode())

def client():
    s = socket.socket()
    s.connect(("127.0.0.1", 9000))

    # Load cert/key
    cert = open("certs/client_cert.pem","rb").read()
    key = open("certs/client_key.pem","rb").read()

    # 1) Send Hello
    sendjson(s, Hello(cert=b64e(cert)).dict())

    # 2) DH
    priv, pub = dh_generate_keypair()
    dh_server = DHParams(**recvjson(s))
    sendjson(s, {"type":"dh", "pub": str(pub)})
    session_key = dh_compute_shared(int(dh_server.pub), priv)

    # 3) Login
    pwd_enc = aes_encrypt_ecb(session_key, b"supersecret")
    sendjson(s, Login(email="test@example.com", pwd_enc=b64e(pwd_enc)).dict())
    print("Login:", recvjson(s))

    # 4) Chat
    seq = 1
    msg_body = b"Hello secure world!"
    ct = aes_encrypt_ecb(session_key, msg_body)
    raw = f"{seq}|{now_ms()}|{b64e(ct)}".encode()
    sig = sign_msg(key, raw)

    sendjson(s, ChatMsg(
        seq=seq,
        ts=now_ms(),
        ct=b64e(ct),
        sig=sig
    ).dict())

    # 5) Receipt
    print("Receipt:", recvjson(s))

    s.close()

if __name__ == "__main__":
    client()
