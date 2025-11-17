# app/server.py
import socket, json
from app.crypto.aes import aes_decrypt_ecb
from app.crypto.dh import dh_generate_keypair, dh_compute_shared
from app.crypto.pki import validate_certificate
from app.crypto.sign import verify_msg
from app.common.protocol import Hello, DHParams, Login, ChatMsg
from app.storage.db import verify_user
from app.storage.transcript import append_entry, transcript_hash
from app.common.utils import b64d

CA_CERT = "certs/ca_cert.pem"
SERVER_CERT = "certs/server_cert.pem"
SERVER_KEY = "certs/server_key.pem"

def sendjson(conn, obj):
    data = json.dumps(obj).encode()
    conn.sendall(len(data).to_bytes(4, "big") + data)

def recvjson(conn):
    size = int.from_bytes(conn.recv(4), "big")
    return json.loads(conn.recv(size).decode())

def server():
    s = socket.socket()
    s.bind(("0.0.0.0", 9000))
    s.listen(5)
    print("Server listening on 9000...")

    while True:
        conn, addr = s.accept()
        print("Client:", addr)

        # 1) Receive Hello with cert
        msg = recvjson(conn)
        hello = Hello(**msg)
        cert_bytes = b64d(hello.cert)

        if not validate_certificate(cert_bytes, CA_CERT):
            conn.close()
            continue

        # 2) DH
        priv, pub = dh_generate_keypair()
        sendjson(conn, {"type": "dh", "pub": str(pub)})
        dh_msg = recvjson(conn)
        dh = DHParams(**dh_msg)
        session_key = dh_compute_shared(int(dh.pub), priv)

        # 3) Login
        login = Login(**recvjson(conn))
        pwd_plain = aes_decrypt_ecb(session_key, b64d(login.pwd_enc))
        if not verify_user(login.email, pwd_plain.decode()):
            sendjson(conn, {"status": "fail"})
            conn.close()
            continue

        sendjson(conn, {"status": "ok"})

        # 4) Chat
        session = f"session_{addr[1]}"
        while True:
            try:
                msg = ChatMsg(**recvjson(conn))
                raw = f"{msg.seq}|{msg.ts}|{msg.ct}".encode()
                if not verify_msg(cert_bytes, raw, msg.sig):
                    continue  # drop invalid

                append_entry(session, raw.decode())
                print("Chat:", raw)
            except:
                break

        # 5) Receipt end
        th = transcript_hash(session)
        sendjson(conn, {"type":"receipt", "sha256": th})
        conn.close()

if __name__ == "__main__":
    server()
