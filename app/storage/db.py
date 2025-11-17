# app/storage/db.py
import mysql.connector
from dotenv import load_dotenv
import os, hashlib, secrets

load_dotenv()

def db():
    return mysql.connector.connect(
        host=os.getenv("MYSQL_HOST"),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASS"),
        database=os.getenv("MYSQL_DB"),
        auth_plugin="mysql_native_password"
    )

def create_user(email, username, password):
    con = db()
    cur = con.cursor()

    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

    cur.execute(
        "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s,%s,%s,%s)",
        (email, username, salt, pwd_hash)
    )
    con.commit()
    cur.close()
    con.close()

def verify_user(email, password) -> bool:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT salt, pwd_hash FROM users WHERE email=%s", (email,))
    row = cur.fetchone()
    cur.close()
    con.close()

    if not row:
        return False

    salt, stored = row
    check = hashlib.sha256(salt + password.encode()).hexdigest()
    return check == stored
