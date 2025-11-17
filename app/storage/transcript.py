# app/storage/transcript.py
import os, hashlib

BASE = "transcripts"
os.makedirs(BASE, exist_ok=True)

def append_entry(session_id: str, line: str):
    path = os.path.join(BASE, f"{session_id}.log")
    with open(path, "a") as f:
        f.write(line + "\n")

def transcript_hash(session_id: str) -> str:
    path = os.path.join(BASE, f"{session_id}.log")
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()
