# app/common/protocol.py
from pydantic import BaseModel

class Hello(BaseModel):
    type: str = "hello"
    cert: str

class DHParams(BaseModel):
    type: str = "dh"
    pub: str

class Login(BaseModel):
    type: str = "login"
    email: str
    pwd_enc: str

class ChatMsg(BaseModel):
    type: str = "msg"
    seq: int
    ts: int
    ct: str
    sig: str

class Receipt(BaseModel):
    type: str = "receipt"
    first_seq: int
    last_seq: int
    transcript_sha256: str
    sig: str
