#!/usr/bin/env python3
"""
DB helper using mysql-connector
"""
import os
import mysql.connector

def get_conn():
    from dotenv import load_dotenv
    load_dotenv()
    import os as _os
    return mysql.connector.connect(
        host=_os.getenv("MYSQL_HOST", "127.0.0.1"),
        user=_os.getenv("MYSQL_USER", "root"),
        password=_os.getenv("MYSQL_PASS", ""),
        database=_os.getenv("MYSQL_DB", "securechat"),
        auth_plugin='mysql_native_password'
    )
