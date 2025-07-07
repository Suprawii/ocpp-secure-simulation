import sqlite3
from cryptography.fernet import Fernet
import bcrypt
import os

DB_FILE = "cp_auth.db"
FERNET_KEY_FILE = "fernet.key"

def get_fernet():
    if not os.path.exists(FERNET_KEY_FILE):
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(FERNET_KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

def create_table():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS charging_points (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity TEXT UNIQUE NOT NULL,
            password_hash_enc TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_cp(identity, password_plain):
    fernet = get_fernet()
    password_hash = bcrypt.hashpw(password_plain.encode(), bcrypt.gensalt())
    password_hash_enc = fernet.encrypt(password_hash)
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO charging_points (identity, password_hash_enc) VALUES (?, ?)",
            (identity, password_hash_enc.decode())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # If already exists, do nothing (could log if needed)
        pass
    conn.close()

def get_password_hash(identity):
    fernet = get_fernet()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT password_hash_enc FROM charging_points WHERE identity=?", (identity,))
    row = cur.fetchone()
    conn.close()
    if row:
        try:
            return fernet.decrypt(row[0].encode())
        except Exception:
            # Decryption failed: possibly corrupted key/file
            return None
    return None

def check_basic_auth(username, password):
    password_hash = get_password_hash(username)
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode(), password_hash)
    except Exception:
        # bcrypt may throw if hash is not valid
        return False

def cp_exists(identity):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM charging_points WHERE identity=?", (identity,))
    exists = cur.fetchone() is not None
    conn.close()
    return exists