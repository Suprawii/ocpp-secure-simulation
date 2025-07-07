import os
from cryptography.fernet import Fernet

PASSWORD_FILE = "cp_password.txt"
KEY_ENV_VAR = "CP_FERNET_KEY"

def get_fernet():
    key = os.environ.get(KEY_ENV_VAR)
    if not key:
        raise RuntimeError(
            f"Fernet key not found in environment variable {KEY_ENV_VAR}! "
            "Generate one with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        )
    return Fernet(key.encode())

def store_password(password: str):
    fernet = get_fernet()
    enc = fernet.encrypt(password.encode())
    with open(PASSWORD_FILE, "wb") as f:
        f.write(enc)

def load_password() -> str:
    if not os.path.exists(PASSWORD_FILE):
        return None
    fernet = get_fernet()
    with open(PASSWORD_FILE, "rb") as f:
        enc = f.read()
    return fernet.decrypt(enc).decode()