import base64
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import Config
from app.models import UserKey

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def is_safe_filename(filename: str) -> bool:
    if not filename:
        return False
    if "\x00" in filename:
        return False
    if "/" in filename or "\\" in filename:
        return False
    if filename in {".", ".."}:
        return False
    return True

def normalize_filename(original: str) -> str:
    if not original:
        return ""
    name = original.split("/")[-1].split("\\")[-1].strip()
    if not name:
        return ""
    cleaned = []
    for ch in name:
        o = ord(ch)
        if o < 32 or ch in '<>:"/\\|?*':
            cleaned.append("_")
        else:
            cleaned.append(ch)
    name = "".join(cleaned).strip().rstrip(".")
    if not name:
        return ""
    base, ext = os.path.splitext(name)
    reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
    if base.upper() in reserved:
        base = f"_{base}"
    name = f"{base}{ext}"
    if len(name) > 180:
        base, ext = os.path.splitext(name)
        keep = max(1, 180 - len(ext))
        name = f"{base[:keep]}{ext}"
    return name

def uniquify_filename(filename: str, used: set[str]) -> str:
    if filename not in used:
        return filename
    base, ext = os.path.splitext(filename)
    i = 1
    while True:
        candidate = f"{base} ({i}){ext}"
        if candidate not in used:
            return candidate
        i += 1

def user_storage_dir(user_id: int) -> str:
    return os.path.join(Config.UPLOAD_FOLDER, str(int(user_id)))

def user_storage_path(user_id: int, filename: str) -> str:
    return os.path.join(user_storage_dir(user_id), filename)

def legacy_storage_path(filename: str) -> str:
    return os.path.join(Config.UPLOAD_FOLDER, filename)

def ensure_user_storage_file(user_id: int, filename: str) -> str:
    new_path = user_storage_path(user_id, filename)
    if os.path.exists(new_path):
        return new_path
    old_path = legacy_storage_path(filename)
    if os.path.exists(old_path):
        os.makedirs(user_storage_dir(user_id), exist_ok=True)
        if not os.path.exists(new_path):
            try:
                os.replace(old_path, new_path)
            except OSError:
                return old_path
        return new_path
    return new_path

def trash_dir(user_id: int) -> str:
    return os.path.join(user_storage_dir(user_id), ".trash")

def trash_path(user_id: int, stored_filename: str) -> str:
    return os.path.join(trash_dir(user_id), stored_filename)

def generate_ecdh_keys():
    """Generates an Elliptic Curve key pair (SECP384R1) for user encryption."""
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def init_user_keys(user_id: int, db_session):
    """
    Checks if a user has encryption keys; if not, generates and stores them.
    This is crucial for the public key infrastructure (PKI) part of the system.
    """
    # Check if keys exist
    user_key = db_session.query(UserKey).filter(UserKey.user_id == user_id).first()
    
    if not user_key:
        private_key, public_key = generate_ecdh_keys()
        
        # Serialize keys to PEM format
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Store using ORM
        new_key = UserKey(
            user_id=user_id,
            private_key=priv_pem,
            public_key=pub_pem
        )
        db_session.add(new_key)
        db_session.commit()

def wrap_file_key(file_key: bytes, *, user_id: int, filename: str) -> bytes:
    if not Config.FILE_KEY_MASTER_KEY_B64:
        return file_key
    master = base64.b64decode(Config.FILE_KEY_MASTER_KEY_B64)
    if len(master) != 32:
        raise ValueError("FILE_KEY_MASTER_KEY_B64 must decode to 32 bytes")
    nonce = os.urandom(12)
    aad = f"{user_id}:{filename}".encode("utf-8")
    ct = AESGCM(master).encrypt(nonce, file_key, aad)
    return b"WK1" + nonce + ct

def unwrap_file_key(stored_key: bytes, *, user_id: int, filename: str) -> bytes:
    if stored_key is None:
        raise ValueError("missing key")
    if stored_key.startswith(b"WK1"):
        if not Config.FILE_KEY_MASTER_KEY_B64:
            raise ValueError("master key not configured")
        master = base64.b64decode(Config.FILE_KEY_MASTER_KEY_B64)
        if len(master) != 32:
            raise ValueError("FILE_KEY_MASTER_KEY_B64 must decode to 32 bytes")
        nonce = stored_key[3:15]
        ct = stored_key[15:]
        aad = f"{user_id}:{filename}".encode("utf-8")
        return AESGCM(master).decrypt(nonce, ct, aad)
    return stored_key

def encrypt_shared_file_key(file_key: bytes, derived_key: bytes, *, sender_id: int, receiver_id: int, filename: str) -> bytes:
    nonce = os.urandom(12)
    aad = f"{sender_id}:{receiver_id}:{filename}".encode("utf-8")
    ct = AESGCM(derived_key).encrypt(nonce, file_key, aad)
    return b"SK1" + nonce + ct

def decrypt_shared_file_key(blob: bytes, derived_key: bytes, *, sender_id: int, receiver_id: int, filename: str) -> bytes:
    if blob.startswith(b"SK1"):
        nonce = blob[3:15]
        ct = blob[15:]
        aad = f"{sender_id}:{receiver_id}:{filename}".encode("utf-8")
        return AESGCM(derived_key).decrypt(nonce, ct, aad)
    return blob
