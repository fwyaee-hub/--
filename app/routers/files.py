import os
import hashlib
import time
from urllib.parse import quote
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from fastapi.responses import StreamingResponse, RedirectResponse
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from app.database import get_db
from app.models import User, File as FileModel, SharedFile, TrashItem
from app.dependencies import get_current_user
from app.config import Config
from app.utils import allowed_file, wrap_file_key, unwrap_file_key, is_safe_filename, normalize_filename, user_storage_dir, user_storage_path, legacy_storage_path, ensure_user_storage_file, trash_dir, trash_path

router = APIRouter(
    prefix="/api/files",
    tags=["files"],
    responses={404: {"description": "Not found"}},
)

@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    """
    Uploads a file and encrypts it using AES-256-CBC.
    
    Security Implementation (Interview Key Point):
    1. Generates a random 32-byte AES key (256-bit) per file.
    2. Generates a random 16-byte IV (Initialization Vector) to ensure semantic security.
    3. Uses PKCS7 padding to handle files that are not multiples of the block size (128-bit).
    4. Stores the IV prepended to the ciphertext (common practice as IV doesn't need to be secret, just unique).
    """
    if not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    filename = normalize_filename(file.filename)
    if not filename or not is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    existing = db.query(FileModel).filter(FileModel.user_id == current_user.id, FileModel.filename == filename).first()
    if existing:
        raise HTTPException(status_code=409, detail="File already exists")
    
    # 1. Key Generation
    # We use os.urandom for cryptographically strong random numbers
    key = os.urandom(32)  # 256 bits
    iv = os.urandom(16)   # 128 bits (AES block size)
    
    # 2. Encryption Setup
    # CBC (Cipher Block Chaining) mode is used.
    # Note: GCM mode would be better for integrity, but CBC is standard for this demo level.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 3. Padding (PKCS7)
    # AES works on 128-bit blocks. We must pad the last block.
    padder = padding.PKCS7(128).padder()
    
    os.makedirs(user_storage_dir(current_user.id), exist_ok=True)
    encrypted_file_path = user_storage_path(current_user.id, filename)

    max_bytes = Config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    total_read = 0
    sha256 = hashlib.sha256()

    try:
        with open(encrypted_file_path, "wb") as f:
            f.write(iv)
            sha256.update(iv)

            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > max_bytes:
                    raise HTTPException(status_code=413, detail="File too large")

                padded = padder.update(chunk)
                if padded:
                    enc = encryptor.update(padded)
                    f.write(enc)
                    sha256.update(enc)

            final_padded = padder.finalize()
            enc_final = encryptor.update(final_padded) + encryptor.finalize()
            f.write(enc_final)
            sha256.update(enc_final)
    except HTTPException:
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        raise
    except Exception as e:
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        raise HTTPException(status_code=500, detail=str(e))

    file_hash = sha256.hexdigest()
        
    new_file = FileModel(
        user_id=current_user.id,
        filename=filename,
        hash=file_hash,
        encryption_key=wrap_file_key(key, user_id=current_user.id, filename=filename),
    )
    db.add(new_file)
    db.commit()
    
    return {"message": "File uploaded successfully", "filename": filename}

def _iter_decrypted_file(encrypted_file_path: str, file_key: bytes):
    with open(encrypted_file_path, "rb") as f:
        iv = f.read(16)
        cipher = Cipher(algorithms.AES(file_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()

        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            decrypted = decryptor.update(chunk)
            data = unpadder.update(decrypted)
            if data:
                yield data

        decrypted_final = decryptor.finalize()
        data_final = unpadder.update(decrypted_final) + unpadder.finalize()
        if data_final:
            yield data_final

@router.get("/")
def list_files(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    files = (
        db.query(FileModel)
        .outerjoin(TrashItem, TrashItem.file_id == FileModel.id)
        .filter(FileModel.user_id == current_user.id, TrashItem.id.is_(None))
        .all()
    )
    files_list = []
    for f in files:
        files_list.append({
            'filename': f.filename,
            'upload_time': f.upload_time,
            'hash': f.hash
        })
    return {"files": files_list}

@router.get("/download/{filename}")
def download_file(filename: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_record = db.query(FileModel).filter(
        FileModel.filename == filename,
        FileModel.user_id == current_user.id,
    ).first()

    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    trashed = db.query(TrashItem).filter(TrashItem.user_id == current_user.id, TrashItem.file_id == file_record.id).first()
    if trashed:
        raise HTTPException(status_code=404, detail="File not found")

    encrypted_file_path = ensure_user_storage_file(current_user.id, filename)
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail="Physical file missing")

    sha256 = hashlib.sha256()
    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    if sha256.hexdigest() != file_record.hash:
        raise HTTPException(status_code=400, detail="Integrity check failed")

    try:
        file_key = unwrap_file_key(file_record.encryption_key, user_id=current_user.id, filename=filename)
    except Exception:
        raise HTTPException(status_code=500, detail="Key unwrap failed")

    encoded_filename = quote(filename, safe="", encoding="utf-8")
    content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"
    return StreamingResponse(
        _iter_decrypted_file(encrypted_file_path, file_key),
        media_type="application/octet-stream",
        headers={"Content-Disposition": content_disposition},
    )

@router.delete("/{filename}")
def api_delete_file(filename: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_record = db.query(FileModel).filter(
        FileModel.filename == filename, 
        FileModel.user_id == current_user.id
    ).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found or permission denied")

    existing_trash = db.query(TrashItem).filter(TrashItem.user_id == current_user.id, TrashItem.file_id == file_record.id).first()
    if existing_trash:
        return {"message": "File moved to trash"}
    
    # Delete shares
    db.query(SharedFile).filter(SharedFile.file_id == file_record.id).delete()

    src = ensure_user_storage_file(current_user.id, filename)
    if not os.path.exists(src):
        raise HTTPException(status_code=404, detail="Physical file missing")

    os.makedirs(trash_dir(current_user.id), exist_ok=True)
    base, ext = os.path.splitext(filename)
    stored = f"{int(time.time())}_{file_record.id}{ext}"
    dst = trash_path(current_user.id, stored)
    os.replace(src, dst)

    db.add(
        TrashItem(
            user_id=current_user.id,
            file_id=file_record.id,
            stored_filename=stored,
            original_filename=filename,
        )
    )
    db.commit()

    return {"message": "File moved to trash"}

@router.get("/{filename}")
def get_file(filename: str):
    encoded = quote(filename, safe="", encoding="utf-8")
    return RedirectResponse(url=f"/api/files/download/{encoded}", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
