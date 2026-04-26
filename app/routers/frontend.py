import os
import shutil
import hashlib
import logging
import time
from typing import Optional, List
from urllib.parse import quote
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form, UploadFile, File, Response
from fastapi.responses import RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from itsdangerous import BadSignature, SignatureExpired

from app.database import get_db
from app.models import User, File as FileModel, SharedFile, UserKey, Folder, FileMeta, TrashItem
from app.dependencies import create_access_token, SECRET_KEY, serializer
from app.config import Config
from app.utils import allowed_file, init_user_keys, wrap_file_key, unwrap_file_key, encrypt_shared_file_key, decrypt_shared_file_key, is_safe_filename, normalize_filename, uniquify_filename, user_storage_dir, user_storage_path, legacy_storage_path, ensure_user_storage_file, trash_dir, trash_path

# Setup templates
templates = Jinja2Templates(directory="templates")

router = APIRouter(include_in_schema=False)

# Custom filters
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

templates.env.filters['datetimeformat'] = datetimeformat

def _format_bytes(size_bytes: int) -> str:
    if size_bytes is None or size_bytes < 0:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0

def _safe_folder_name(name: str) -> str:
    if not name:
        return ""
    n = name.strip()
    if not n:
        return ""
    bad = set('/\\\x00')
    cleaned = []
    for ch in n:
        if ch in bad:
            cleaned.append("_")
        else:
            cleaned.append(ch)
    out = "".join(cleaned).strip()
    if len(out) > 60:
        out = out[:60].strip()
    return out

def _parse_optional_int(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if not s:
        return None
    return int(s)

def _build_folder_tree(rows: list[Folder]) -> list[dict]:
    by_parent: dict[Optional[int], list[Folder]] = {}
    for f in rows:
        by_parent.setdefault(f.parent_id, []).append(f)
    for k in list(by_parent.keys()):
        by_parent[k].sort(key=lambda x: (x.name.lower(), x.id))

    out: list[dict] = []

    def walk(parent_id: Optional[int], depth: int):
        for f in by_parent.get(parent_id, []):
            out.append({"id": f.id, "name": f.name, "parent_id": f.parent_id, "depth": depth})
            walk(f.id, depth + 1)

    walk(None, 0)
    return out

# Helper for flash messages
def get_flashed_messages_impl(request: Request):
    msg = request.query_params.get("message")
    if msg:
        return [msg]
    return []

# Helper render function
def render(template_name, request, **kwargs):
    kwargs["get_flashed_messages"] = lambda: get_flashed_messages_impl(request)
    kwargs["current_user"] = request.state.user if hasattr(request.state, "user") else None
    context = {"request": request, **kwargs}
    try:
        return templates.TemplateResponse(template_name, context)
    except TypeError:
        return templates.TemplateResponse(request, template_name, context)

# Middleware to get current user
async def add_user_to_request(request: Request, db: Session):
    token = request.cookies.get("access_token")
    user = None
    if token:
        try:
            payload = serializer.loads(token)
            exp = payload.get("exp")
            if not isinstance(exp, int) or exp < int(time.time()):
                raise SignatureExpired("expired", payload)
            username: str = payload.get("sub")
            if username:
                user = db.query(User).filter(User.username == username).first()
        except (BadSignature, SignatureExpired):
            pass
    request.state.user = user
    return user

@router.get("/")
async def index(request: Request, folder: Optional[int] = None, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    folder_rows = db.query(Folder).filter(Folder.user_id == user.id).all()
    folders = _build_folder_tree(folder_rows)
    folder_by_id = {f.id: f for f in folder_rows}
    current_folder_name = "根目录"
    if folder is not None:
        cf = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder).first()
        if not cf:
            return RedirectResponse(url="/?message=目录不存在", status_code=status.HTTP_302_FOUND)
        current_folder_name = cf.name

    breadcrumb = []
    if folder is not None:
        seen = set()
        cur = folder
        while cur is not None and cur not in seen:
            seen.add(cur)
            node = folder_by_id.get(cur)
            if not node:
                break
            breadcrumb.append({"id": node.id, "name": node.name})
            cur = node.parent_id
        breadcrumb.reverse()

    child_folders = (
        db.query(Folder)
        .filter(Folder.user_id == user.id, Folder.parent_id == folder)
        .order_by(Folder.created_at.desc(), Folder.id.desc())
        .all()
    )
    child_folder_rows = [
        {
            "id": d.id,
            "name": d.name,
            "created_at": d.created_at,
            "created_ts": int(d.created_at.timestamp()) if d.created_at else 0,
        }
        for d in child_folders
    ]

    files = (
        db.query(FileModel)
        .outerjoin(FileMeta, FileMeta.file_id == FileModel.id)
        .outerjoin(TrashItem, TrashItem.file_id == FileModel.id)
        .filter(FileModel.user_id == user.id, TrashItem.id.is_(None))
        .filter(FileMeta.folder_id == folder if folder is not None else FileMeta.folder_id.is_(None))
        .order_by(FileModel.upload_time.desc(), FileModel.id.desc())
        .all()
    )
    file_rows = []
    for f in files:
        encrypted_file_path = ensure_user_storage_file(user.id, f.filename)
        size_bytes = os.path.getsize(encrypted_file_path) if os.path.exists(encrypted_file_path) else 0
        ext = os.path.splitext(f.filename)[1].lower().lstrip(".")
        file_rows.append(
            {
                "filename": f.filename,
                "hash": f.hash,
                "upload_time": f.upload_time,
                "upload_ts": int(f.upload_time.timestamp()) if f.upload_time else 0,
                "size_bytes": size_bytes,
                "size_human": _format_bytes(size_bytes),
                "ext": ext,
            }
        )

    trash_map = {t.file_id: t.stored_filename for t in db.query(TrashItem).filter(TrashItem.user_id == user.id).all()}
    used_bytes = 0
    for fid, fn in db.query(FileModel.id, FileModel.filename).filter(FileModel.user_id == user.id).all():
        if fid in trash_map:
            p = trash_path(user.id, trash_map[fid])
        else:
            p = ensure_user_storage_file(user.id, fn)
        if os.path.exists(p):
            used_bytes += os.path.getsize(p)

    shared_count = db.query(SharedFile).filter(SharedFile.receiver_id == user.id).count()
    quota_bytes = int(Config.STORAGE_QUOTA_GB) * 1024 * 1024 * 1024
    usage_pct = 0
    if quota_bytes > 0:
        usage_pct = int(min(100.0, (used_bytes / quota_bytes) * 100.0))

    return render(
        "index.html",
        request,
        user={"username": user.username, "email": user.email, "is_admin": bool(user.is_admin)},
        files=file_rows,
        child_folders=child_folder_rows,
        folders=folders,
        current_folder_id=folder,
        current_folder_name=current_folder_name,
        breadcrumb=breadcrumb,
        shared_count=shared_count,
        used_bytes=used_bytes,
        used_human=_format_bytes(used_bytes),
        quota_bytes=quota_bytes,
        quota_human=_format_bytes(quota_bytes),
        usage_pct=usage_pct,
    )

@router.get("/login")
async def login(request: Request):
    return render("login.html", request)

@router.post("/login")
async def login_post(
    request: Request, 
    username: str = Form(...), 
    password: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(data={"sub": user.username})
        response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=Config.COOKIE_SECURE,
            samesite=Config.COOKIE_SAMESITE,
        )
        return response
    else:
        return RedirectResponse(url="/login?message=用户名或密码错误", status_code=status.HTTP_302_FOUND)

@router.get("/register")
async def register(request: Request):
    return render("register.html", request)

@router.post("/register")
async def register_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(...),
    db: Session = Depends(get_db)
):
    if len(username) < 3 or len(password) < 6:
        return RedirectResponse(url="/register?message=用户名或密码太短", status_code=status.HTTP_302_FOUND)
        
    try:
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        init_user_keys(new_user.id, db)
        return RedirectResponse(url="/login?message=注册成功！", status_code=status.HTTP_302_FOUND)
    except Exception as e:
        db.rollback()
        return RedirectResponse(url="/register?message=用户名或邮箱已存在！", status_code=status.HTTP_302_FOUND)

@router.get("/logout")
async def logout(response: Response):
    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie("access_token")
    return resp

@router.get("/profile")
async def profile(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return render("profile.html", request, username=user.username, email=user.email)

@router.get("/change_password")
async def change_password_page(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return render("change_password.html", request)

@router.post("/change_password")
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    if not check_password_hash(user.password, old_password):
        return RedirectResponse(url="/change_password?message=旧密码错误", status_code=status.HTTP_302_FOUND)
        
    user.password = generate_password_hash(new_password)
    db.commit()
    return RedirectResponse(url="/profile?message=密码修改成功！", status_code=status.HTTP_302_FOUND)

@router.get("/admin")
async def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        
    users = db.query(User).all()
    return render(
        "admin.html",
        request,
        user={"username": user.username, "email": user.email, "is_admin": bool(user.is_admin)},
        users=users,
    )

@router.post("/admin/delete_user/{user_id}")
async def delete_user_frontend(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user or not user.is_admin:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
        
    if user.id == user_id:
        return RedirectResponse(url="/admin?message=不能删除自己！", status_code=status.HTTP_302_FOUND)

    db.query(SharedFile).filter((SharedFile.sender_id == user_id) | (SharedFile.receiver_id == user_id)).delete()
    db.query(TrashItem).filter(TrashItem.user_id == user_id).delete()
    db.query(Folder).filter(Folder.user_id == user_id).delete()
    db.query(FileMeta).filter(FileMeta.file_id.in_(db.query(FileModel.id).filter(FileModel.user_id == user_id))).delete(synchronize_session=False)
    db.query(FileModel).filter(FileModel.user_id == user_id).delete()
    db.query(UserKey).filter(UserKey.user_id == user_id).delete()
    db.query(User).filter(User.id == user_id).delete()
    db.commit()

    shutil.rmtree(user_storage_dir(user_id), ignore_errors=True)
    
    return RedirectResponse(url="/admin?message=用户已删除", status_code=status.HTTP_302_FOUND)

@router.get("/upload")
async def upload_page(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return render("upload.html", request)

@router.post("/upload")
async def upload_file_frontend(
    request: Request,
    file: UploadFile = File(...),
    folder_id: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    if not allowed_file(file.filename):
        return RedirectResponse(url="/upload?message=File type not allowed", status_code=status.HTTP_302_FOUND)
        
    filename = normalize_filename(file.filename)
    if not filename or not is_safe_filename(filename):
        return RedirectResponse(url="/upload?message=Invalid filename", status_code=status.HTTP_302_FOUND)

    existing = db.query(FileModel).filter(FileModel.user_id == user.id, FileModel.filename == filename).first()
    if existing:
        return RedirectResponse(url="/upload?message=File already exists", status_code=status.HTTP_302_FOUND)

    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()

    os.makedirs(user_storage_dir(user.id), exist_ok=True)
    encrypted_file_path = user_storage_path(user.id, filename)

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
    except Exception:
        if os.path.exists(encrypted_file_path):
            os.remove(encrypted_file_path)
        return RedirectResponse(url="/upload?message=Upload failed", status_code=status.HTTP_302_FOUND)

    file_hash = sha256.hexdigest()
        
    new_file = FileModel(
        user_id=user.id,
        filename=filename,
        hash=file_hash,
        encryption_key=wrap_file_key(key, user_id=user.id, filename=filename),
    )
    db.add(new_file)
    db.commit()

    try:
        folder_id_int = _parse_optional_int(folder_id)
    except Exception:
        folder_id_int = None

    if folder_id_int is not None:
        folder = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder_id_int).first()
        if folder:
            existing_meta = db.query(FileMeta).filter(FileMeta.file_id == new_file.id).first()
            if existing_meta:
                existing_meta.folder_id = folder_id_int
            else:
                db.add(FileMeta(file_id=new_file.id, folder_id=folder_id_int))
            db.commit()
    
    referer = request.headers.get("referer") or ""
    if "/uploaded_files" in referer or "/?folder=" in referer or referer.endswith("/"):
        return RedirectResponse(url=referer, status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/uploaded_files?message=文件上传成功", status_code=status.HTTP_302_FOUND)

@router.get("/uploaded_files")
async def uploaded_files(request: Request, folder: Optional[int] = None, mode: Optional[str] = None, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    folder_rows = db.query(Folder).filter(Folder.user_id == user.id).all()
    folders = _build_folder_tree(folder_rows)
    folder_by_id = {f.id: f for f in folder_rows}
    current_folder_name = "根目录"
    if folder is not None:
        cf = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder).first()
        if not cf:
            return RedirectResponse(url="/uploaded_files?message=目录不存在", status_code=status.HTTP_302_FOUND)
        current_folder_name = cf.name

    breadcrumb = []
    if folder is not None:
        seen = set()
        cur = folder
        while cur is not None and cur not in seen:
            seen.add(cur)
            node = folder_by_id.get(cur)
            if not node:
                break
            breadcrumb.append({"id": node.id, "name": node.name})
            cur = node.parent_id
        breadcrumb.reverse()

    child_folder_rows = []
    if mode != "trash":
        child_folders = (
            db.query(Folder)
            .filter(Folder.user_id == user.id, Folder.parent_id == folder)
            .order_by(Folder.created_at.desc(), Folder.id.desc())
            .all()
        )
        child_folder_rows = [
            {
                "id": d.id,
                "name": d.name,
                "created_at": d.created_at,
                "created_ts": int(d.created_at.timestamp()) if d.created_at else 0,
            }
            for d in child_folders
        ]

    if mode == "trash":
        trashed = (
            db.query(TrashItem, FileModel)
            .join(FileModel, FileModel.id == TrashItem.file_id)
            .filter(TrashItem.user_id == user.id)
            .order_by(TrashItem.trashed_at.desc(), TrashItem.id.desc())
            .all()
        )
        file_rows = []
        for t, f in trashed:
            p = trash_path(user.id, t.stored_filename)
            size_bytes = os.path.getsize(p) if os.path.exists(p) else 0
            ext = os.path.splitext(f.filename)[1].lower().lstrip(".")
            file_rows.append(
                {
                    "trash_id": t.id,
                    "filename": f.filename,
                    "original_filename": t.original_filename,
                    "trashed_at": t.trashed_at,
                    "trashed_ts": int(t.trashed_at.timestamp()) if t.trashed_at else 0,
                    "size_bytes": size_bytes,
                    "size_human": _format_bytes(size_bytes),
                    "ext": ext,
                }
            )
    else:
        files = (
            db.query(FileModel)
            .outerjoin(FileMeta, FileMeta.file_id == FileModel.id)
            .outerjoin(TrashItem, TrashItem.file_id == FileModel.id)
            .filter(FileModel.user_id == user.id, TrashItem.id.is_(None))
            .filter(FileMeta.folder_id == folder if folder is not None else FileMeta.folder_id.is_(None))
            .order_by(FileModel.upload_time.desc(), FileModel.id.desc())
            .all()
        )
        file_rows = []
        for f in files:
            encrypted_file_path = ensure_user_storage_file(user.id, f.filename)
            size_bytes = os.path.getsize(encrypted_file_path) if os.path.exists(encrypted_file_path) else 0
            ext = os.path.splitext(f.filename)[1].lower().lstrip(".")
            file_rows.append(
                {
                    "filename": f.filename,
                    "hash": f.hash,
                    "upload_time": f.upload_time,
                    "upload_ts": int(f.upload_time.timestamp()) if f.upload_time else 0,
                    "size_bytes": size_bytes,
                    "size_human": _format_bytes(size_bytes),
                    "ext": ext,
                }
            )

    trash_map = {t.file_id: t.stored_filename for t in db.query(TrashItem).filter(TrashItem.user_id == user.id).all()}
    used_bytes = 0
    for fid, fn in db.query(FileModel.id, FileModel.filename).filter(FileModel.user_id == user.id).all():
        if fid in trash_map:
            p = trash_path(user.id, trash_map[fid])
        else:
            p = ensure_user_storage_file(user.id, fn)
        if os.path.exists(p):
            used_bytes += os.path.getsize(p)

    quota_bytes = int(Config.STORAGE_QUOTA_GB) * 1024 * 1024 * 1024
    usage_pct = 0
    if quota_bytes > 0:
        usage_pct = int(min(100.0, (used_bytes / quota_bytes) * 100.0))

    return render(
        "uploaded_files.html",
        request,
        user={"username": user.username, "email": user.email, "is_admin": bool(user.is_admin)},
        files=file_rows,
        child_folders=child_folder_rows,
        folders=folders,
        current_folder_id=folder,
        current_folder_name=current_folder_name,
        breadcrumb=breadcrumb,
        mode=mode or "files",
        used_bytes=used_bytes,
        used_human=_format_bytes(used_bytes),
        quota_bytes=quota_bytes,
        quota_human=_format_bytes(quota_bytes),
        usage_pct=usage_pct,
    )

@router.get("/trash")
async def trash_page(request: Request):
    return RedirectResponse(url="/uploaded_files?mode=trash", status_code=status.HTTP_302_FOUND)

@router.post("/trash/restore/{trash_id}")
async def trash_restore(trash_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    item = db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.id == trash_id).first()
    if not item:
        return RedirectResponse(url="/uploaded_files?mode=trash&message=回收站条目不存在", status_code=status.HTTP_302_FOUND)

    file_record = db.query(FileModel).filter(FileModel.user_id == user.id, FileModel.id == item.file_id).first()
    if not file_record:
        db.delete(item)
        db.commit()
        return RedirectResponse(url="/uploaded_files?mode=trash&message=文件记录不存在", status_code=status.HTTP_302_FOUND)

    src = trash_path(user.id, item.stored_filename)
    if not os.path.exists(src):
        db.delete(item)
        db.commit()
        return RedirectResponse(url="/uploaded_files?mode=trash&message=物理文件缺失", status_code=status.HTTP_302_FOUND)

    used_names = {
        fn
        for (fn,) in (
            db.query(FileModel.filename)
            .outerjoin(TrashItem, TrashItem.file_id == FileModel.id)
            .filter(FileModel.user_id == user.id, TrashItem.id.is_(None))
            .all()
        )
    }
    desired = item.original_filename
    restored_name = desired if desired not in used_names else uniquify_filename(desired, used_names)

    os.makedirs(user_storage_dir(user.id), exist_ok=True)
    dst = user_storage_path(user.id, restored_name)
    os.replace(src, dst)

    if restored_name != desired:
        try:
            file_key = unwrap_file_key(file_record.encryption_key, user_id=user.id, filename=desired)
            file_record.encryption_key = wrap_file_key(file_key, user_id=user.id, filename=restored_name)
            file_record.filename = restored_name
        except Exception:
            os.replace(dst, src)
            return RedirectResponse(url="/uploaded_files?mode=trash&message=密钥更新失败", status_code=status.HTTP_302_FOUND)

    db.delete(item)
    db.commit()
    return RedirectResponse(url="/uploaded_files?message=已从回收站还原", status_code=status.HTTP_302_FOUND)

@router.post("/trash/purge/{trash_id}")
async def trash_purge(trash_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    item = db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.id == trash_id).first()
    if not item:
        return RedirectResponse(url="/uploaded_files?mode=trash&message=回收站条目不存在", status_code=status.HTTP_302_FOUND)

    db.query(SharedFile).filter(SharedFile.file_id == item.file_id).delete()
    db.query(FileMeta).filter(FileMeta.file_id == item.file_id).delete()

    file_record = db.query(FileModel).filter(FileModel.user_id == user.id, FileModel.id == item.file_id).first()
    if file_record:
        db.delete(file_record)

    p = trash_path(user.id, item.stored_filename)
    if os.path.exists(p):
        os.remove(p)

    db.delete(item)
    db.commit()
    return RedirectResponse(url="/uploaded_files?mode=trash&message=已彻底删除", status_code=status.HTTP_302_FOUND)

@router.post("/folders/create")
async def folder_create(
    request: Request,
    name: str = Form(...),
    parent_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    try:
        parent_id_int = _parse_optional_int(parent_id)
    except Exception:
        return RedirectResponse(url=request.headers.get("referer") or "/?message=上级目录参数错误", status_code=status.HTTP_302_FOUND)

    folder_name = _safe_folder_name(name)
    if not folder_name:
        return RedirectResponse(url="/?message=目录名不能为空", status_code=status.HTTP_302_FOUND)

    if parent_id_int is not None:
        parent = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == parent_id_int).first()
        if not parent:
            return RedirectResponse(url="/?message=上级目录不存在", status_code=status.HTTP_302_FOUND)

    exists = (
        db.query(Folder)
        .filter(Folder.user_id == user.id, Folder.parent_id == parent_id_int, Folder.name == folder_name)
        .first()
    )
    if exists:
        return RedirectResponse(url="/?message=目录已存在", status_code=status.HTTP_302_FOUND)

    db.add(Folder(user_id=user.id, name=folder_name, parent_id=parent_id_int))
    db.commit()
    return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

@router.post("/folders/rename/{folder_id}")
async def folder_rename(
    folder_id: int,
    request: Request,
    name: str = Form(...),
    db: Session = Depends(get_db),
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    folder = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder_id).first()
    if not folder:
        return RedirectResponse(url="/?message=目录不存在", status_code=status.HTTP_302_FOUND)

    folder_name = _safe_folder_name(name)
    if not folder_name:
        return RedirectResponse(url="/?message=目录名不能为空", status_code=status.HTTP_302_FOUND)

    exists = (
        db.query(Folder)
        .filter(Folder.user_id == user.id, Folder.parent_id == folder.parent_id, Folder.name == folder_name, Folder.id != folder_id)
        .first()
    )
    if exists:
        return RedirectResponse(url="/?message=同级目录重名", status_code=status.HTTP_302_FOUND)

    folder.name = folder_name
    db.commit()
    return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

@router.post("/folders/delete/{folder_id}")
async def folder_delete(folder_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    folder = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder_id).first()
    if not folder:
        return RedirectResponse(url="/?message=目录不存在", status_code=status.HTTP_302_FOUND)

    db.query(Folder).filter(Folder.user_id == user.id, Folder.parent_id == folder_id).update({"parent_id": folder.parent_id})
    db.query(FileMeta).filter(FileMeta.folder_id == folder_id).update({"folder_id": folder.parent_id})
    db.delete(folder)
    db.commit()
    return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

@router.post("/folders/move/{folder_id}")
async def folder_move(
    folder_id: int,
    request: Request,
    parent_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    folder = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder_id).first()
    if not folder:
        return RedirectResponse(url="/?message=目录不存在", status_code=status.HTTP_302_FOUND)

    try:
        parent_id_int = _parse_optional_int(parent_id)
    except Exception:
        return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

    if parent_id_int is not None:
        parent = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == parent_id_int).first()
        if not parent:
            return RedirectResponse(url="/?message=上级目录不存在", status_code=status.HTTP_302_FOUND)

    rows = db.query(Folder).filter(Folder.user_id == user.id).all()
    children_map: dict[Optional[int], list[int]] = {}
    for r in rows:
        children_map.setdefault(r.parent_id, []).append(r.id)

    disallowed = {folder_id}
    stack = [folder_id]
    while stack:
        cur = stack.pop()
        for cid in children_map.get(cur, []):
            if cid not in disallowed:
                disallowed.add(cid)
                stack.append(cid)

    if parent_id_int in disallowed:
        return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

    folder.parent_id = parent_id_int
    db.commit()
    return RedirectResponse(url=request.headers.get("referer") or "/", status_code=status.HTTP_302_FOUND)

@router.post("/move_file/{filename}")
async def move_file(filename: str, request: Request, folder_id: Optional[str] = Form(None), db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not is_safe_filename(filename):
        return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=文件名不合法", status_code=status.HTTP_302_FOUND)

    file_record = db.query(FileModel).filter(FileModel.user_id == user.id, FileModel.filename == filename).first()
    if not file_record:
        return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=文件不存在", status_code=status.HTTP_302_FOUND)

    if db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.file_id == file_record.id).first():
        return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=文件在回收站中", status_code=status.HTTP_302_FOUND)

    try:
        folder_id_int = _parse_optional_int(folder_id)
    except Exception:
        return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=目录参数错误", status_code=status.HTTP_302_FOUND)

    if folder_id_int is not None:
        folder = db.query(Folder).filter(Folder.user_id == user.id, Folder.id == folder_id_int).first()
        if not folder:
            return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=目录不存在", status_code=status.HTTP_302_FOUND)

    meta = db.query(FileMeta).filter(FileMeta.file_id == file_record.id).first()
    if meta:
        meta.folder_id = folder_id_int
    else:
        db.add(FileMeta(file_id=file_record.id, folder_id=folder_id_int))
    db.commit()
    return RedirectResponse(url=request.headers.get("referer") or "/uploaded_files?message=已移动", status_code=status.HTTP_302_FOUND)

@router.get("/preview/{filename}")
async def preview_file(filename: str, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not is_safe_filename(filename):
        return RedirectResponse(url="/?message=文件名不合法", status_code=status.HTTP_302_FOUND)

    file_record = db.query(FileModel).filter(FileModel.user_id == user.id, FileModel.filename == filename).first()
    if not file_record:
        return RedirectResponse(url="/?message=文件不存在", status_code=status.HTTP_302_FOUND)

    if db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.file_id == file_record.id).first():
        return RedirectResponse(url="/?message=文件在回收站中", status_code=status.HTTP_302_FOUND)

    encrypted_file_path = ensure_user_storage_file(user.id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/?message=物理文件缺失", status_code=status.HTTP_302_FOUND)

    try:
        key = unwrap_file_key(file_record.encryption_key, user_id=user.id, filename=filename)
    except Exception:
        return RedirectResponse(url="/?message=密钥错误", status_code=status.HTTP_302_FOUND)

    ext = os.path.splitext(filename)[1].lower()
    media_type = "application/octet-stream"
    if ext in [".png"]:
        media_type = "image/png"
    elif ext in [".jpg", ".jpeg"]:
        media_type = "image/jpeg"
    elif ext in [".gif"]:
        media_type = "image/gif"
    elif ext in [".webp"]:
        media_type = "image/webp"
    elif ext in [".pdf"]:
        media_type = "application/pdf"
    elif ext in [".txt", ".log", ".md", ".json", ".csv", ".py", ".js", ".css", ".html"]:
        media_type = "text/plain; charset=utf-8"

    def iter_decrypted():
        with open(encrypted_file_path, "rb") as f:
            iv = f.read(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
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

    encoded_filename = quote(filename, safe="", encoding="utf-8")
    content_disposition = f"inline; filename*=UTF-8''{encoded_filename}"
    return StreamingResponse(iter_decrypted(), media_type=media_type, headers={"Content-Disposition": content_disposition})

@router.get("/preview_shared_by_id/{shared_file_id}")
async def preview_shared_by_id(shared_file_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    share_info = (
        db.query(SharedFile.encrypted_key, FileModel.hash, FileModel.user_id, FileModel.filename)
        .join(FileModel, SharedFile.file_id == FileModel.id)
        .filter(SharedFile.receiver_id == user.id, SharedFile.id == shared_file_id)
        .first()
    )
    if not share_info:
        return RedirectResponse(url="/shared_files?message=文件不存在或没有访问权限", status_code=status.HTTP_302_FOUND)

    encrypted_key, original_file_hash, sender_id, filename = share_info

    receiver_key = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    sender_key = db.query(UserKey).filter(UserKey.user_id == sender_id).first()
    receiver_private_key = serialization.load_pem_private_key(receiver_key.private_key, password=None)
    sender_public_key = serialization.load_pem_public_key(sender_key.public_key)

    shared_key = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)

    try:
        decrypted_file_key = decrypt_shared_file_key(
            encrypted_key,
            derived_key,
            sender_id=sender_id,
            receiver_id=user.id,
            filename=filename,
        )
    except Exception:
        return RedirectResponse(url="/shared_files?message=密钥错误", status_code=status.HTTP_302_FOUND)

    encrypted_file_path = ensure_user_storage_file(sender_id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/shared_files?message=文件不存在于服务器", status_code=status.HTTP_302_FOUND)

    sha256 = hashlib.sha256()
    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    if sha256.hexdigest() != original_file_hash:
        return RedirectResponse(url="/shared_files?message=完整性校验失败", status_code=status.HTTP_302_FOUND)

    ext = os.path.splitext(filename)[1].lower()
    media_type = "application/octet-stream"
    if ext in [".png"]:
        media_type = "image/png"
    elif ext in [".jpg", ".jpeg"]:
        media_type = "image/jpeg"
    elif ext in [".gif"]:
        media_type = "image/gif"
    elif ext in [".webp"]:
        media_type = "image/webp"
    elif ext in [".pdf"]:
        media_type = "application/pdf"
    elif ext in [".txt", ".log", ".md", ".json", ".csv", ".py", ".js", ".css", ".html"]:
        media_type = "text/plain; charset=utf-8"

    def iter_decrypted():
        with open(encrypted_file_path, "rb") as f:
            iv = f.read(16)
            cipher = Cipher(algorithms.AES(decrypted_file_key), modes.CBC(iv), backend=default_backend())
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

    encoded_filename = quote(filename, safe="", encoding="utf-8")
    content_disposition = f"inline; filename*=UTF-8''{encoded_filename}"
    return StreamingResponse(iter_decrypted(), media_type=media_type, headers={"Content-Disposition": content_disposition})

@router.post("/delete_file/{filename}")
async def delete_file(filename: str, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if not is_safe_filename(filename):
        return RedirectResponse(url="/uploaded_files?message=文件名不合法", status_code=status.HTTP_302_FOUND)
        
    file_record = db.query(FileModel).filter(
        FileModel.filename == filename, 
        FileModel.user_id == user.id
    ).first()
    
    if not file_record:
        return RedirectResponse(url="/uploaded_files?message=文件不存在", status_code=status.HTTP_302_FOUND)

    existing_trash = db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.file_id == file_record.id).first()
    if existing_trash:
        return RedirectResponse(url="/uploaded_files?message=已在回收站", status_code=status.HTTP_302_FOUND)

    db.query(SharedFile).filter(SharedFile.file_id == file_record.id).delete()

    src = ensure_user_storage_file(user.id, filename)
    if not os.path.exists(src):
        return RedirectResponse(url="/uploaded_files?message=物理文件缺失", status_code=status.HTTP_302_FOUND)

    os.makedirs(trash_dir(user.id), exist_ok=True)
    base, ext = os.path.splitext(filename)
    stored = f"{int(time.time())}_{file_record.id}{ext}"
    dst = trash_path(user.id, stored)
    os.replace(src, dst)

    db.add(
        TrashItem(
            user_id=user.id,
            file_id=file_record.id,
            stored_filename=stored,
            original_filename=filename,
        )
    )
    db.commit()
    return RedirectResponse(url="/uploaded_files?message=已移入回收站", status_code=status.HTTP_302_FOUND)

@router.get("/share_file/{filename}")
async def share_file(filename: str, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if not is_safe_filename(filename):
        return RedirectResponse(url="/uploaded_files?message=文件名不合法", status_code=status.HTTP_302_FOUND)
    return render("share_file.html", request, filename=filename)

@router.post("/share_file/{filename}")
async def share_file_post(
    filename: str, 
    request: Request, 
    username: str = Form(...), 
    db: Session = Depends(get_db)
):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if not is_safe_filename(filename):
        return RedirectResponse(url="/uploaded_files?message=文件名不合法", status_code=status.HTTP_302_FOUND)

    receiver = db.query(User).filter(User.username == username).first()
    if not receiver:
        return RedirectResponse(url=f"/share_file/{filename}?message=用户不存在", status_code=status.HTTP_302_FOUND)
    
    receiver_key = db.query(UserKey).filter(UserKey.user_id == receiver.id).first()
    sender_key = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    
    if not receiver_key or not sender_key:
         return RedirectResponse(url=f"/share_file/{filename}?message=密钥错误", status_code=status.HTTP_302_FOUND)

    receiver_public_key = serialization.load_pem_public_key(receiver_key.public_key)
    sender_private_key = serialization.load_pem_private_key(sender_key.private_key, password=None)
    
    shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)
    
    file_record = db.query(FileModel).filter(
        FileModel.filename == filename, 
        FileModel.user_id == user.id
    ).first()
    
    if not file_record:
        return RedirectResponse(url="/uploaded_files?message=文件不存在", status_code=status.HTTP_302_FOUND)

    if db.query(TrashItem).filter(TrashItem.user_id == user.id, TrashItem.file_id == file_record.id).first():
        return RedirectResponse(url="/uploaded_files?message=文件在回收站中，无法分享", status_code=status.HTTP_302_FOUND)

    try:
        file_key = unwrap_file_key(file_record.encryption_key, user_id=user.id, filename=file_record.filename)
    except Exception:
        return RedirectResponse(url=f"/share_file/{filename}?message=密钥错误", status_code=status.HTTP_302_FOUND)

    encrypted_file_key = encrypt_shared_file_key(
        file_key,
        derived_key,
        sender_id=user.id,
        receiver_id=receiver.id,
        filename=file_record.filename,
    )
    
    new_share = SharedFile(
        file_id=file_record.id,
        sender_id=user.id,
        receiver_id=receiver.id,
        encrypted_key=encrypted_file_key
    )
    db.add(new_share)
    db.commit()
    
    return RedirectResponse(url="/uploaded_files?message=文件分享成功", status_code=status.HTTP_302_FOUND)

@router.get("/shared_files")
async def shared_files(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    results = (
        db.query(
            FileModel.filename,
            User.username,
            SharedFile.shared_at,
            FileModel.hash,
            SharedFile.id,
        )
        .join(FileModel, SharedFile.file_id == FileModel.id)
        .join(User, SharedFile.sender_id == User.id)
        .filter(SharedFile.receiver_id == user.id)
        .order_by(SharedFile.shared_at.desc(), SharedFile.id.desc())
        .all()
    )

    own_names = {fn for (fn,) in db.query(FileModel.filename).filter(FileModel.user_id == user.id).all()}
    used_names = set(own_names)
    display_map: dict[int, str] = {}
    for r in results:
        desired = r.filename
        display = desired if desired not in used_names else uniquify_filename(desired, used_names)
        used_names.add(display)
        display_map[r.id] = display
     
    # Convert to list of dicts or objects for template
    files = []
    for r in results:
        # We create a dummy object or dict
        ext = os.path.splitext(r.filename)[1].lower().lstrip(".")
        display_name = display_map.get(r.id, r.filename)
        files.append({
            "filename": r.filename,
            "display_name": display_name,
            "name_changed": display_name != r.filename,
            "username": r.username,
            "shared_at": r.shared_at,
            "hash": r.hash,
            "id": r.id,
            "ext": ext,
        })

    # Sidebar storage stats (personal space usage)
    own_files = db.query(FileModel.filename).filter(FileModel.user_id == user.id).all()
    used_bytes = 0
    for (fn,) in own_files:
        encrypted_file_path = ensure_user_storage_file(user.id, fn)
        if os.path.exists(encrypted_file_path):
            used_bytes += os.path.getsize(encrypted_file_path)

    quota_bytes = int(Config.STORAGE_QUOTA_GB) * 1024 * 1024 * 1024
    usage_pct = 0
    if quota_bytes > 0:
        usage_pct = int(min(100.0, (used_bytes / quota_bytes) * 100.0))

    return render(
        "shared_files.html",
        request,
        user={"username": user.username, "email": user.email, "is_admin": bool(user.is_admin)},
        files=files,
        used_bytes=used_bytes,
        used_human=_format_bytes(used_bytes),
        quota_bytes=quota_bytes,
        quota_human=_format_bytes(quota_bytes),
        usage_pct=usage_pct,
    )

@router.get("/download_shared/{filename}")
async def download_shared(filename: str, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if not is_safe_filename(filename):
        return RedirectResponse(url="/shared_files?message=文件名不合法", status_code=status.HTTP_302_FOUND)
        
    # Query join
    # SELECT sf.encrypted_key, f.hash, f.user_id 
    # FROM shared_files sf JOIN files f ON sf.file_id = f.id ...
    share_info = db.query(SharedFile.encrypted_key, FileModel.hash, FileModel.user_id)\
        .join(FileModel, SharedFile.file_id == FileModel.id)\
        .filter(SharedFile.receiver_id == user.id, FileModel.filename == filename).first()
        
    if not share_info:
        return RedirectResponse(url="/shared_files?message=文件不存在或没有访问权限", status_code=status.HTTP_302_FOUND)
        
    encrypted_key, original_file_hash, sender_id = share_info
    
    receiver_key = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    sender_key = db.query(UserKey).filter(UserKey.user_id == sender_id).first()
    
    receiver_private_key = serialization.load_pem_private_key(receiver_key.private_key, password=None)
    sender_public_key = serialization.load_pem_public_key(sender_key.public_key)
    
    shared_key = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)

    try:
        file_encryption_key = decrypt_shared_file_key(
            encrypted_key,
            derived_key,
            sender_id=sender_id,
            receiver_id=user.id,
            filename=filename,
        )
    except Exception:
        return RedirectResponse(url="/shared_files?message=文件密钥解密失败", status_code=status.HTTP_302_FOUND)
    
    encrypted_file_path = ensure_user_storage_file(sender_id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/shared_files?message=文件不存在", status_code=status.HTTP_302_FOUND)
        
    sha256 = hashlib.sha256()
    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    current_encrypted_hash = sha256.hexdigest()
    if current_encrypted_hash != original_file_hash:
        return RedirectResponse(url="/shared_files?message=❌ 文件完整性验证失败！", status_code=status.HTTP_302_FOUND)

    def iter_decrypted():
        with open(encrypted_file_path, "rb") as f:
            iv = f.read(16)
            cipher = Cipher(algorithms.AES(file_encryption_key), modes.CBC(iv), backend=default_backend())
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
        
    encoded_filename = quote(filename, safe='', encoding='utf-8')
    content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"

    return StreamingResponse(
        iter_decrypted(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": content_disposition},
    )

@router.post("/delete_shared/{shared_file_id}")
async def delete_shared(shared_file_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    share = db.query(SharedFile).filter(SharedFile.id == shared_file_id, SharedFile.receiver_id == user.id).first()
    if not share:
        return RedirectResponse(url="/shared_files?message=无权限删除该共享记录", status_code=status.HTTP_302_FOUND)
        
    db.delete(share)
    db.commit()
    return RedirectResponse(url="/shared_files?message=已删除共享文件记录", status_code=status.HTTP_302_FOUND)

@router.get("/verify_shared_file/{filename}")
async def verify_shared_file(filename: str, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    share_info = (
        db.query(FileModel.hash, User.username, SharedFile.sender_id)
        .join(SharedFile, SharedFile.file_id == FileModel.id)
        .join(User, SharedFile.sender_id == User.id)
        .filter(SharedFile.receiver_id == user.id, FileModel.filename == filename)
        .first()
    )
        
    if not share_info:
        return RedirectResponse(url="/shared_files?message=文件不存在或没有访问权限", status_code=status.HTTP_302_FOUND)
        
    original_file_hash, sender_name, sender_id = share_info
    
    encrypted_file_path = ensure_user_storage_file(sender_id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/shared_files?message=❌ 文件不存在于服务器", status_code=status.HTTP_302_FOUND)
        
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    current_hash = hashlib.sha256(encrypted_data).hexdigest()
    
    if current_hash == original_file_hash:
        msg = f"✅ 共享文件完整性验证成功！文件来源：{sender_name}"
    else:
        msg = "❌ 共享文件完整性验证失败！文件可能已被篡改"
        
    return RedirectResponse(url=f"/shared_files?message={msg}", status_code=status.HTTP_302_FOUND)

@router.get("/download_shared_by_id/{shared_file_id}")
async def download_shared_by_id(shared_file_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    results = (
        db.query(
            FileModel.filename,
            SharedFile.id,
            SharedFile.shared_at,
        )
        .join(FileModel, SharedFile.file_id == FileModel.id)
        .filter(SharedFile.receiver_id == user.id)
        .order_by(SharedFile.shared_at.desc(), SharedFile.id.desc())
        .all()
    )
    own_names = {fn for (fn,) in db.query(FileModel.filename).filter(FileModel.user_id == user.id).all()}
    used_names = set(own_names)
    display_map: dict[int, str] = {}
    for r in results:
        desired = r.filename
        display = desired if desired not in used_names else uniquify_filename(desired, used_names)
        used_names.add(display)
        display_map[r.id] = display

    share_info = (
        db.query(SharedFile.encrypted_key, FileModel.hash, FileModel.user_id, FileModel.filename)
        .join(FileModel, SharedFile.file_id == FileModel.id)
        .filter(SharedFile.receiver_id == user.id, SharedFile.id == shared_file_id)
        .first()
    )
    if not share_info:
        return RedirectResponse(url="/shared_files?message=文件不存在或没有访问权限", status_code=status.HTTP_302_FOUND)

    encrypted_key, original_file_hash, sender_id, filename = share_info

    receiver_key = db.query(UserKey).filter(UserKey.user_id == user.id).first()
    sender_key = db.query(UserKey).filter(UserKey.user_id == sender_id).first()
    receiver_private_key = serialization.load_pem_private_key(receiver_key.private_key, password=None)
    sender_public_key = serialization.load_pem_public_key(sender_key.public_key)

    shared_key = receiver_private_key.exchange(ec.ECDH(), sender_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)

    try:
        decrypted_file_key = decrypt_shared_file_key(
            encrypted_key,
            derived_key,
            sender_id=sender_id,
            receiver_id=user.id,
            filename=filename,
        )
    except Exception:
        return RedirectResponse(url="/shared_files?message=密钥错误", status_code=status.HTTP_302_FOUND)

    encrypted_file_path = ensure_user_storage_file(sender_id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/shared_files?message=文件不存在于服务器", status_code=status.HTTP_302_FOUND)

    sha256 = hashlib.sha256()
    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    if sha256.hexdigest() != original_file_hash:
        return RedirectResponse(url="/shared_files?message=完整性校验失败", status_code=status.HTTP_302_FOUND)

    def iter_decrypted():
        with open(encrypted_file_path, "rb") as f:
            iv = f.read(16)
            cipher = Cipher(algorithms.AES(decrypted_file_key), modes.CBC(iv), backend=default_backend())
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

    download_name = display_map.get(shared_file_id, filename)
    encoded_filename = quote(download_name, safe="", encoding="utf-8")
    content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"
    return StreamingResponse(
        iter_decrypted(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": content_disposition},
    )

@router.get("/verify_shared_by_id/{shared_file_id}")
async def verify_shared_by_id(shared_file_id: int, request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    share_info = (
        db.query(FileModel.hash, User.username, SharedFile.sender_id, FileModel.filename)
        .join(SharedFile, SharedFile.file_id == FileModel.id)
        .join(User, SharedFile.sender_id == User.id)
        .filter(SharedFile.receiver_id == user.id, SharedFile.id == shared_file_id)
        .first()
    )

    if not share_info:
        return RedirectResponse(url="/shared_files?message=文件不存在或没有访问权限", status_code=status.HTTP_302_FOUND)

    original_file_hash, sender_name, sender_id, filename = share_info
    encrypted_file_path = ensure_user_storage_file(sender_id, filename)
    if not os.path.exists(encrypted_file_path):
        return RedirectResponse(url="/shared_files?message=❌ 文件不存在于服务器", status_code=status.HTTP_302_FOUND)

    sha256 = hashlib.sha256()
    with open(encrypted_file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
    current_hash = sha256.hexdigest()

    if current_hash == original_file_hash:
        msg = f"✅ 共享文件完整性验证成功！文件来源：{sender_name}"
    else:
        msg = "❌ 共享文件完整性验证失败！文件可能已被篡改"

    return RedirectResponse(url=f"/shared_files?message={msg}", status_code=status.HTTP_302_FOUND)

@router.get("/batch_verify")
async def batch_verify(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    files = db.query(FileModel.filename, FileModel.hash).filter(FileModel.user_id == user.id).all()
    verified_count = 0
    failed_count = 0
    failed_files = []
    
    for filename, stored_hash in files:
        encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            current_hash = hashlib.sha256(encrypted_data).hexdigest()
            if current_hash == stored_hash:
                verified_count += 1
            else:
                failed_count += 1
                failed_files.append(filename)
        else:
            failed_count += 1
            failed_files.append(f"{filename} (missing)")
            
    if failed_count == 0:
        msg = f"✅ 批量验证完成！{verified_count} 个文件完整性良好"
    else:
        msg = f"⚠️ 验证完成：{verified_count} 个正常，{failed_count} 个异常"
        
    return RedirectResponse(url=f"/uploaded_files?message={msg}", status_code=status.HTTP_302_FOUND)

@router.get("/batch_verify_shared")
async def batch_verify_shared(request: Request, db: Session = Depends(get_db)):
    user = await add_user_to_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
        
    shared_files = db.query(FileModel.filename, FileModel.hash)\
        .join(SharedFile, SharedFile.file_id == FileModel.id)\
        .filter(SharedFile.receiver_id == user.id).all()
        
    if not shared_files:
        return RedirectResponse(url="/shared_files?message=没有共享文件", status_code=status.HTTP_302_FOUND)
        
    verified_count = 0
    failed_count = 0
    
    for filename, stored_hash in shared_files:
        encrypted_file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        if os.path.exists(encrypted_file_path):
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            current_hash = hashlib.sha256(encrypted_data).hexdigest()
            if current_hash == stored_hash:
                verified_count += 1
            else:
                failed_count += 1
        else:
            failed_count += 1
            
    if failed_count == 0:
        msg = f"✅ 批量验证完成！{verified_count} 个文件完整性良好"
    else:
        msg = f"⚠️ 验证完成：{verified_count} 个正常，{failed_count} 个异常"
        
    return RedirectResponse(url=f"/shared_files?message={msg}", status_code=status.HTTP_302_FOUND)
