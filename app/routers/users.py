import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel

from app.database import get_db
from app.models import User, File as FileModel, SharedFile, UserKey, TrashItem, Folder, FileMeta
from app.dependencies import get_current_user, get_current_admin_user
from app.config import Config
from app.utils import user_storage_path, legacy_storage_path, user_storage_dir

router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

@router.get("/profile")
def profile(request: Request, current_user: User = Depends(get_current_user)):
    accept = request.headers.get("accept", "")
    if "text/html" in accept.lower():
        return RedirectResponse(url="/profile", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return {
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin
    }

@router.post("/change_password")
def change_password(
    data: ChangePasswordRequest, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    if not check_password_hash(current_user.password, data.old_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
    
    hashed_password = generate_password_hash(data.new_password)
    current_user.password = hashed_password
    db.commit()
    
    return {"message": "Password updated successfully"}

@router.get("/admin/users")
def get_all_users(db: Session = Depends(get_db), admin: User = Depends(get_current_admin_user)):
    users = db.query(User).all()
    users_list = []
    for u in users:
        users_list.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'is_admin': u.is_admin
        })
    return {"users": users_list}

@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: int, 
    db: Session = Depends(get_db), 
    admin: User = Depends(get_current_admin_user)
):
    if admin.id == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Delete shared files where user is sender or receiver
    db.query(SharedFile).filter((SharedFile.sender_id == user_id) | (SharedFile.receiver_id == user_id)).delete()
    
    db.query(TrashItem).filter(TrashItem.user_id == user_id).delete()
    db.query(Folder).filter(Folder.user_id == user_id).delete()

    # Get user files to delete physical files
    files = db.query(FileModel).filter(FileModel.user_id == user_id).all()
    for f in files:
        old_path = legacy_storage_path(f.filename)
        if os.path.exists(old_path):
            os.remove(old_path)
            
    shutil.rmtree(user_storage_dir(user_id), ignore_errors=True)

    db.query(FileMeta).filter(FileMeta.file_id.in_(db.query(FileModel.id).filter(FileModel.user_id == user_id))).delete(synchronize_session=False)

    # Delete files records
    db.query(FileModel).filter(FileModel.user_id == user_id).delete()
    
    # Delete keys
    db.query(UserKey).filter(UserKey.user_id == user_id).delete()
    
    # Delete user
    db.delete(user_to_delete)
    db.commit()
    
    return {"message": "User deleted successfully"}
