from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel

from app.database import get_db
from app.models import User, File as FileModel, SharedFile, UserKey
from app.dependencies import get_current_user
from app.utils import encrypt_shared_file_key, unwrap_file_key, is_safe_filename

router = APIRouter(
    prefix="/api/share",
    tags=["share"],
    responses={404: {"description": "Not found"}},
)

class ShareRequest(BaseModel):
    username: str

@router.post("/share/{filename}")
def api_share_file(
    filename: str, 
    share_data: ShareRequest, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    if not is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    receiver_username = share_data.username
    
    receiver = db.query(User, UserKey.public_key).join(UserKey).filter(User.username == receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="User not found")
    
    receiver_user, receiver_pub_pem = receiver
    receiver_public_key = serialization.load_pem_public_key(receiver_pub_pem)
    
    sender_key_record = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not sender_key_record:
         raise HTTPException(status_code=500, detail="Sender keys not found")
         
    sender_private_key = serialization.load_pem_private_key(sender_key_record.private_key, password=None)
    
    shared_key = sender_private_key.exchange(ec.ECDH(), receiver_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file sharing',
    ).derive(shared_key)
    
    file_record = db.query(FileModel).filter(
        FileModel.filename == filename, 
        FileModel.user_id == current_user.id
    ).first()
    
    if not file_record:
        raise HTTPException(status_code=404, detail="File not found")

    try:
        file_key = unwrap_file_key(file_record.encryption_key, user_id=current_user.id, filename=file_record.filename)
    except Exception:
        raise HTTPException(status_code=500, detail="Key unwrap failed")

    encrypted_file_key = encrypt_shared_file_key(
        file_key,
        derived_key,
        sender_id=current_user.id,
        receiver_id=receiver_user.id,
        filename=file_record.filename,
    )
    
    try:
        new_share = SharedFile(
            file_id=file_record.id,
            sender_id=current_user.id,
            receiver_id=receiver_user.id,
            encrypted_key=encrypted_file_key
        )
        db.add(new_share)
        db.commit()
        return {"message": "File shared successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/share/{filename}")
def api_share_file_help(filename: str, request: Request):
    accept = request.headers.get("accept", "")
    if "text/html" in accept.lower():
        return RedirectResponse(url=f"/share_file/{filename}", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    raise HTTPException(status_code=405, detail="Method Not Allowed")

@router.get("/")
def list_shared_files(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # SELECT f.filename, u.username, sf.shared_at, f.hash, sf.id 
    # FROM shared_files sf
    # JOIN files f ON sf.file_id = f.id 
    # JOIN users u ON sf.sender_id = u.id 
    # WHERE sf.receiver_id = :rid
    
    results = db.query(
        FileModel.filename, 
        User.username, 
        SharedFile.shared_at, 
        FileModel.hash, 
        SharedFile.id
    ).join(FileModel, SharedFile.file_id == FileModel.id)\
     .join(User, SharedFile.sender_id == User.id)\
     .filter(SharedFile.receiver_id == current_user.id).all()
     
    files_list = []
    for f in results:
        files_list.append({
            'filename': f.filename,
            'sender': f.username,
            'shared_at': f.shared_at,
            'hash': f.hash,
            'id': f.id
        })
    return {"files": files_list}
