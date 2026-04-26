import time
from datetime import timedelta
from fastapi import Depends, HTTPException, status, Request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User
from app.config import Config

SECRET_KEY = Config.SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = Config.ACCESS_TOKEN_EXPIRE_MINUTES
serializer = URLSafeTimedSerializer(SECRET_KEY)

def create_access_token(data: dict, expires_delta: timedelta = None):
    expire_seconds = int((expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)).total_seconds())
    payload = dict(data)
    payload["exp"] = int(time.time()) + expire_seconds
    return serializer.dumps(payload)

def get_current_user(request: Request, db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    token = request.cookies.get("access_token")
    if not token:
        # Check if it's a bearer token in header (for API clients)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            
    if not token:
         raise credentials_exception

    try:
        # If token starts with "Bearer ", strip it (in case cookie had it)
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
            
        payload = serializer.loads(token)
        exp = payload.get("exp")
        if not isinstance(exp, int) or exp < int(time.time()):
            raise SignatureExpired("expired", payload)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except (BadSignature, SignatureExpired):
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
        )
    return current_user
