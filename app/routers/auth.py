from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

from app.database import get_db
from app.models import User
from app.schemas import UserCreate, UserLogin, Token
from app.utils import init_user_keys
from app.config import Config
from app.dependencies import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES

router = APIRouter(
    prefix="/api/auth",
    tags=["auth"],
    responses={404: {"description": "Not found"}},
)

@router.get("/register")
def register_help():
    return RedirectResponse(url="/register", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    db_email = db.query(User).filter(User.email == user.email).first()
    if db_email:
         raise HTTPException(status_code=400, detail="Email already registered")

    if len(user.username) < 3 or len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Username or password too short")

    hashed_password = generate_password_hash(user.password)
    new_user = User(username=user.username, password=hashed_password, email=user.email)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    init_user_keys(new_user.id, db)
    
    return {"message": "Registration successful"}

@router.get("/login")
def login_help():
    return RedirectResponse(url="/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

@router.post("/login")
def login(response: Response, user_in: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_in.username).first()
    if not user or not check_password_hash(user.password, user_in.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Set cookie for browser access
    response.set_cookie(
        key="access_token",
        value=f"{access_token}",
        httponly=True,
        secure=Config.COOKIE_SECURE,
        samesite=Config.COOKIE_SAMESITE,
    )
    
    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer", "user": {"username": user.username, "is_admin": user.is_admin}}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully"}

@router.get("/logout")
def logout_help():
    return RedirectResponse(url="/logout", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
