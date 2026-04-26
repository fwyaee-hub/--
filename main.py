import os
import logging
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app.database import engine, Base, SessionLocal
from app.routers import auth, frontend, users, files, share, agent
from app.config import Config

# Create database tables
# In production, use Alembic for migrations instead of create_all
if Config.AUTO_CREATE_TABLES:
    Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure File Management System",
    description="A FastAPI-based secure file storage system with AES encryption and RBAC.",
    version="1.0.0"
)

# CORS Middleware (Important for separate frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=Config.CORS_ORIGINS or ["*"],
    allow_credentials=bool(Config.CORS_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files if needed
# app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(files.router)
app.include_router(share.router)
app.include_router(agent.router)

app.include_router(frontend.router)

@app.on_event("startup")
async def startup_event():
    # Create upload folder
    if not os.path.exists(Config.UPLOAD_FOLDER):
        os.makedirs(Config.UPLOAD_FOLDER)
    
    # Initialize admin user (only when explicitly configured)
    db = SessionLocal()
    try:
        admin_username = Config.ADMIN_BOOTSTRAP_USERNAME
        admin_password = Config.ADMIN_BOOTSTRAP_PASSWORD
        admin_email = Config.ADMIN_BOOTSTRAP_EMAIL
        if not admin_username or not admin_password:
            return

        result = db.execute(
            text('SELECT * FROM users WHERE username = :name'),
            {"name": admin_username}
        )
        admin_user = result.fetchone()
        
        if not admin_user:
            hashed_password = generate_password_hash(admin_password)
            db.execute(
                text('INSERT INTO users (username, password, email, is_admin) VALUES (:name, :pwd, :email, :is_admin)'),
                {
                    "name": admin_username,
                    "pwd": hashed_password,
                    "email": admin_email,
                    "is_admin": True,
                }
            )
            db.commit()
    except Exception as e:
        logging.exception("Error bootstrapping admin: %s", e)
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
