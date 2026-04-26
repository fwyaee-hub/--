from sqlalchemy import Column, Integer, String, Boolean, Text, ForeignKey, LargeBinary, DateTime, func
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    password = Column(String(255))
    email = Column(String(255))
    is_admin = Column(Boolean, default=False)
    
    keys = relationship(
        "UserKey",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        single_parent=True,
    )
    files = relationship("File", back_populates="user")
    sent_shares = relationship("SharedFile", back_populates="sender", foreign_keys="SharedFile.sender_id")
    received_shares = relationship("SharedFile", back_populates="receiver", foreign_keys="SharedFile.receiver_id")

class UserKey(Base):
    __tablename__ = "user_keys"
    
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    public_key = Column(LargeBinary)
    private_key = Column(LargeBinary)
    
    user = relationship("User", back_populates="keys")

class File(Base):
    __tablename__ = "files"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String(255))
    hash = Column(String(255))
    encryption_key = Column(LargeBinary)
    upload_time = Column(DateTime, default=func.now())
    
    user = relationship("User", back_populates="files")
    shares = relationship("SharedFile", back_populates="file")

class SharedFile(Base):
    __tablename__ = "shared_files"
    
    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("files.id"))
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"))
    encrypted_key = Column(LargeBinary)
    shared_at = Column(DateTime, default=func.now())
    
    file = relationship("File", back_populates="shares")
    sender = relationship("User", back_populates="sent_shares", foreign_keys=[sender_id])
    receiver = relationship("User", back_populates="received_shares", foreign_keys=[receiver_id])

class Folder(Base):
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    parent_id = Column(Integer, ForeignKey("folders.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=func.now())

    parent = relationship("Folder", remote_side=[id], back_populates="children")
    children = relationship("Folder", back_populates="parent")

class FileMeta(Base):
    __tablename__ = "file_meta"

    file_id = Column(Integer, ForeignKey("files.id"), primary_key=True)
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=True, index=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    file = relationship("File")
    folder = relationship("Folder")

class TrashItem(Base):
    __tablename__ = "trash_items"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    file_id = Column(Integer, ForeignKey("files.id"), index=True, nullable=False, unique=True)
    stored_filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    trashed_at = Column(DateTime, default=func.now(), index=True)

    file = relationship("File")
