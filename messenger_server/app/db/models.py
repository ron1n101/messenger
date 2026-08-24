import uuid
from datetime import datetime
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, LargeBinary, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.db.session import Base

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    identity_key_public: Mapped[str] = mapped_column(String(255), nullable=False)
    registration_id: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


    signed_prekeys: Mapped[list["SignedPreKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    one_time_prekeys: Mapped[list["OneTimePreKey"]] = relationship(back_populates="user", cascade= "all, delete-orphan")


class SignedPreKey(Base):
    __tablename__ = "signed_prekeys"
    
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    key_id: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    signature: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    user: Mapped["User"] = relationship(back_populates="signed_prekeys")


class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    key_id: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship(back_populates="one_time_prekeys")

class QueuedMessage(Base):
    __tablename__ = "queued_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    recipient_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    ciphertext_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())



