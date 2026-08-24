"""
Business logic for auth
"""

import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status

from app.db.models import *
from app.schemas.user import RegisterRequest, LoginRequest
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token


async def register_user(payload: RegisterRequest, db: AsyncSession) -> tuple[User, str, str]:
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    user = User(
        id = uuid.uuid4(),
        username = payload.username,
        password_hash = hash_password(payload.password),
        identity_key_public = payload.identity_key_public,
        registration_id = payload.registration_id
    )
    db.add(user)
    await db.flush()

    signed_prekey = SignedPreKey(
        id = uuid.uuid4(),
        user_id = user.id,
        key_id = 1,
        public_key = payload.signed_prekey_public,
        signature = payload.signed_prekey_signature
    )
    db.add(signed_prekey)


    # COM: For Generate one-time prekeys data
    for idx, key in enumerate(payload.one_time_prekeys):
        db.add(OneTimePreKey(
            id = uuid.uuid4(),
            user_id = user.id,
            key_id = idx,
            public_key= key,
            used = False
        ))

    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(user_id=user.id)
    refresh_token = create_refresh_token(user_id=user.id)
    return user, access_token, refresh_token


async def authenticate_user(payload: LoginRequest, db: AsyncSession) -> tuple[User, str, str]:
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    access_token = create_access_token(user_id = user.id)
    refresh_token = create_refresh_token(user_id = user.id)
    return user, access_token, refresh_token
    