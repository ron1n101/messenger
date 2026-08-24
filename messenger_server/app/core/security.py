
"""
WORKING WITH SECURITY
1. we need hash our password
2. verify our password
3. create access_token using by passlib, and take the instrucion from our settings file.
we need dete record time, when access_token had been created, and assigned his live-time date.
and  encoded using by jwt.
4. create refresh_token - this is the "endpoint" for generate new access_token. if 
refresh_token has been expired, server need to create new pair tokens
5. get_current_user - this func for check user on the availability. decode JWT token from request
and validate them. find the user in the DB. And return User as the object.
If not, error 401 = unauthorized.
"""


from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt, JWTError
from app.core.config import settings

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.db.models import User


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")     # need to change (for test)
async def get_current_user(token: str = Depends(oauth2_scheme), 
                           db: AsyncSession = Depends(get_db)) -> User:

    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials",
                                         headers={"WWW-Authenticate" : "Bearer"})

    try:
        payload = decode_token(token)
    except ValueError:
        raise credential_exception

    if payload.get("type") != "access":
        raise credential_exception

    user_id = payload.get("sub")

    if user_id is None:
        raise credential_exception
    try:
        user_uuid = UUID(user_id)
    except (ValueError, TypeError):
        raise credential_exception


    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None:
        raise credential_exception
    
    return user


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(user_id: str | UUID, expires_delta: timedelta | None=None) -> str:
    user_id_str = str(user_id)
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    payload = {"sub": user_id_str, "exp": expire, "type": "access"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def create_refresh_token(user_id: str | UUID) -> str:
    user_id_str = str(user_id)
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    payload = {"sub": user_id_str, "exp": expire, "type": "refresh"}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=settings.jwt_algorithm)
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")






