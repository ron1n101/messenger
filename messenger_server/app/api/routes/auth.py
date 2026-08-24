"""
Auth API routes
"""

from fastapi import APIRouter, Depends

from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.schemas.user import *
from app.services.auth_service import *
from app.core.security import decode_token, create_access_token
from fastapi import HTTPException, status

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=RegisterResponse)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)) -> RegisterResponse:
    user, access_token, refresh_token = await register_user(payload, db)
    return RegisterResponse(user_id=user.id, access_token=access_token, refresh_token=refresh_token)

@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    access_token, refresh_token = await authenticate_user(payload, db)
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)
    

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_route(payload: RefreshRequest) -> TokenResponse:
    try:
        decoded = decode_token(payload.refresh_token)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail= "Invalid refresh token")

    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    new_access_token = create_access_token(user_id=decoded["sub"])
    return TokenResponse(access_token=new_access_token, refresh_token=payload.refresh_token)