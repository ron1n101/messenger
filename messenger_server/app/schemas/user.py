
"""
Pydantinc schemas - это такие классы, которые описывают форму данных, которые будут приходить в АПИ и выходить из 
него (запросы и ответы). Для фастапи нужно для ясной и корректной валидации
"""

from pydantic import BaseModel, Field
from uuid import UUID


"""""
Register Request - build full schemas about user, when he on stage Registration
Register Response - receive from api response (generated userID. his access_token and refresh_token)
Login Request - username and password
Token Response - after user receive his token, user automatically set identificator "bearer"
Refresh request - only refreshing "refresh_token"
"""""

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8)
    identity_key_public: str
    registration_id: int
    signed_prekey_public: str
    signed_prekey_signature: str
    one_time_prekeys: list[str]

class RegisterResponse(BaseModel):
    user_id: UUID
    access_token: str
    refresh_token: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str


