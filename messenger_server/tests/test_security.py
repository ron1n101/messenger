import time
from datetime import timedelta
from app.core.security import *

def test_password_hash_and_verify():
    hashed = hash_password("mysecretpassword")
    assert hashed != "mysecretpassword"
    assert verify_password("mysecretpassword", hashed) is True
    assert verify_password("mywrongpassword", hashed) is False


def test_access_token_roundtrip():
    token = create_access_token(user_id="user-12345")
    payload = decode_token(token)
    assert payload["sub"] == "user-12345"
    assert payload["type"] == "access"


def test_refresh_token_roundtrip():
    token = create_refresh_token(user_id="user-12345")
    payload = decode_token(token)
    assert payload["sub"] == "user-12345"
    assert payload["type"] == "refresh"

def test_expire_token_raise():
    token = create_access_token(user_id="user-12345", expires_delta=timedelta(seconds=1))
    time.sleep(2)
    try:
        decode_token(token)
        assert False, "Was expected error expired token"
    except ValueError:
        pass
