import pytest
from pydantic import ValidationError
from app.schemas.user import RegisterRequest

def test_register_request_valid():
    payload = RegisterRequest(
        username="alice",
        password="1234hashhas",
        identity_key_public="fakeidentitypubkey==",
        registration_id=12345,
        signed_prekey_public="fakesignedprekey_public==",
        signed_prekey_signature="signedprekeysignature==",
        one_time_prekeys=["key1", "key2", "key3"],
    )
    assert payload.username == "alice"


def test_register_request_username_tooshort():
    with pytest.raises(ValidationError):
        RegisterRequest(
            username="al",
            password="1234hashhas",
            identity_key_public="fakeidentitypubkey==",
            registration_id=12345,
            signed_prekey_public="fakesignedprekey_public==",
            signed_prekey_signature="signedprekeysignature==",
            one_time_prekeys=["key1", "key2", "key3"],
    )

def test_register_request_password_tooshort():
    with pytest.raises(ValidationError):
        RegisterRequest(
            username="alice",
            password="1234",
            identity_key_public="fakeidentitypubkey==",
            registration_id=12345,
            signed_prekey_public="fakesignedprekey_public==",
            signed_prekey_signature="signedprekeysignature==",
            one_time_prekeys=["key1", "key2", "key3"],
        )
    
        
    
    