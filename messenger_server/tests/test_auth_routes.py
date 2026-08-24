import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

"""
Create tests for test auth_routes
"""

@pytest.mark.asyncio
async def test_register_login_refresh_flow(client):
    register_payload = {
        "username": "alice_flow_register",
        "password": "fakestrongpassword",
        "identity_key_public": "fakeidentitykey123==",
        "registration_id": 111,
        "signed_prekey_public": "fakesignedprekeypublic123==",
        "signed_prekey_signature": "fakesignedprekeysignature123==",
        "one_time_prekeys": ["key1","key2", "key3"],
    }
    response = await client.post("/auth/register", json=register_payload)        
    assert response.status_code == 200, response.text
    register_data = response.json()
    assert "access_token" in register_data
    assert "user_id" in register_data

    login_payload = {"username": "alice_flow_register", "password": "fakestrongpassword"}
    response = await client.post("/auth/login", json=login_payload)
    assert response.status_code == 200, response.text
    login_data = response.json()
    assert "access_token" in login_data
    assert "refresh_token" in login_data

    refresh_payload = {"refresh_token" : login_data["refresh_token"]}
    response = await client.post("/auth/refresh", json=refresh_payload)
    assert response.status_code == 200, response.text
    assert "access_token" in response.json()


@pytest.mark.asyncio
async def test_login_test_wrong_password(client):
    await client.post("/auth/register", json={
        "username": "bob_wrong_password_test2",
        "password": "somepassword",
        "identity_key_public": "fake==",
        "registration_id": 222,
        "signed_prekey_public": "fake==",
        "signed_prekey_signature": "fake==",
        "one_time_prekeys": [],
        })
    response = await client.post("/auth/login", json={"username":"bob_wrong_password_test2",
                                 "password": "fakepassword"})
    
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_register_duplicate_username(client):
    payload = {     
        "username": "carol_duplicate_test",
        "password": "fakestrongpassword",
        "identity_key_public": "fakeidentitykey123==",
        "registration_id": 333,
        "signed_prekey_public": "fakesignedprekeypublic123==",
        "signed_prekey_signature": "fakesignedprekeysignature123==",
        "one_time_prekeys": [],
        }
    first = await client.post("/auth/register", json=payload)
    assert first.status_code == 200

    second = await client.post("/auth/register", json=payload)
    assert second.status_code == 409
    


