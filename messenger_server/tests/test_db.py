import pytest
from app.db.session import AsyncSessionLocal
from app.db.models import User


@pytest.mark.asyncio
async def test_create_user(db_session):
        user = User(
            username="alice_test",
            password_hash="fake_hash",
            identity_key_public="fake_base64_key",
            registration_id=12345,
        )
        db_session.add(user)
        await db_session.commit()
        assert user.id is not None