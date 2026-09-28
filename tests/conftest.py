import pytest

from app import create_app
from app.db import create_user, init_db


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "DATABASE_PATH": str(tmp_path / "test.sqlite"),
            "JWT_SECRET": "test-secret-that-is-not-used-in-production",
            "JWT_TTL_MINUTES": 30,
        }
    )
    with application.app_context():
        init_db()
        create_user("student", "Strong-Test1!")
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_header(client):
    response = client.post(
        "/auth/login", json={"username": "student", "password": "Strong-Test1!"}
    )
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
