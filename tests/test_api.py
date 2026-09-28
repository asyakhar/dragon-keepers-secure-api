from app.db import get_db


def test_health_and_security_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_login_returns_jwt(client):
    response = client.post(
        "/auth/login", json={"username": "student", "password": "Strong-Test1!"}
    )
    assert response.status_code == 200
    assert response.get_json()["expires_in"] == 1800
    assert response.get_json()["access_token"].count(".") == 2


def test_bad_credentials_and_sql_injection_are_rejected(client):
    wrong_password = client.post(
        "/auth/login", json={"username": "student", "password": "wrong"}
    )
    injection = client.post(
        "/auth/login", json={"username": "' OR 1=1 --", "password": "anything"}
    )
    assert wrong_password.status_code == 401
    assert injection.status_code == 401
    assert wrong_password.get_json() == injection.get_json()


def test_protected_endpoint_requires_valid_token(client, auth_header):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers={"Authorization": "Bearer broken"}).status_code == 401
    assert client.get("/api/data", headers=auth_header).status_code == 200


def test_xss_is_escaped_in_note_responses(client, auth_header):
    payload = {"title": "<script>alert(1)</script>", "content": "<img src=x onerror=alert(1)>"}
    created = client.post("/api/notes", json=payload, headers=auth_header)
    listed = client.get("/api/notes", headers=auth_header)
    assert created.status_code == 201
    assert "<script>" not in created.get_json()["title"]
    assert "&lt;script&gt;" in created.get_json()["title"]
    assert "<img" not in listed.get_json()["notes"][0]["content"]


def test_password_is_stored_as_bcrypt_hash(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("student",)
        ).fetchone()
        assert row["password_hash"].startswith("$2")
        assert "Strong-Test1!" not in row["password_hash"]
