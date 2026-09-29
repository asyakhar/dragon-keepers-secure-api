from app.db import create_rider, get_db


def test_health_and_security_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_rider_login_returns_jwt(client):
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


def test_dragon_collection_requires_valid_token(client, auth_header):
    assert client.get("/api/data").status_code == 401
    assert client.get("/api/data", headers={"Authorization": "Bearer broken"}).status_code == 401

    response = client.get("/api/data", headers=auth_header)
    assert response.status_code == 200
    assert response.get_json()["rider"] == "student"
    assert response.get_json()["collection_size"] == 2
    assert {dragon["name"] for dragon in response.get_json()["dragons"]} == {"Искра", "Север"}


def test_rider_can_add_dragon_and_xss_is_escaped(client, auth_header):
    payload = {
        "name": "<script>alert(1)</script>",
        "species": "Грозовой дракон",
        "element": "storm",
        "age": 42,
        "description": "<img src=x onerror=alert(1)>",
    }
    created = client.post("/api/dragons", json=payload, headers=auth_header)
    collection = client.get("/api/data", headers=auth_header).get_json()

    assert created.status_code == 201
    assert "<script>" not in created.get_json()["dragon"]["name"]
    assert "&lt;script&gt;" in created.get_json()["dragon"]["name"]
    assert "<img" not in collection["dragons"][-1]["description"]
    assert collection["collection_size"] == 3


def test_dragon_input_validation_and_duplicate_names(client, auth_header):
    invalid = client.post(
        "/api/dragons",
        json={
            "name": "A",
            "species": "Виверн",
            "element": "unknown",
            "age": -1,
            "description": "invalid",
        },
        headers=auth_header,
    )
    duplicate = client.post(
        "/api/dragons",
        json={
            "name": "Искра",
            "species": "Небесный дракон",
            "element": "fire",
            "age": 120,
            "description": "duplicate",
        },
        headers=auth_header,
    )
    assert invalid.status_code == 400
    assert duplicate.status_code == 409


def test_riders_cannot_read_each_others_dragons(app, client, auth_header):
    with app.app_context():
        second_rider_id = create_rider("astrid", "Another-Strong1!")
        get_db().execute(
            """
            INSERT INTO dragons (rider_id, name, species, element, age, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (second_rider_id, "Тайна", "Теневой дракон", "shadow", 300, "Hidden"),
        )
        get_db().commit()

    collection = client.get("/api/data", headers=auth_header).get_json()
    assert "Тайна" not in {dragon["name"] for dragon in collection["dragons"]}


def test_password_is_stored_as_bcrypt_hash(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM riders WHERE username = ?", ("student",)
        ).fetchone()
        assert row["password_hash"].startswith("$2")
        assert "Strong-Test1!" not in row["password_hash"]
