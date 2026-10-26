from app.db import get_db
from app.security import verify_password

ALICE_PASSWORD = "Alice-Strong-Pass-1!"


def test_login_success(client):
    response = client.post(
        "/auth/login", json={"login": "alice", "password": ALICE_PASSWORD}
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["token"]
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 60


def test_login_wrong_password(client):
    response = client.post(
        "/auth/login", json={"login": "alice", "password": "wrong-password"}
    )
    assert response.status_code == 401


def test_login_unknown_user(client):
    response = client.post(
        "/auth/login", json={"login": "nobody", "password": "whatever"}
    )
    assert response.status_code == 401


def test_login_sql_injection_is_not_bypassable(client):
    response = client.post(
        "/auth/login",
        json={"login": "' OR '1'='1", "password": "' OR '1'='1"},
    )
    assert response.status_code == 401


def test_login_requires_fields(client):
    response = client.post("/auth/login", json={"login": "alice"})
    assert response.status_code == 400

    response = client.post("/auth/login", data="not json", content_type="application/json")
    assert response.status_code == 400


def test_password_is_hashed_in_database(app):
    with app.app_context():
        row = get_db().execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()

    assert row["password_hash"] != ALICE_PASSWORD
    assert row["password_hash"].startswith("$2")
    assert verify_password(ALICE_PASSWORD, row["password_hash"])
