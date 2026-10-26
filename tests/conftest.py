import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.db import get_db
from app.security import hash_password


@pytest.fixture()
def app(tmp_path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-jwt-secret-0123456789abcdef",
            "JWT_SECRET": "test-only-jwt-secret-0123456789abcdef",
            "JWT_EXPIRES_MINUTES": 60,
            "DATABASE": str(tmp_path / "test.sqlite3"),
        }
    )

    with application.app_context():
        database = get_db()
        for username, password in (
            ("alice", "Alice-Strong-Pass-1!"),
            ("bob", "Bob-Strong-Pass-2!"),
        ):
            database.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hash_password(password)),
            )
        database.execute(
            "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
            (1, "Hello", "first post"),
        )
        database.commit()

    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    response = client.post(
        "/auth/login",
        json={"login": "alice", "password": "Alice-Strong-Pass-1!"},
    )
    token = response.get_json()["token"]
    return {"Authorization": f"Bearer {token}"}
