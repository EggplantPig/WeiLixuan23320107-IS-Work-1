from app.db import get_db


def test_data_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401


def test_invalid_token_is_rejected(client):
    response = client.get("/api/data", headers={"Authorization": "Bearer not-a-token"})
    assert response.status_code == 401


def test_data_with_token(client, auth_headers):
    response = client.get("/api/data", headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert len(data) >= 1
    assert data[0]["title"] == "Hello"


def test_create_post_requires_token(client):
    response = client.post("/api/data", json={"title": "x", "content": "y"})
    assert response.status_code == 401


def test_create_post(client, auth_headers):
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "New post", "content": "Body text"},
    )
    assert response.status_code == 201
    body = response.get_json()["data"]
    assert body["title"] == "New post"
    assert body["author"] == "alice"


def test_create_post_validation(client, auth_headers):
    response = client.post(
        "/api/data", headers=auth_headers, json={"title": "", "content": ""}
    )
    assert response.status_code == 400

    response = client.post(
        "/api/data", headers=auth_headers, json={"title": "x" * 121, "content": "y"}
    )
    assert response.status_code == 400


def test_xss_payload_is_escaped_in_response(client, auth_headers):
    payload = "<script>alert('xss')</script>"
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "XSS demo", "content": payload},
    )
    assert response.status_code == 201

    body = response.get_data(as_text=True)
    assert "<script>" not in body
    assert "&lt;script&gt;" in body

    listed = client.get("/api/data", headers=auth_headers)
    assert "<script>" not in listed.get_data(as_text=True)
    assert "&lt;script&gt;" in listed.get_data(as_text=True)


def test_sql_injection_payload_is_stored_literally(client, auth_headers, app):
    payload = "'; DROP TABLE posts; --"
    response = client.post(
        "/api/data",
        headers=auth_headers,
        json={"title": "SQLi demo", "content": payload},
    )
    assert response.status_code == 201

    with app.app_context():
        row = get_db().execute(
            "SELECT content FROM posts WHERE title = ?", ("SQLi demo",)
        ).fetchone()
    assert row["content"] == payload

    # Table still exists and the API still works after the payload.
    assert client.get("/api/data", headers=auth_headers).status_code == 200
