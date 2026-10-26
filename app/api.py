from flask import Blueprint, g, jsonify, request

from .db import get_db
from .security import escape_text, token_required

bp = Blueprint("api", __name__)

MAX_TITLE_LENGTH = 120
MAX_CONTENT_LENGTH = 5000

POST_SELECT = """
SELECT posts.id, posts.title, posts.content, posts.created_at, users.username AS author
FROM posts
JOIN users ON users.id = posts.user_id
"""


def serialize_post(row):
    return {
        "id": row["id"],
        "title": escape_text(row["title"]),
        "content": escape_text(row["content"]),
        "author": escape_text(row["author"]),
        "created_at": row["created_at"],
    }


@bp.get("/api/data")
@token_required
def list_data():
    rows = get_db().execute(POST_SELECT + " ORDER BY posts.id").fetchall()
    return jsonify({"data": [serialize_post(row) for row in rows]})


@bp.post("/api/data")
@token_required
def create_data():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body required"}), 400

    title = payload.get("title")
    content = payload.get("content")
    if not isinstance(title, str) or not isinstance(content, str):
        return jsonify({"error": "title and content are required"}), 400

    title = title.strip()
    content = content.strip()
    if not title or not content:
        return jsonify({"error": "title and content must not be empty"}), 400
    if len(title) > MAX_TITLE_LENGTH:
        return jsonify({"error": f"title must be at most {MAX_TITLE_LENGTH} characters"}), 400
    if len(content) > MAX_CONTENT_LENGTH:
        return jsonify({"error": f"content must be at most {MAX_CONTENT_LENGTH} characters"}), 400

    db = get_db()
    cursor = db.execute(
        "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
        (g.current_user["id"], title, content),
    )
    db.commit()
    row = db.execute(POST_SELECT + " WHERE posts.id = ?", (cursor.lastrowid,)).fetchone()
    return jsonify({"data": serialize_post(row)}), 201
