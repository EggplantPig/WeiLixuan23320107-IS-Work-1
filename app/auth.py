from flask import Blueprint, current_app, jsonify, request

from .db import get_db
from .security import create_token, verify_password

bp = Blueprint("auth", __name__)


@bp.post("/auth/login")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON body required"}), 400

    login_name = payload.get("login")
    password = payload.get("password")
    if not isinstance(login_name, str) or not isinstance(password, str):
        return jsonify({"error": "login and password are required"}), 400
    if not login_name.strip() or not password:
        return jsonify({"error": "login and password are required"}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (login_name.strip(),),
    ).fetchone()

    if user is None or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_token(user["id"], user["username"])
    return jsonify(
        {
            "token": token,
            "token_type": "Bearer",  # nosec B105 - token type label, not a credential
            "expires_in": current_app.config["JWT_EXPIRES_MINUTES"],
        }
    )
