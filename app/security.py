"""Password hashing, JWT handling and XSS output escaping."""

from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request
from markupsafe import escape


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )
    except (TypeError, ValueError):
        return False


def create_token(user_id, username):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=current_app.config["JWT_EXPIRES_MINUTES"]),
    }
    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def decode_token(token):
    try:
        return jwt.decode(
            token,
            current_app.config["JWT_SECRET"],
            algorithms=[current_app.config["JWT_ALGORITHM"]],
        )
    except jwt.PyJWTError:
        return None


def token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "missing or invalid Authorization header"}), 401
        payload = decode_token(header[7:].strip())
        if payload is None:
            return jsonify({"error": "invalid or expired token"}), 401
        g.current_user = {"id": int(payload["sub"]), "username": payload["username"]}
        return view(*args, **kwargs)

    return wrapped


def escape_text(value):
    """Escape user-controlled text with the framework's built-in escaper."""
    return str(escape(value))
