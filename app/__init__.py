import os

from flask import Flask

from . import api, auth, db
from .seed import seed_command


def create_app(test_config=None):
    """Application factory.

    Secrets must come from the environment; nothing sensitive is hardcoded.
    """
    app = Flask(__name__, instance_relative_config=True)

    secret_key = os.environ.get("SECRET_KEY") or os.environ.get("JWT_SECRET")
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        JWT_SECRET=os.environ.get("JWT_SECRET"),
        JWT_ALGORITHM="HS256",
        JWT_EXPIRES_MINUTES=int(os.environ.get("JWT_EXPIRES_MINUTES", "60")),
        DATABASE=os.environ.get(
            "DATABASE_PATH", os.path.join(app.instance_path, "work1.sqlite3")
        ),
    )

    if test_config:
        app.config.update(test_config)

    if not app.config.get("JWT_SECRET"):
        raise RuntimeError(
            "JWT_SECRET is not set; provide it via environment variable "
            "or test configuration."
        )

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)
    app.cli.add_command(seed_command)

    return app
