import click
from flask.cli import with_appcontext

from .db import get_db
from .security import hash_password

# Demo accounts for the local lab only. These are not real credentials.
DEMO_USERS = (
    ("alice", "Alice-Strong-Pass-1!"),
    ("bob", "Bob-Strong-Pass-2!"),
)

DEMO_POSTS = (
    ("Welcome to Work 1", "This is the first seeded post."),
    ("Stored XSS demo payload", "<script>alert('stored-xss-demo')</script>"),
)


@click.command("seed")
@with_appcontext
def seed_command():
    """Create demo users and posts for local testing."""
    db = get_db()
    for username, password in DEMO_USERS:
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )

    count = db.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    if count == 0:
        alice_id = db.execute(
            "SELECT id FROM users WHERE username = ?", ("alice",)
        ).fetchone()[0]
        for title, content in DEMO_POSTS:
            db.execute(
                "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
                (alice_id, title, content),
            )

    db.commit()
    click.echo("Database seeded: users alice/bob, demo posts created.")
