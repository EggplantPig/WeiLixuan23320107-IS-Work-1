# Work 1 — Secure REST API with CI/CD and Real CVE Analysis

HDU IS course, Work 1. A functional REST API built with **Python / Flask**, hardened with the security controls required by the assignment, and scanned by a SAST/SCA CI pipeline. The Vulhub CVE reproduction and fix will be added in a follow-up commit.

> Status: API, security controls, unit tests and GitHub Actions are implemented and CI is passing. The CVE reproduction/fix section is still pending.

## 1. API

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/auth/login` | none | Log in with `login` and `password`; returns a JWT |
| `GET` | `/api/data` | Bearer JWT | Return the list of posts (authenticated users only) |
| `POST` | `/api/data` | Bearer JWT | Create a post (third endpoint; demonstrates parameterized writes and XSS escaping) |

### Request examples

```bash
# Log in
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"Alice-Strong-Pass-1!"}'

# Read data (replace <TOKEN>)
curl -s http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>"

# Create data
curl -s -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Hello","content":"First post"}'
```

`POST /api/data` was chosen as the third endpoint because it exercises the write path: parameterized `INSERT` (SQL injection protection), output escaping (XSS protection), JWT authentication and input validation. A read-only endpoint would cover fewer grading criteria.

## 2. Security controls

### 2.1 SQL injection protection

All database access uses `sqlite3` parameterized queries (`?` placeholders); no SQL statement is built by string concatenation:

- `app/auth.py`: `SELECT ... WHERE username = ?`
- `app/api.py`: `SELECT`, `INSERT ... VALUES (?, ?, ?)`

`tests/test_api.py::test_sql_injection_payload_is_stored_literally` verifies that an injection payload is stored as plain text and that the schema is not damaged.

### 2.2 XSS protection

- User-controlled values are escaped on output with `markupsafe.escape` (the framework's built-in escaper); see `app/security.py::escape_text` and `app/api.py::serialize_post`.
- Seed data contains `<script>alert('stored-xss-demo')</script>`; `GET /api/data` returns `&lt;script&gt;...`, which proves escaping is applied.
- Test: `tests/test_api.py::test_xss_payload_is_escaped_in_response`.

### 2.3 Broken authentication protection

- A **JWT (HS256)** is issued after a successful login. It contains `sub`, `username`, `iat` and `exp`, and expires after 60 minutes by default.
- Protected endpoints validate `Authorization: Bearer <token>` through the `@token_required` decorator; invalid or expired tokens return 401.
- Passwords are hashed with **bcrypt** (unique salt per password) and never stored in plaintext. Failed logins always return the same `invalid credentials` message to avoid username enumeration.
- Secrets (`JWT_SECRET`, `SECRET_KEY`) are read from environment variables only; no real secret is committed to the repository.

## 3. Local development

Python 3.11+ is required.

```powershell
cd E:\MyFile\IS-Lab\Work-1
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt

$env:JWT_SECRET = "local-dev-only-jwt-secret-0123456789abcdef"
$env:SECRET_KEY = "local-dev-only-flask-secret-0123456789abcdef"

flask --app app seed
flask --app app run --port 5000
```

The API is then available at `http://127.0.0.1:5000`. Demo accounts for local testing only: `alice / Alice-Strong-Pass-1!` and `bob / Bob-Strong-Pass-2!`.

Run the tests:

```powershell
pytest -q
```

## 4. CI/CD

Workflow: `.github/workflows/ci.yml`. It runs on every push to `main` and on pull requests:

[![CI](https://github.com/EggplantPig/WeiLixuan23320107-IS-Work-1/actions/workflows/ci.yml/badge.svg)](https://github.com/EggplantPig/WeiLixuan23320107-IS-Work-1/actions/workflows/ci.yml)

1. Install dependencies and run `pytest`.
2. **SAST**: `bandit -r app`, writing `reports/bandit.json`.
3. **SCA**: `safety check -r requirements.txt`, writing `reports/safety.txt`.
4. Upload `reports/` as a build artifact (downloadable from the Actions page for report screenshots).

> OWASP Dependency-Check CLI is installed in the local user environment (`dependency-check`) and can be added to CI as a second SCA tool. The current pipeline uses safety for dependency vulnerability scanning.

## 5. Project structure

```text
Work-1/
├── app/
│   ├── __init__.py      # application factory
│   ├── auth.py          # /auth/login
│   ├── api.py           # /api/data GET/POST
│   ├── db.py            # SQLite connection and schema
│   ├── security.py      # bcrypt, JWT, XSS escaping, auth decorator
│   └── seed.py          # demo data
├── tests/               # pytest unit tests
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
└── run.py
```

## 6. Real CVE reproduction and fix (TODO)

- Vulnerable environment: Vulhub is cloned in WSL at `/home/EggplantPig/vulhub`.
- Pending CVE selection. This section will document: CVE ID, environment startup commands, reproduction steps and screenshots, root-cause analysis, the fix, proof that the attack fails after the fix, and regression tests.
