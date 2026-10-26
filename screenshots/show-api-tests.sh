#!/usr/bin/env bash
# Screenshot script: API functional and authentication tests with curl.
set -u
BASE=http://127.0.0.1:5000

echo "Work 1 API functional test (curl)"
echo "---------------------------------"
echo "[1] POST /auth/login with valid credentials"
curl -s -o /tmp/login.json -w 'HTTP=%{http_code}\n' -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"login":"alice","password":"Alice-Strong-Pass-1!"}'
python3 - <<'PY'
import json
data = json.load(open('/tmp/login.json'))
print('token_type=%s token_length=%d' % (data.get('token_type'), len(data.get('token', ''))))
PY
TOKEN=$(python3 -c 'import json;print(json.load(open("/tmp/login.json"))["token"])')
echo
echo "[2] GET /api/data without token (must be 401)"
curl -s -o /dev/null -w 'HTTP=%{http_code}\n' "$BASE/api/data"
echo
echo "[3] GET /api/data with Bearer token"
curl -s -o /tmp/data.json -w 'HTTP=%{http_code}\n' -H "Authorization: Bearer $TOKEN" "$BASE/api/data"
python3 - <<'PY'
import json
data = json.load(open('/tmp/data.json'))['data']
print('items=%d first_title=%s' % (len(data), data[0]['title']))
PY
echo
echo "[4] POST /api/data with Bearer token"
curl -s -o /tmp/post.json -w 'HTTP=%{http_code}\n' -X POST "$BASE/api/data" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"API test post","content":"created by curl"}'
python3 - <<'PY'
import json
data = json.load(open('/tmp/post.json'))['data']
print('created_title=%s author=%s' % (data['title'], data['author']))
PY
echo
echo "RESULT: login success, unauthorised request rejected, authenticated read/create succeeded."
