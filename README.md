# Work 1 鈥?Secure REST API with CI/CD and Real CVE Analysis

HDU IS 璇剧▼ Work 1 椤圭洰锛氫娇鐢?**Python / Flask** 瀹炵幇甯﹀畨鍏ㄦ帾鏂界殑鍔熻兘鎬?REST API锛屽苟閰嶇疆 SAST/SCA 鐨?CI 娴佹按绾匡紱Vulhub 鐪熷疄 CVE 鐨勫鐜颁笌淇閮ㄥ垎灏嗗湪鍚庣画鎻愪氦涓ˉ鍏呫€?
> 褰撳墠鐘舵€侊細API銆佸畨鍏ㄦ帾鏂姐€佸崟鍏冩祴璇曚笌 GitHub Actions 宸插疄鐜帮紱CVE 澶嶇幇/淇绔犺妭寰呭畬鎴愩€?
## 1. API 璇存槑

| 鏂规硶 | 璺緞 | 璁よ瘉 | 璇存槑 |
|---|---|---|---|
| `POST` | `/auth/login` | 鏃?| 浣跨敤 `login` 鍜?`password` 鐧诲綍锛屾垚鍔熻繑鍥?JWT |
| `GET` | `/api/data` | Bearer JWT | 杩斿洖甯栧瓙鍒楄〃锛堜粎璁よ瘉鐢ㄦ埛鍙闂級 |
| `POST` | `/api/data` | Bearer JWT | 鍒涘缓甯栧瓙锛堢涓変釜鎺ュ彛锛屾紨绀哄弬鏁板寲鍐欏叆涓?XSS 杞箟锛?|

### 璇锋眰绀轰緥

```bash
# 鐧诲綍
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"Alice-Strong-Pass-1!"}'

# 璇诲彇鏁版嵁锛堟浛鎹?<TOKEN>锛?curl -s http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>"

# 鍒涘缓鏁版嵁
curl -s -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Hello","content":"First post"}'
```

绗笁涓帴鍙ｉ€夋嫨 `POST /api/data` 鐨勫師鍥狅細瀹冨悓鏃惰鐩栧啓璺緞鐨?SQL 娉ㄥ叆闃叉姢锛堝弬鏁板寲 `INSERT`锛夈€乆SS 闃叉姢锛堣緭鍑鸿浆涔夛級銆丣WT 閴存潈涓庤緭鍏ユ牎楠岋紝姣斿崟绾啀鍔犱竴涓彧璇绘帴鍙ｆ洿鑳戒綋鐜?Work 1 鐨勫畨鍏ㄨ瘎鍒嗙偣銆?
## 2. 宸插疄鏂界殑瀹夊叏鎺柦

### 2.1 SQL 娉ㄥ叆闃叉姢

鎵€鏈夋暟鎹簱璁块棶閮戒娇鐢?`sqlite3` 鍙傛暟鍖栨煡璇紙`?` 鍗犱綅绗︼級锛屼笉瀛樺湪瀛楃涓叉嫾鎺?SQL锛?
- `app/auth.py`锛歚SELECT ... WHERE username = ?`
- `app/api.py`锛歚SELECT`銆乣INSERT ... VALUES (?, ?, ?)`

`tests/test_api.py::test_sql_injection_payload_is_stored_literally` 楠岃瘉娉ㄥ叆涓茶褰撲綔鏅€氭枃鏈瓨鍌紝涓旇〃缁撴瀯鏈鐮村潖銆?
### 2.2 XSS 闃叉姢

- 浣跨敤 Flask 椤圭洰鑷甫鐨?`markupsafe.escape`锛堟鏋跺唴缃浆涔夊嚱鏁帮級瀵硅繑鍥炵殑鐢ㄦ埛鏁版嵁缁熶竴杞箟锛岃 `app/security.py::escape_text` 涓?`app/api.py::serialize_post`銆?- 绉嶅瓙鏁版嵁涓寘鍚?`<script>alert('stored-xss-demo')</script>`锛宍GET /api/data` 杩斿洖鐨勬槸 `&lt;script&gt;...`锛岃瘉鏄庤浆涔夌敓鏁堛€?- 娴嬭瘯锛歚tests/test_api.py::test_xss_payload_is_escaped_in_response`銆?
### 2.3 Broken Authentication 闃叉姢

- 鐧诲綍鎴愬姛鍚庣鍙?**JWT锛圚S256锛?*锛屽寘鍚?`sub`銆乣username`銆乣iat`銆乣exp`锛岄粯璁?60 鍒嗛挓杩囨湡銆?- 鍙椾繚鎶ょ鐐归€氳繃 `@token_required` 涓棿浠舵牎楠?`Authorization: Bearer <token>`锛屾棤鏁堟垨杩囨湡杩斿洖 401銆?- 瀵嗙爜浣跨敤 **bcrypt** 鍔犵洂鍝堝笇鍚庡瓨鍏ユ暟鎹簱锛岀粷涓嶄繚瀛樻槑鏂囷紱鐧诲綍澶辫触缁熶竴杩斿洖 `invalid credentials`锛岄伩鍏嶇敤鎴峰悕鏋氫妇銆?- 瀵嗛挜锛坄JWT_SECRET`銆乣SECRET_KEY`锛夊彧浠庣幆澧冨彉閲忚鍙栵紝浠撳簱涓笉鍚湡瀹炲瘑閽ャ€?
## 3. 鏈湴杩愯

瑕佹眰 Python 3.11+銆?
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

鍚姩鍚庤闂?`http://127.0.0.1:5000`銆傛紨绀鸿处鍙凤紙浠呮湰鍦板疄楠岀敤锛夛細`alice / Alice-Strong-Pass-1!`銆乣bob / Bob-Strong-Pass-2!`銆?
杩愯娴嬭瘯锛?
```powershell
pytest -q
```

## 4. CI/CD

宸ヤ綔娴侊細`.github/workflows/ci.yml`锛屽湪 push 鍒?`main` 鍜?pull request 鏃惰嚜鍔ㄨ繍琛岋細

1. 瀹夎渚濊禆骞惰繍琛?`pytest`銆?2. **SAST**锛歚bandit -r app`锛岀敓鎴?`reports/bandit.json`銆?3. **SCA**锛歚safety check -r requirements.txt`锛岀敓鎴?`reports/safety.txt`銆?4. 涓婁紶 `reports/` 浣滀负鏋勫缓浜х墿锛圓ctions 椤甸潰鍙笅杞芥垨鎴浘锛夈€?
> OWASP Dependency-Check CLI 宸插畨瑁呭湪鏈満鐢ㄦ埛绾х幆澧冿紙`dependency-check`锛夛紝鍚庣画鍙姞鍏?CI 浣滀负绗簩绉?SCA 宸ュ叿锛涘綋鍓?CI 浣跨敤 safety 瀹屾垚渚濊禆婕忔礊鎵弿銆?
## 5. 椤圭洰缁撴瀯

```text
Work-1/
鈹溾攢鈹€ app/
鈹?  鈹溾攢鈹€ __init__.py      # 搴旂敤宸ュ巶
鈹?  鈹溾攢鈹€ auth.py          # /auth/login
鈹?  鈹溾攢鈹€ api.py           # /api/data GET/POST
鈹?  鈹溾攢鈹€ db.py            # SQLite 杩炴帴涓庡缓琛?鈹?  鈹溾攢鈹€ security.py      # bcrypt銆丣WT銆乆SS 杞箟銆侀壌鏉冭楗板櫒
鈹?  鈹斺攢鈹€ seed.py          # 婕旂ず鏁版嵁
鈹溾攢鈹€ tests/               # pytest 鍗曞厓娴嬭瘯
鈹溾攢鈹€ .github/workflows/ci.yml
鈹溾攢鈹€ requirements.txt
鈹溾攢鈹€ requirements-dev.txt
鈹斺攢鈹€ run.py
```

## 6. 鐪熷疄 CVE 澶嶇幇涓庝慨澶嶏紙寰呭畬鎴愶級

- 鑴嗗急鐜锛歐SL 涓凡鍏嬮殕 Vulhub 鍒?`/home/EggplantPig/vulhub`銆?- 寰呴€夊畾 CVE 鍚庤ˉ鍏咃細CVE ID銆佺幆澧冨惎鍔ㄥ懡浠ゃ€佹敾鍑诲鐜版楠や笌鎴浘銆佹牴鍥犲垎鏋愩€佷慨澶嶅唴瀹广€佷慨澶嶅悗鏀诲嚮澶辫触楠岃瘉涓庡洖褰掓祴璇曘€?
