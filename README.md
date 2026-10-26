# Work 1 — Secure REST API with CI/CD and Real CVE Analysis

HDU IS 课程 Work 1 项目：使用 **Python / Flask** 实现带安全措施的功能性 REST API，并配置 SAST/SCA 的 CI 流水线；Vulhub 真实 CVE 的复现与修复部分将在后续提交中补充。

> 当前状态：API、安全措施、单元测试与 GitHub Actions 已实现，CI 已通过；CVE 复现/修复章节待完成。

## 1. API 说明

| 方法 | 路径 | 认证 | 说明 |
|---|---|---|---|
| `POST` | `/auth/login` | 无 | 使用 `login` 和 `password` 登录，成功返回 JWT |
| `GET` | `/api/data` | Bearer JWT | 返回帖子列表（仅认证用户可访问） |
| `POST` | `/api/data` | Bearer JWT | 创建帖子（第三个接口，演示参数化写入与 XSS 转义） |

### 请求示例

```bash
# 登录
curl -s -X POST http://127.0.0.1:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"alice","password":"Alice-Strong-Pass-1!"}'

# 读取数据（替换 <TOKEN>）
curl -s http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>"

# 创建数据
curl -s -X POST http://127.0.0.1:5000/api/data \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Hello","content":"First post"}'
```

第三个接口选择 `POST /api/data` 的原因：它同时覆盖写路径的 SQL 注入防护（参数化 `INSERT`）、XSS 防护（输出转义）、JWT 鉴权与输入校验，比单纯再加一个只读接口更能体现 Work 1 的安全评分点。

## 2. 已实施的安全措施

### 2.1 SQL 注入防护

所有数据库访问都使用 `sqlite3` 参数化查询（`?` 占位符），不存在字符串拼接 SQL：

- `app/auth.py`：`SELECT ... WHERE username = ?`
- `app/api.py`：`SELECT`、`INSERT ... VALUES (?, ?, ?)`

`tests/test_api.py::test_sql_injection_payload_is_stored_literally` 验证注入串被当作普通文本存储，且表结构未被破坏。

### 2.2 XSS 防护

- 使用 Flask 项目自带的 `markupsafe.escape`（框架内置转义函数）对返回的用户数据统一转义，见 `app/security.py::escape_text` 与 `app/api.py::serialize_post`。
- 种子数据中包含 `<script>alert('stored-xss-demo')</script>`，`GET /api/data` 返回的是 `&lt;script&gt;...`，证明转义生效。
- 测试：`tests/test_api.py::test_xss_payload_is_escaped_in_response`。

### 2.3 Broken Authentication 防护

- 登录成功后签发 **JWT（HS256）**，包含 `sub`、`username`、`iat`、`exp`，默认 60 分钟过期。
- 受保护端点通过 `@token_required` 中间件校验 `Authorization: Bearer <token>`，无效或过期返回 401。
- 密码使用 **bcrypt** 加盐哈希后存入数据库，绝不保存明文；登录失败统一返回 `invalid credentials`，避免用户名枚举。
- 密钥（`JWT_SECRET`、`SECRET_KEY`）只从环境变量读取，仓库中不含真实密钥。

## 3. 本地运行

要求 Python 3.11+。

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

启动后访问 `http://127.0.0.1:5000`。演示账号（仅本地实验用）：`alice / Alice-Strong-Pass-1!`、`bob / Bob-Strong-Pass-2!`。

运行测试：

```powershell
pytest -q
```

## 4. CI/CD

工作流：`.github/workflows/ci.yml`，在 push 到 `main` 和 pull request 时自动运行：

[![CI](https://github.com/EggplantPig/Work-1/actions/workflows/ci.yml/badge.svg)](https://github.com/EggplantPig/Work-1/actions/workflows/ci.yml)

1. 安装依赖并运行 `pytest`。
2. **SAST**：`bandit -r app`，生成 `reports/bandit.json`。
3. **SCA**：`safety check -r requirements.txt`，生成 `reports/safety.txt`。
4. 上传 `reports/` 作为构建产物（Actions 页面可下载或截图）。

> OWASP Dependency-Check CLI 已安装在本机用户级环境（`dependency-check`），后续可加入 CI 作为第二种 SCA 工具；当前 CI 使用 safety 完成依赖漏洞扫描。

## 5. 项目结构

```text
Work-1/
├── app/
│   ├── __init__.py      # 应用工厂
│   ├── auth.py          # /auth/login
│   ├── api.py           # /api/data GET/POST
│   ├── db.py            # SQLite 连接与建表
│   ├── security.py      # bcrypt、JWT、XSS 转义、鉴权装饰器
│   └── seed.py          # 演示数据
├── tests/               # pytest 单元测试
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
└── run.py
```

## 6. 真实 CVE 复现与修复（待完成）

- 脆弱环境：WSL 中已克隆 Vulhub 到 `/home/EggplantPig/vulhub`。
- 待选定 CVE 后补充：CVE ID、环境启动命令、攻击复现步骤与截图、根因分析、修复内容、修复后攻击失败验证与回归测试。
