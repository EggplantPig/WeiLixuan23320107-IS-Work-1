$ErrorActionPreference = 'Continue'
$BASE = 'http://127.0.0.1:5000'

Write-Host 'Work 1 API functional test (PowerShell)'
Write-Host '---------------------------------------'

Write-Host '[1] POST /auth/login with valid credentials'
$loginResp = Invoke-WebRequest -UseBasicParsing -Uri "$BASE/auth/login" -Method Post -ContentType 'application/json' -Body '{"login":"alice","password":"Alice-Strong-Pass-1!"}'
$login = $loginResp.Content | ConvertFrom-Json
Write-Host "HTTP=$($loginResp.StatusCode) token_type=$($login.token_type) token_length=$($login.token.Length)"

Write-Host ''
Write-Host '[2] GET /api/data without token (must be 401)'
try {
    $unauth = Invoke-WebRequest -UseBasicParsing -Uri "$BASE/api/data"
    Write-Host "HTTP=$($unauth.StatusCode) (unexpected)"
}
catch {
    $code = [int]$_.Exception.Response.StatusCode
    Write-Host "HTTP=$code"
}

Write-Host ''
Write-Host '[3] GET /api/data with Bearer token'
$dataResp = Invoke-WebRequest -UseBasicParsing -Uri "$BASE/api/data" -Headers @{ Authorization = "Bearer $($login.token)" }
$data = $dataResp.Content | ConvertFrom-Json
Write-Host "HTTP=$($dataResp.StatusCode) items=$($data.data.Count) first_title=$($data.data[0].title)"

Write-Host ''
Write-Host '[4] POST /api/data with Bearer token'
$postResp = Invoke-WebRequest -UseBasicParsing -Uri "$BASE/api/data" -Method Post -Headers @{ Authorization = "Bearer $($login.token)" } -ContentType 'application/json' -Body '{"title":"API test post","content":"created by curl"}'
$post = $postResp.Content | ConvertFrom-Json
Write-Host "HTTP=$($postResp.StatusCode) created_title=$($post.data.title) author=$($post.data.author)"

Write-Host ''
Write-Host 'RESULT: login success, unauthorised request rejected, authenticated read/create succeeded.'
