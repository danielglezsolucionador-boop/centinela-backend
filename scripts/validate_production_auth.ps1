param(
  [string]$BackendUrl = "https://centinela-backend.vercel.app"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:ADMIN_PASSWORD)) {
  Write-Host "ADMIN_PASSWORD: missing"
  exit 2
}

$AdminUsername = if ([string]::IsNullOrWhiteSpace($env:ADMIN_USERNAME)) { "admin" } else { $env:ADMIN_USERNAME }
$ProtectedEndpoints = @(
  "/api/v1/auth/me",
  "/api/v1/incidents",
  "/api/v1/policy/all",
  "/api/v1/agents/stats",
  "/api/v1/resilience/degraded-runtime",
  "/api/v1/governance/runtime-trust"
)

function ConvertFrom-JsonSafe {
  param([string]$Content)
  if ([string]::IsNullOrWhiteSpace($Content)) { return $null }
  try { return $Content | ConvertFrom-Json } catch { return $null }
}

function Read-ErrorResponseContent {
  param($Response)
  if ($null -eq $Response) { return "" }
  try {
    $stream = $Response.GetResponseStream()
    if ($null -eq $stream) { return "" }
    $reader = New-Object System.IO.StreamReader($stream)
    return $reader.ReadToEnd()
  } catch {
    return ""
  }
}

function Invoke-Api {
  param(
    [string]$Method,
    [string]$Path,
    [hashtable]$Headers = @{},
    $Body = $null
  )
  $uri = if ($Path.StartsWith("http")) { $Path } else { "$BackendUrl$Path" }
  $params = @{
    Uri = $uri
    Method = $Method
    UseBasicParsing = $true
    Headers = $Headers
  }
  if ($null -ne $Body) {
    $params.ContentType = "application/json"
    $params.Body = ($Body | ConvertTo-Json -Depth 20)
  }
  try {
    $response = Invoke-WebRequest @params -ErrorAction Stop
    return [pscustomobject]@{
      StatusCode = [int]$response.StatusCode
      Json = ConvertFrom-JsonSafe $response.Content
      Content = $response.Content
    }
  } catch {
    $response = $_.Exception.Response
    $content = Read-ErrorResponseContent $response
    $statusCode = if ($response) { [int]$response.StatusCode } else { 0 }
    return [pscustomobject]@{
      StatusCode = $statusCode
      Json = ConvertFrom-JsonSafe $content
      Content = $content
    }
  }
}

function Assert-Status {
  param(
    [string]$Label,
    $Response,
    [int[]]$Expected
  )
  if ($Expected -notcontains $Response.StatusCode) {
    Write-Host "${Label}: FAIL HTTP $($Response.StatusCode)"
    exit 1
  }
  Write-Host "${Label}: PASS HTTP $($Response.StatusCode)"
}

function Mask-Token {
  param([string]$Token)
  if ([string]::IsNullOrWhiteSpace($Token)) { return "<missing>" }
  if ($Token.Length -le 18) { return "***masked***" }
  return "$($Token.Substring(0, 8))...$($Token.Substring($Token.Length - 6))"
}

$health = Invoke-Api -Method "GET" -Path "/api/v1/health"
Assert-Status "HEALTH" $health @(200)

$provenance = Invoke-Api -Method "GET" -Path "/api/v1/provenance"
Assert-Status "PROVENANCE" $provenance @(200)

$incomplete = Invoke-Api -Method "POST" -Path "/api/v1/auth/login" -Body @{ username = $AdminUsername }
Assert-Status "PAYLOAD_INCOMPLETE" $incomplete @(400)

$wrong = Invoke-Api -Method "POST" -Path "/api/v1/auth/login" -Body @{
  username = $AdminUsername
  password = "invalid-password-for-auth-validation"
}
Assert-Status "LOGIN_INCORRECT" $wrong @(401)

foreach ($endpoint in $ProtectedEndpoints) {
  $withoutToken = Invoke-Api -Method "GET" -Path $endpoint
  Assert-Status "WITHOUT_TOKEN $endpoint" $withoutToken @(401)
}

$invalidToken = Invoke-Api -Method "GET" -Path "/api/v1/auth/me" -Headers @{
  Authorization = "Bearer invalid-token"
}
Assert-Status "INVALID_TOKEN /api/v1/auth/me" $invalidToken @(401)

$login = Invoke-Api -Method "POST" -Path "/api/v1/auth/login" -Body @{
  username = $AdminUsername
  password = $env:ADMIN_PASSWORD
}
Assert-Status "LOGIN_CORRECT" $login @(200)

$token = $login.Json.access_token
if ([string]::IsNullOrWhiteSpace($token) -and $login.Json.token) {
  $token = $login.Json.token
}
if ([string]::IsNullOrWhiteSpace($token)) {
  Write-Host "TOKEN: FAIL missing"
  exit 1
}
Write-Host "TOKEN_MASKED: $(Mask-Token $token)"

$authHeaders = @{ Authorization = "Bearer $token" }
foreach ($endpoint in $ProtectedEndpoints) {
  $withToken = Invoke-Api -Method "GET" -Path $endpoint -Headers $authHeaders
  Assert-Status "WITH_TOKEN $endpoint" $withToken @(200)
}

Write-Host "PRODUCTION_AUTH_VALIDATION: PASS"
exit 0
