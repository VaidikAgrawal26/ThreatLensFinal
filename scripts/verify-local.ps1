$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'

Write-Host '== ThreatLens AI local verification ==' -ForegroundColor Cyan
Write-Host 'This script installs dependencies and runs tests; use a disposable development environment.'

if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python was not found on PATH.' }
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw 'npm was not found on PATH.' }

Push-Location $backend
try {
  Write-Host "`n[1/4] Installing backend dependencies..." -ForegroundColor Cyan
  python -m pip install -r requirements.txt
  if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }
  Write-Host "`n[2/4] Running backend tests..." -ForegroundColor Cyan
  $env:PYTHONPATH = '.'
  python -m pytest -q
  if ($LASTEXITCODE -ne 0) { throw 'Backend tests failed.' }
} finally { Pop-Location }

Push-Location $frontend
try {
  Write-Host "`n[3/4] Installing exact frontend dependencies from lockfile..." -ForegroundColor Cyan
  if (-not (Test-Path 'package-lock.json')) {
    Write-Host 'No package-lock.json is present; using npm install to generate a local lockfile.' -ForegroundColor Yellow
    npm install --no-audit --no-fund
  } else {
    npm ci --no-audit --no-fund
  }
  if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
  Write-Host "`n[4/4] Building production frontend..." -ForegroundColor Cyan
  npm run build
  if ($LASTEXITCODE -ne 0) { throw 'Frontend production build failed.' }
} finally { Pop-Location }

Write-Host "`nStatic/build checks passed. For full integration, start the backend and frontend, then follow docs/TESTING.md for role/API and browser workflows." -ForegroundColor Green
