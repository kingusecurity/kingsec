# rebuild-frontend.ps1
# Run this from the root of your KingSec project (the folder containing both
# "frontend" and "src").
#
# What it does:
#   1. Builds the frontend (npm run build)
#   2. Clears out the old static/ folder in the backend
#   3. Copies the fresh build into it
#   4. Optionally starts the server (-Serve)
#
# Usage:
#   .\rebuild-frontend.ps1            # just build + copy
#   .\rebuild-frontend.ps1 -Serve     # build + copy, then run "python -m kingsec"

param(
    [switch]$Serve
)

$ErrorActionPreference = "Stop"

# Sanity check: make sure this is being run from the right place
if (-not (Test-Path "frontend") -or -not (Test-Path "src\kingsec")) {
    Write-Host "This doesn't look like the KingSec project root." -ForegroundColor Red
    Write-Host "Run this script from the folder that contains both 'frontend' and 'src'." -ForegroundColor Red
    exit 1
}

Write-Host "==> Building frontend..." -ForegroundColor Cyan
Push-Location frontend
npm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Frontend build failed. Stopping." -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location

$staticPath = "src\kingsec\adapters\inbound\web\static"

Write-Host "==> Clearing old static files..." -ForegroundColor Cyan
if (Test-Path $staticPath) {
    Remove-Item -Recurse -Force $staticPath
}
New-Item -ItemType Directory -Force $staticPath | Out-Null

Write-Host "==> Copying new build into static folder..." -ForegroundColor Cyan
Copy-Item -Path "frontend\dist\*" -Destination $staticPath -Recurse

# Quick confirmation
if (Test-Path "$staticPath\index.html") {
    Write-Host "==> Done. index.html and assets are in place." -ForegroundColor Green
} else {
    Write-Host "==> Something is wrong - index.html was not found after copying." -ForegroundColor Red
    exit 1
}

if ($Serve) {
    Write-Host "==> Starting server (python -m kingsec)..." -ForegroundColor Cyan
    python -m kingsec
}
