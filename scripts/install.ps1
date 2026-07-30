# KingSec Installer Script for Windows
# Supports Windows 10/11 and Windows Server 2019+
# Usage: powershell -ExecutionPolicy Bypass -File scripts\install.ps1

param(
    [string]$InstallDir = "$env:LOCALAPPDATA\KingSec",
    [switch]$SkipDocker,
    [switch]$DevMode
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# --- Helpers ---
function Write-Step($msg) { Write-Host "`n>> $msg" -ForegroundColor Cyan }
function Write-OK($msg) { Write-Host "   [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "   [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "   [FAIL] $msg" -ForegroundColor Red }

function Test-Command($cmd) {
    try { Get-Command $cmd -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

# --- Banner ---
Write-Host @"

  _  __          __  __
 | |/ /___ _   _|  \/  | ___  _ __ ___   ___  __ _| |_ ___
 | ' // _ \ | | | |\/| |/ _ \| '_ ` _ \ / _ \/ _` | __/ _ \
 | . \  __/ |_| | |  | | (_) | | | | | |  __/ (_| | ||  __/
 |_|\_\___|\__, |_|  |_|\___/|_| |_| |_|\___|\__,_|\__\___|
           |___/
  Security Assessment Platform — Installer

"@ -ForegroundColor DarkCyan

# --- Step 1: Check Python ---
Write-Step "Checking Python..."
if (Test-Command "python") {
    $pyVer = python --version 2>&1
    Write-OK "Found: $pyVer"
    $verMatch = [regex]::Match($pyVer, '(\d+)\.(\d+)')
    if ([int]$verMatch.Groups[1].Value -lt 3 -or ([int]$verMatch.Groups[1].Value -eq 3 -and [int]$verMatch.Groups[2].Value -lt 12)) {
        Write-Fail "Python 3.12+ required. Found: $pyVer"
        exit 1
    }
} else {
    Write-Fail "Python not found. Install Python 3.12+ from https://python.org"
    exit 1
}

# --- Step 2: Check Git ---
Write-Step "Checking Git..."
if (Test-Command "git") {
    $gitVer = git --version
    Write-OK "Found: $gitVer"
} else {
    Write-Warn "Git not found. Some features may be limited."
}

# --- Step 3: Create directories ---
Write-Step "Creating directories..."
$dirs = @($InstallDir, "$InstallDir\logs", "$InstallDir\backups", "$InstallDir\plugins", "$InstallDir\telemetry")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-OK "Directories created at $InstallDir"

# --- Step 4: Create .env if missing ---
Write-Step "Checking configuration..."
$envFile = "$InstallDir\.env"
if (-not (Test-Path $envFile)) {
    $jwtSecret = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $apiPepper = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $encKey = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

    $envContent = @"
# KingSec Environment Configuration
KINGSEC_ENVIRONMENT=production
KINGSEC_DEBUG=false
KINGSEC_LOGGING__LEVEL=INFO

# Security (auto-generated secrets — do not share)
KINGSEC_JWT__SECRET_KEY=$jwtSecret
KINGSEC_SECRETS__API_KEY_PEPPER=$apiPepper
KINGSEC_SECRETS__ENCRYPTION_KEY=$encKey

# Server
KINGSEC_SERVER__HOST=127.0.0.1
KINGSEC_SERVER__PORT=8765

# Storage
KINGSEC_STORAGE__DATA_DIR=$InstallDir
"@
    Set-Content -Path $envFile -Value $envContent
    Write-OK "Created .env with auto-generated secrets"
} else {
    Write-OK ".env already exists"
}

# --- Step 5: Install Python package ---
Write-Step "Installing KingSec package..."
if ($DevMode) {
    pip install -e ".[dev]" --quiet
} else {
    pip install . --quiet
}
if ($LASTEXITCODE -ne 0) { Write-Fail "pip install failed"; exit 1 }
Write-OK "KingSec package installed"

# --- Step 6: Run migrations ---
Write-Step "Running database migrations..."
$env:KINGSEC_STORAGE__DATA_DIR = $InstallDir
kingsec-migrate 2>&1 | Out-Null
Write-OK "Database migrations complete"

# --- Step 7: Docker (optional) ---
if (-not $SkipDocker) {
    Write-Step "Checking Docker..."
    if (Test-Command "docker") {
        Write-OK "Docker available"
        Write-Host "   Run 'docker compose up -d' to start with Docker"
    } else {
        Write-Warn "Docker not found. Install Docker Desktop for containerized deployment."
    }
}

# --- Step 8: Create Start shortcut ---
Write-Step "Creating start script..."
$startScript = @"
@echo off
echo Starting KingSec...
cd /d "%~dp0"
set KINGSEC_STORAGE__DATA_DIR=$InstallDir
python -m kingsec
"@
Set-Content -Path "$InstallDir\start.cmd" -Value $startScript
Write-OK "Created start.cmd"

# --- Done ---
Write-Host @"

=====================================
  Installation Complete!
=====================================

  Location:  $InstallDir
  Config:    $InstallDir\.env
  Start:     $InstallDir\start.cmd
  Or run:    python -m kingsec

  Default: http://127.0.0.1:8765
  Health:  http://127.0.0.1:8765/api/v1/health

"@ -ForegroundColor Green
