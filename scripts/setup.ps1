# Windows setup: create the project venv (.venv) and install requirements.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$req  = Join-Path $root "requirements.txt"

Write-Host "==> Creating virtual environment at $venv"
python -m venv $venv
if ($LASTEXITCODE -ne 0) {
    throw "python -m venv failed. Is Python 3.10+ installed and on PATH?"
}

$py = Join-Path $venv "Scripts\python.exe"

Write-Host "==> Upgrading pip"
& $py -m pip install --upgrade pip

Write-Host "==> Installing requirements from $req"
& $py -m pip install -r $req
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

Write-Host ""
Write-Host "Done. Activate with:"
Write-Host "  .\.venv\Scripts\Activate.ps1"
Write-Host "Then run:"
Write-Host "  python -m src.cli discover --domain example.com"
