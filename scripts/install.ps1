# subtake — install like a program (Windows).
# Double-click scripts\install.bat, or run:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 [-BuildExe] [-Shortcut]
#
# What it does:
#   1. Creates/uses the project venv (.venv)
#   2. Installs the package as a program: `subtake` and `subtake-gui` commands
#      work from any terminal (with the venv activated)
#   3. -BuildExe  → also builds a standalone dist\subtake.exe (runs without Python)
#   4. -Shortcut  → creates a "subtake GUI" shortcut on the Desktop
param(
    [switch]$BuildExe,
    [switch]$Shortcut
)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$py   = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $py)) {
    Write-Host "==> Creating virtual environment at $venv"
    python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "python -m venv failed. Is Python 3.10+ on PATH?" }
}

Write-Host "==> Upgrading pip"
& $py -m pip install --upgrade pip -q

Write-Host "==> Installing subtake as a program (subtake / subtake-gui commands)"
& $py -m pip install -e $root
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

if ($BuildExe) {
    Write-Host "==> Installing PyInstaller (project venv only)"
    & $py -m pip install pyinstaller -q
    Write-Host "==> Building standalone dist\subtake.exe (windowed — no cmd window; this takes a couple of minutes)"
    Push-Location $root
    try {
        & $py -m PyInstaller --onefile --name subtake --windowed `
            --icon "$root\assets\logo.ico" `
            --paths $root `
            --add-data "config;config" `
            --add-data "assets;assets" `
            --add-data "data\wordlists;data\wordlists" `
            --add-data "src\reporting\templates;src\reporting\templates" `
            launcher.py
        if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed." }
    } finally {
        Pop-Location
    }
    Write-Host "    Built: $root\dist\subtake.exe (double-click = GUI; CLI from a terminal keeps its output via attach-console)"
}

if ($Shortcut) {
    $ws      = New-Object -ComObject WScript.Shell
    $desktop = [Environment]::GetFolderPath("Desktop")
    $lnk     = $ws.CreateShortcut("$desktop\subtake GUI.lnk")
    if ($BuildExe) {
        $lnk.TargetPath = "$root\dist\subtake.exe"
        $lnk.WorkingDirectory = "$root\dist"
    } else {
        $lnk.TargetPath = $py
        $lnk.Arguments  = "-m src.gui"
        $lnk.WorkingDirectory = $root
    }
    $lnk.Save()
    Write-Host "==> Desktop shortcut created: subtake GUI"
}

Write-Host ""
Write-Host "Installed successfully. How to use:"
Write-Host "  subtake scan --domain example.com --format all   (CLI, after: .\.venv\Scripts\Activate.ps1)"
Write-Host "  subtake-gui                                      (point-and-click GUI)"
if ($BuildExe) { Write-Host "  dist\subtake.exe                                 (standalone — no Python needed)" }
