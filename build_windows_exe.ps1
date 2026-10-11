$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "============================================================"
Write-Host "RansomLeak Pro v9.0.0 - Windows EXE Builder"
Write-Host "============================================================"
Write-Host ""

python --version

Write-Host ""
Write-Host "[1/4] Installing build dependencies..."
python -m pip install --upgrade pip setuptools wheel
python -m pip install ".[dev]" "pyinstaller>=6.10"

Write-Host ""
Write-Host "[2/4] Running tests..."
python -m pytest

Write-Host ""
Write-Host "[3/4] Building standalone Windows executable..."
python -m PyInstaller --noconfirm --clean RansomLeakPro.spec

$exe = Join-Path $PSScriptRoot "dist\RansomLeakPro.exe"
if (-not (Test-Path $exe)) {
    throw "Build completed without producing dist\RansomLeakPro.exe"
}

Write-Host ""
Write-Host "[4/4] SHA-256:"
Get-FileHash $exe -Algorithm SHA256 | Format-List

Write-Host ""
Write-Host "============================================================"
Write-Host "BUILD SUCCESSFUL"
Write-Host "EXE: $exe"
Write-Host "============================================================"
