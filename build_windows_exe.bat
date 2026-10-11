@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo RansomLeak Pro v9.0.0 - Windows EXE Builder
echo ============================================================
echo.

python --version
if errorlevel 1 goto :fail

echo.
echo [1/4] Installing build dependencies...
python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 goto :fail
python -m pip install ".[dev]" "pyinstaller>=6.10"
if errorlevel 1 goto :fail

echo.
echo [2/4] Running tests...
python -m pytest
if errorlevel 1 goto :fail

echo.
echo [3/4] Building standalone Windows executable...
python -m PyInstaller --noconfirm --clean RansomLeakPro.spec
if errorlevel 1 goto :fail

if not exist "dist\RansomLeakPro.exe" goto :fail

echo.
echo [4/4] SHA-256:
certutil -hashfile "dist\RansomLeakPro.exe" SHA256

echo.
echo ============================================================
echo BUILD SUCCESSFUL
echo.
echo EXE:
echo %CD%\dist\RansomLeakPro.exe
echo ============================================================
echo.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo BUILD FAILED
echo Review the error messages above.
echo ============================================================
echo.
pause
exit /b 1
