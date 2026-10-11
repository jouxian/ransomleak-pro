# Building the Windows EXE

RansomLeak Pro can be packaged as a standalone Windows GUI executable with PyInstaller.

## Easiest method

On Windows, double-click:

```text
build_windows_exe.bat
```

The script will:

1. Install the build dependencies.
2. Run the unit tests.
3. Build a single-file, windowed executable.
4. Print the SHA-256 hash.

The finished application will be:

```text
dist\RansomLeakPro.exe
```

The executable bundles Python, PySide6, `py7zr`, and the Python `rarfile` package, so users do not need to install Python to launch the GUI.

## RAR note

The `rarfile` Python package can require an external RAR backend such as UnRAR or 7-Zip for some RAR operations. The standalone EXE does not redistribute those third-party executables.

## PowerShell method

```powershell
.\build_windows_exe.ps1
```

If script execution is restricted by local PowerShell policy, use the `.bat` builder instead.

## GitHub Actions

The workflow `.github/workflows/windows-exe.yml` builds and tests the Windows executable automatically. Tag builds also attach `RansomLeakPro.exe` and its SHA-256 file to the matching GitHub Release.
