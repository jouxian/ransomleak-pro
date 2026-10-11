# RansomLeak Pro

**RansomLeak Pro v9.0.0** is a read-only forensic archive inventory application for authorized local datasets.

Version 9 introduces a professional project architecture: the scan engine, archive readers, reporting layer, and desktop interface are separated into testable modules. The desktop interface now uses **PySide6/Qt** instead of a monolithic Tkinter application.

## Highlights

- High-performance single-pass filesystem traversal
- Recursive ZIP, RAR, and 7Z inspection
- Deep nested archive discovery
- Hidden archive detection through magic bytes
- Extension / magic mismatch detection
- Bounded nested reads and decompression-ratio screening
- Path traversal, absolute-path, symlink, and special-entry detection
- Password/encryption and split-volume awareness
- Atomic TXT forensic reports with SHA-256 data digest
- Normal, Deep, and Ultra Deep scan modes
- Modern PySide6 dark desktop interface
- Cancellation-aware background scanning and report generation
- Unit tests and GitHub Actions CI
- Standard `pyproject.toml` packaging
- MIT License

## Architecture

```text
src/ransomleak_pro/
├── config.py       # version, limits, and application configuration
├── models.py       # dataclasses and shared types
├── utils.py        # formatting and sanitization helpers
├── detection.py    # magic-byte and archive-member risk detection
├── filesystem.py   # read-only filesystem traversal
├── archives/       # format-specific ZIP/RAR/7Z readers and shared limits
├── scanner.py      # GUI-independent forensic scan engine
├── reporting.py    # atomic report writer and SHA-256 digest
├── gui.py          # PySide6 desktop interface
└── __main__.py     # application entry point
```

The core scanner and report writer do not depend on the GUI, which makes them easier to test, reuse, and maintain.

## Requirements

- Python 3.11 or newer
- PySide6
- `rarfile`
- `py7zr`

RAR inspection may also require a compatible external backend such as **UnRAR** or **7-Zip** depending on the system configuration.

## Installation

Clone the repository and install it in editable mode:

```bash
python -m pip install -e .
```

For development tools:

```bash
python -m pip install -e ".[dev]"
```

## Running

After installation:

```bash
ransomleak-pro
```

or:

```bash
python -m ransomleak_pro
```

The root-level `run_ransomleak_pro.py` file is also included as a convenience launcher for source checkouts.

## Tests

Run the unit tests with:

```bash
python -m pytest
```

Run the linter with:

```bash
python -m ruff check src/ransomleak_pro tests
```

GitHub Actions runs package installation, compilation, and unit tests on Windows and Linux for supported Python versions.

## Privacy and Safety

RansomLeak Pro is designed for local, read-only analysis. It does not upload scanned files, transmit scanned content, modify source files, or extract archive contents into the scanned dataset during normal analysis.

Use this software only on systems and datasets that you own or are explicitly authorized to inspect.

## Limitations

RansomLeak Pro is an archive inventory and metadata inspection utility. It is not a malware sandbox, antivirus engine, complete archive integrity verifier, immutable filesystem snapshot, or OS-isolated decompression environment.

Solid 7Z archives may be inventoried without recursively reading nested contents. Archive metadata parsing and codec allocations are not process-isolated.

## Version

**v9.0.0 — Professional Architecture**

## License

Released under the **MIT License**. See `LICENSE`.


## Windows Executable

A standalone Windows GUI executable can be produced with the included build configuration.

On Windows, run:

```text
build_windows_exe.bat
```

After the tests and build complete, the portable application is created at:

```text
dist\RansomLeakPro.exe
```

Users of the resulting EXE do not need to install Python. See [`BUILD_WINDOWS.md`](BUILD_WINDOWS.md) for details.

Tagged builds can also be compiled automatically by the included GitHub Actions Windows workflow and attached to the corresponding GitHub Release.
