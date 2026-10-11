<div align="center">

# RansomLeak Pro

**Read-only forensic archive inventory and deep inspection for authorized local datasets.**

[![Release](https://img.shields.io/github/v/release/jouxian/ransomleak-pro?sort=semver)](https://github.com/jouxian/ransomleak-pro/releases/latest)
[![CI](https://github.com/jouxian/ransomleak-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/jouxian/ransomleak-pro/actions/workflows/ci.yml)
[![Windows EXE](https://github.com/jouxian/ransomleak-pro/actions/workflows/windows-exe.yml/badge.svg)](https://github.com/jouxian/ransomleak-pro/actions/workflows/windows-exe.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/github/license/jouxian/ransomleak-pro)](LICENSE)
[![Downloads](https://img.shields.io/github/downloads/jouxian/ransomleak-pro/total)](https://github.com/jouxian/ransomleak-pro/releases)

[**Download Windows EXE**](https://github.com/jouxian/ransomleak-pro/releases/download/v9.0.0/RansomLeakPro.exe) · [Latest Release](https://github.com/jouxian/ransomleak-pro/releases/latest) · [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

---

## Overview

**RansomLeak Pro v9.0.0** is a local, read-only forensic inventory application for inspecting files and archives without modifying the source dataset.

It is designed for forensic triage, incident-response support, archival inspection, evidence inventory, and research workflows where analysts need visibility into ordinary files, nested archives, suspicious archive structures, and archive metadata while keeping processing local.

Version 9 replaces the previous monolithic design with a modular architecture. The filesystem scanner, archive readers, detection logic, reporting layer, and desktop interface are separated into independently testable components.

> **Authorized use only.** Use RansomLeak Pro only on systems and datasets that you own or are explicitly authorized to inspect.

## Quick Start — Windows

The easiest way to use RansomLeak Pro is the standalone Windows executable.

1. Download **`RansomLeakPro.exe`** from the [v9.0.0 release](https://github.com/jouxian/ransomleak-pro/releases/tag/v9.0.0).
2. Run the executable.
3. Select the local dataset directory.
4. Choose a scan mode and start the inventory.
5. Save the forensic TXT report when the scan is complete.

**Python is not required to run the standalone Windows executable.**

Current Windows build SHA-256:

```text
2ebc167912626a7b8481a437a176359fb1649767d27f317b10cdbf1d752028d3
```

GitHub also displays a digest beside the release asset so the downloaded binary can be verified independently.

## Key Capabilities

| Area | Capabilities |
| --- | --- |
| Filesystem | High-performance single-pass traversal, directory/file counters, symlink-aware handling |
| Archive formats | ZIP, RAR, and 7Z inventory |
| Nested archives | Recursive archive discovery with configurable depth limits |
| Hidden archives | Magic-byte detection for archive content that may not match its filename |
| Validation | Extension/magic mismatch detection and malformed archive reporting |
| Archive safety | Nested-read limits, archive-entry limits, decompression-ratio screening, recursion limits |
| Member risk checks | Path traversal, absolute paths, symlinks, special entries, suspicious member names |
| Encryption | Password/encryption awareness for supported archive formats |
| Split archives | Split-volume awareness and non-first-volume handling |
| Reporting | Atomic TXT reports with SHA-256 digest of report data |
| Desktop UI | PySide6/Qt dark interface with live statistics, logs, progress, and cancellation |
| Privacy | Local processing; no file uploads and no telemetry in the application |

## Scan Modes

RansomLeak Pro provides three recursive inspection levels:

| Mode | Maximum configured depth | Intended use |
| --- | ---: | --- |
| **Normal** | 8 | Routine archive inventory |
| **Deep** | 20 | Datasets with substantial archive nesting |
| **Ultra Deep** | 32 | Maximum configured recursive inspection |

Deeper scans can consume more time and memory, especially when datasets contain large numbers of nested archives.

## Safety Controls

Archive inspection is intentionally bounded. The engine includes defensive limits designed to reduce uncontrolled resource consumption and unsafe archive traversal.

- Maximum nested archive member size
- Total nested-read budget per archive traversal context
- Maximum archive-entry count
- Maximum recursive archive depth
- Compression-ratio screening
- Path traversal detection (`..`)
- Absolute-path detection
- Symbolic-link and special-entry detection
- Extension/magic mismatch detection
- Password/encryption awareness
- Split-volume awareness
- Cancellation checks during long-running operations

These controls reduce risk; they do **not** turn the application into an OS-isolated decompression sandbox.

## Supported Archive Formats

### ZIP

ZIP support uses Python's built-in `zipfile` module and supports recursive inspection, nested archive discovery, encryption indicators, member-risk checks, and magic validation.

### RAR

RAR support uses the [`rarfile`](https://pypi.org/project/rarfile/) Python package.

Some RAR operations may require a compatible external backend such as **UnRAR** or **7-Zip**, depending on the host configuration. The portable EXE does not redistribute those third-party executables.

### 7Z

7Z support uses [`py7zr`](https://pypi.org/project/py7zr/).

Solid 7Z archives may be inventoried at the metadata level without recursively reading nested contents when safe bounded extraction of an individual member cannot be guaranteed.

## Forensic Reporting

RansomLeak Pro can generate a TXT inventory report containing scan metadata, discovered entries, archive contents, warnings, and analysis results.

Reports are written atomically: data is written to a temporary file, flushed, synchronized, and then moved into place. A **SHA-256 digest of the report data lines** is included in the report to support integrity verification.

The report is an inventory artifact, not a substitute for a cryptographically sealed evidence container or immutable forensic image.

## Privacy and Read-Only Design

RansomLeak Pro is built around local analysis.

The application does not intentionally:

- upload scanned files;
- transmit scanned content to a remote service;
- modify source files;
- rename or delete scanned files;
- extract archive contents into the scanned dataset during normal analysis.

Nested archive content may be read or decompressed **in memory** within configured safety limits when recursive inspection is enabled.

## Architecture

```text
src/ransomleak_pro/
├── __init__.py
├── __main__.py
├── config.py
├── models.py
├── utils.py
├── detection.py
├── filesystem.py
├── scanner.py
├── reporting.py
├── gui.py
└── archives/
    ├── __init__.py
    ├── common.py
    ├── zip_reader.py
    ├── rar_reader.py
    └── sevenzip_reader.py
```

The scan engine and report writer are independent of the GUI. This separation improves maintainability, automated testing, and future reuse from other interfaces.

## Install from Source

### Requirements

- Python **3.11 or newer**
- PySide6
- `rarfile`
- `py7zr`

Clone the repository:

```bash
git clone https://github.com/jouxian/ransomleak-pro.git
cd ransomleak-pro
```

Install the application:

```bash
python -m pip install .
```

Run it:

```bash
ransomleak-pro
```

Alternative launcher:

```bash
python -m ransomleak_pro
```

## Development Setup

Install the project with development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the test suite:

```bash
python -m pytest
```

Run the linter:

```bash
python -m ruff check src/ransomleak_pro tests
```

The repository includes automated CI for package installation, compilation, and tests.

## Building the Windows EXE

A PyInstaller configuration and Windows build scripts are included.

On Windows, the simplest build path is:

```text
build_windows_exe.bat
```

The script installs the required build tooling, runs the test suite, builds the standalone GUI executable, and prints its SHA-256 hash.

Successful builds are written to:

```text
dist\RansomLeakPro.exe
```

See [BUILD_WINDOWS.md](BUILD_WINDOWS.md) for additional details.

## Automated Windows Builds

The repository includes a GitHub Actions workflow for Windows EXE builds. Tagged builds can compile the executable and attach the Windows binary and checksum artifact to the corresponding GitHub Release.

Workflow file:

```text
.github/workflows/windows-exe.yml
```

## Project Structure

```text
.github/workflows/   Automated CI and Windows EXE build workflows
src/                 Application source package
tests/               Automated test suite
BUILD_WINDOWS.md      Windows build instructions
CHANGELOG.md          Version history
LICENSE               MIT License
pyproject.toml        Package/build configuration
RansomLeakPro.spec    PyInstaller configuration
SECURITY.md           Vulnerability reporting policy
```

## Known Limitations

RansomLeak Pro is an archive inventory and metadata inspection utility. It is **not**:

- a malware sandbox;
- an antivirus engine;
- a complete archive integrity verifier;
- an immutable filesystem snapshot;
- a process- or OS-isolated decompression sandbox;
- a replacement for a full digital-forensics suite.

Archive metadata parsing and codec allocations may still occur inside the application process. Extremely large, malformed, or adversarial files should be handled in an appropriately isolated analysis environment.

## Version

**RansomLeak Pro v9.0.0 — Professional Architecture**

See [CHANGELOG.md](CHANGELOG.md) and [RELEASE_NOTES_v9.0.0.md](RELEASE_NOTES_v9.0.0.md) for release details.

## Security

Please review [SECURITY.md](SECURITY.md) before reporting a vulnerability or security-sensitive issue.

## License

RansomLeak Pro is released under the **MIT License**. See [LICENSE](LICENSE).

---

<div align="center">

**RansomLeak Pro** — local, read-only forensic archive inventory.

[Download](https://github.com/jouxian/ransomleak-pro/releases/latest) · [Releases](https://github.com/jouxian/ransomleak-pro/releases) · [Security](SECURITY.md) · [License](LICENSE)

</div>
