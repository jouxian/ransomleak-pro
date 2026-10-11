# RansomLeak Pro v9.0.0 — Professional Architecture

RansomLeak Pro v9.0.0 is a major architecture and maintainability release. It preserves the read-only forensic archive inventory workflow while restructuring the project for testing, packaging, CI, and long-term maintenance.

### Highlights

- Replaced the single-file architecture with a modular `src/` package layout
- Separated filesystem traversal, archive detection, archive readers, scan orchestration, report generation, and GUI code
- Split ZIP, RAR, and 7Z readers into format-specific modules
- Replaced the Tkinter interface with a modern PySide6/Qt desktop interface
- Added standard `pyproject.toml` packaging and the `ransomleak-pro` command
- Added unit tests for utilities, archive detection, safety limits, nested ZIP scanning, report generation, and version consistency
- Added GitHub Actions CI for Windows and Linux on Python 3.11 and 3.13
- Added MIT License, Security Policy, changelog, and repository hygiene files
- Added version-consistency testing to prevent release/package/UI version drift
- Preserved atomic TXT report generation with SHA-256 data digest
- Preserved bounded nested reads, archive-entry limits, recursion limits, compression-ratio screening, and archive-member risk checks

### Installation

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

### Run

```bash
ransomleak-pro
```

or:

```bash
python -m ransomleak_pro
```

### Important

RAR inspection may require an external backend such as UnRAR or 7-Zip depending on system configuration.

Use RansomLeak Pro only on systems and datasets that you own or are explicitly authorized to inspect.
