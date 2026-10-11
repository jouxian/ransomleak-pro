# Changelog

## v9.0.0

- Refactored the monolithic application into a `src/` package architecture.
- Separated scanning, archive inspection, reporting, configuration, models, and GUI concerns.
- Replaced the Tkinter interface with a PySide6/Qt desktop interface.
- Added standard `pyproject.toml` packaging and a console entry point.
- Added unit tests for formatting, detection, safety limits, scanning, and reporting.
- Added GitHub Actions CI for Windows and Linux.
- Added Ruff linting configuration.
- Added MIT license.
- Synchronized the application version across code, package metadata, and UI.
- Preserved read-only archive inspection and atomic forensic reporting behavior from v8.1.x.
