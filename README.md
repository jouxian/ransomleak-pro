# RansomLeak Pro

**RansomLeak Pro v8.1** is a read-only forensic archive inventory tool designed for authorized analysis of local datasets.

It performs deep inspection of files and archives without extracting archives to disk, modifying source files, uploading data, or transmitting scanned content.

## Features

- High-performance single-pass filesystem traversal
- Recursive ZIP, RAR, and 7Z archive inspection
- Deep nested archive discovery
- Hidden archive detection using magic bytes
- File extension and magic-byte mismatch detection
- Password and encryption detection
- Split-volume archive awareness
- Path traversal detection
- Absolute-path detection
- Symbolic-link detection
- Suspicious archive-member detection
- Compression-ratio screening
- Bounded nested archive reads
- Archive entry safety limits
- Recursive depth limits
- Normal, Deep, and Ultra Deep scan modes
- Real-time scan statistics
- Live diagnostic logging
- Scan cancellation support
- Atomic forensic report creation
- SHA-256 digest for report data
- Dark-mode Tkinter interface
- Fully local and offline processing

## Privacy

RansomLeak Pro is designed for local forensic analysis.

The application:

- Does not upload scanned files
- Does not transmit scanned content
- Does not modify source files
- Does not extract archives to disk during analysis
- Processes datasets locally on the user's system

## Authorized Use

This software is intended for legitimate forensic analysis, incident response, archival inspection, research, and other authorized activities.

Only use RansomLeak Pro on systems and datasets that you own or are explicitly authorized to inspect.

## Requirements

- Python 3
- Tkinter
- `rarfile` for RAR support
- `py7zr` for 7Z support

Install the optional Python dependencies with:

```bash
pip install rarfile py7zr
```

RAR processing may also require a compatible external backend such as **UnRAR** or **7-Zip**.

ZIP support is provided by Python's built-in `zipfile` module.

## Running

Clone or download the repository, then run:

```bash
python ransomleak_pro.py
```

The graphical interface will open.

Select a local dataset directory, configure the scan options, and start the forensic inventory scan.

## Scan Modes

RansomLeak Pro supports multiple archive recursion levels:

- **Normal** — Standard recursive archive inspection
- **Deep** — Extended nested archive inspection
- **Ultra Deep** — Maximum configured recursive depth

Deeper scan modes may require more memory and processing time.

## Archive Formats

### ZIP

ZIP support is built into Python and supports recursive archive inspection, nested archive discovery, password detection, and archive-member risk analysis.

### RAR

RAR support is provided through the `rarfile` Python package.

A compatible external extraction backend may be required depending on the operating system and configuration.

### 7Z

7Z support is provided through the `py7zr` package.

Solid 7Z archives may be inventoried at the metadata level without recursively reading nested archive contents.

## Archive Safety Controls

RansomLeak Pro includes safeguards for malformed, suspicious, or resource-intensive archives.

These controls include:

- Maximum nested archive size
- Total nested-read budget
- Maximum archive entry count
- Compression-ratio screening
- Recursive archive depth limits
- Path traversal detection
- Absolute-path detection
- Symbolic-link detection
- Suspicious member-name detection
- Extension and magic-byte mismatch detection
- Password-protected archive detection

These safeguards reduce the risk of excessive memory use and unsafe recursive archive processing.

## Forensic Reporting

RansomLeak Pro can generate a TXT forensic inventory report containing scan metadata, discovered files, archive contents, warnings, and analysis results.

Reports are written atomically to reduce the risk of incomplete report files.

Each completed report also includes a **SHA-256 digest** of the report data to assist with integrity verification.

## Read-Only Design

RansomLeak Pro is designed as a read-only inventory utility.

During normal operation, it does not:

- Delete files
- Rename files
- Modify scanned files
- Extract archive contents to the scanned directory
- Upload data to remote services

## Limitations

RansomLeak Pro is an archive inventory and metadata inspection utility.

It is not:

- A malware sandbox
- An antivirus engine
- A complete archive integrity verifier
- An immutable filesystem snapshot
- A process-isolated decompression sandbox
- A replacement for dedicated digital forensic suites

Archive metadata parsing and codec allocations are not isolated at the operating-system level.

## Version

**RansomLeak Pro v8.1 — Hardened Forensic**

## License

No license has been selected for this project yet.
