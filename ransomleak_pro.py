#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RANSOMLEAK PRO v8.1
DEEP FORENSIC ARCHIVE INVENTORY
================================

Read-only forensic inventory utility for authorized local datasets.

Core capabilities
-----------------
- High-performance single-pass filesystem traversal
- Recursive ZIP / RAR / 7Z inspection
- Deep nested archive discovery
- Hidden archive detection through magic bytes
- Extension / magic mismatch detection
- Bounded nested reads / decompression-ratio screening
- Path traversal and absolute-path detection
- Symlink detection
- Password/encryption detection
- Split-volume awareness
- On-disk size kept separate from archive-member sizes
- Atomic report creation
- SHA-256 report data digest
- Responsive dark-mode Tkinter GUI
- Real-time statistics
- Cancellation support
- Deep and Ultra Deep scan modes
- 100% English interface and output

The program never extracts archives to disk, never modifies scanned files,
never uploads data, and never transmits scanned content.

Limits: archive metadata and codec allocations are not OS-isolated. Solid 7z
archives are inventoried without recursive content reads. This is a metadata
inventory, not a complete integrity check or an immutable filesystem snapshot.
"""

from __future__ import annotations

import hashlib
import unicodedata
import io
import math
import os
import queue
import re
import stat
import tempfile
import threading
import time
import traceback
import zipfile

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Generator, Iterable, Optional, Union


# ============================================================
# OPTIONAL ARCHIVE BACKENDS
# ============================================================

try:
    import rarfile  # type: ignore
    RAR_AVAILABLE = True
except ImportError:
    rarfile = None
    RAR_AVAILABLE = False


try:
    import py7zr  # type: ignore
    PY7ZR_AVAILABLE = True
except ImportError:
    py7zr = None
    PY7ZR_AVAILABLE = False


# ============================================================
# TKINTER
# ============================================================

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from tkinter.scrolledtext import ScrolledText
    TK_IMPORT_ERROR = None
except ImportError as exc:
    tk = None
    TK_IMPORT_ERROR = str(exc)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "RansomLeak Pro"
APP_VERSION = "v8.1 Hardened Forensic"
APP_TITLE = f"{APP_NAME} {APP_VERSION}"

REPORT_FORMAT_VERSION = 4


# -------------------- DEPTH --------------------

NORMAL_MAX_DEPTH = 8
DEEP_MAX_DEPTH = 20
ULTRA_MAX_DEPTH = 32


# -------------------- SAFETY BUDGETS --------------------

# Maximum individual nested archive member that will be read into memory.
MAX_NESTED_ARCHIVE_SIZE = 128 * 1024 * 1024

# Maximum nested bytes read while analyzing one top-level archive.
MAX_TOTAL_NESTED_READ_BYTES = 1024 * 1024 * 1024

# Maximum archive entries encountered inside one traversal context.
MAX_ARCHIVE_ENTRIES = 500_000

# Maximum accepted compression ratio for nested archive candidates.
MAX_NESTED_COMPRESSION_RATIO = 150

# Prevent runaway recursive inspection.
MAX_ARCHIVE_RECURSION_DEPTH = ULTRA_MAX_DEPTH


# -------------------- PERFORMANCE --------------------

# UI update frequency.
PROGRESS_UPDATE_EVERY_FILES = 500
STATS_UPDATE_EVERY_FILES = 1000
LOG_PREVIEW_INNER_FILES = 30

# Report save progress.
SAVE_PROGRESS_EVERY_ROWS = 20_000


# -------------------- ARCHIVE SIGNATURES --------------------

ARCHIVE_ERROR_MARKERS = (
    "[BAD",
    "[BROKEN",
    "[NOT A VALID",
    "[PASSWORD",
    "[PERMISSION",
    "[RAR BACKEND",
    "[7Z SUPPORT",
    "[NESTED",
    "[ARCHIVE",
    "[SUSPICIOUS",
    "[TOO MANY",
    "[READ BUDGET",
    "[SIZE LIMIT",
    "[MAGIC",
    "[SPLIT",
)


# ============================================================
# DATA TYPES
# ============================================================

ArchiveSource = Union[str, os.PathLike, Path, io.BytesIO]

# name, size, kind
ArchiveYield = tuple[str, int, str]


@dataclass(frozen=True)
class ScanOptions:
    root_path: Path
    deep_mode: str
    aggressive_magic: bool
    verbose: bool
    victim: str
    domain: str
    started_at: datetime
    auto_save_prompt: bool


@dataclass
class ArchiveSafetyContext:
    entries_seen: int = 0
    nested_bytes_read: int = 0
    max_entries: int = MAX_ARCHIVE_ENTRIES
    max_nested_bytes: int = MAX_TOTAL_NESTED_READ_BYTES

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.max_nested_bytes - self.nested_bytes_read)

    def can_read_nested(self, size: int) -> bool:
        return (
            0 <= size <= MAX_NESTED_ARCHIVE_SIZE
            and self.nested_bytes_read + size <= self.max_nested_bytes
        )

    def consume(self, amount: int) -> None:
        if amount < 0:
            raise ValueError("byte count must not be negative")
        # Charge actual returned bytes, including failed/oversized reads.
        self.nested_bytes_read += amount
        if self.nested_bytes_read > self.max_nested_bytes:
            raise ValueError("nested read budget exceeded")


@dataclass
class ScanCounters:
    report_rows: int = 0

    filesystem_files: int = 0
    filesystem_directories: int = 0

    real_file_entries: int = 0
    total_size_bytes: int = 0

    archives_found: int = 0
    archives_broken: int = 0
    archives_encrypted: int = 0

    nested_archives_found: int = 0
    hidden_archives_found: int = 0

    warnings: int = 0
    skipped_files: int = 0

    processed_files: int = 0

    filesystem_changed: bool = False


# ============================================================
# FORMATTING HELPERS
# ============================================================

def format_size(size_bytes: Optional[int]) -> str:
    if size_bytes is None:
        return "0 B"

    try:
        size = int(size_bytes)
    except (TypeError, ValueError):
        return "0 B"

    if size <= 0:
        return "0 B"

    units = ("B", "KB", "MB", "GB", "TB", "PB")

    exponent = min(
        int(math.floor(math.log(size, 1024))),
        len(units) - 1,
    )

    value = size / (1024 ** exponent)

    if abs(value - round(value)) < 1e-9:
        text = str(int(round(value)))
    else:
        text = f"{value:.2f}".rstrip("0").rstrip(".")

    return f"{text} {units[exponent]}"


def format_eta(seconds: Optional[float]) -> str:
    if (
        seconds is None
        or seconds < 0
        or math.isinf(seconds)
        or math.isnan(seconds)
    ):
        return "N/A"

    seconds = int(seconds)

    if seconds < 60:
        return f"{seconds}s"

    minutes, seconds = divmod(seconds, 60)

    if minutes < 60:
        return f"{minutes}m {seconds}s"

    hours, minutes = divmod(minutes, 60)

    if hours < 24:
        return f"{hours}h {minutes}m"

    days, hours = divmod(hours, 24)

    return f"{days}d {hours}h"


def safe_report_text(value: object) -> str:
    text = str(value)

    text = (
        text
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )

    return "".join(
        (f"\\u{ord(ch):04x}" if ord(ch) > 255 else f"\\x{ord(ch):02x}")
        if unicodedata.category(ch) in {"Cc", "Cs"}
        or unicodedata.bidirectional(ch) in {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
        or ch in {"\u2028", "\u2029"}
        else ch
        for ch in text
    )


def safe_filename(name: str, fallback: str = "victim") -> str:
    cleaned = re.sub(
        r'[<>:"/\\|?*\x00-\x1F]',
        "_",
        name,
    )

    cleaned = cleaned.strip(" ._")

    cleaned = cleaned[:120].rstrip(" ._") or fallback
    if cleaned.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        cleaned = "_" + cleaned
    return cleaned


def normalize_domain(domain: str) -> str:
    value = (domain or "xxxxx").strip()

    value = re.sub(
        r"^https?://",
        "",
        value,
        flags=re.IGNORECASE,
    )

    value = value.strip().strip("/")

    return value or "xxxxx"


# ============================================================
# MAGIC BYTE DETECTION
# ============================================================

def magic_to_archive_type(header: bytes) -> Optional[str]:
    if header.startswith(
        (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08",
        )
    ):
        return "zip"

    if header.startswith(b"Rar!\x1A\x07"):
        return "rar"

    if header.startswith(b"7z\xBC\xAF\x27\x1C"):
        return "7z"

    return None


def get_magic_header(
    path: Union[str, os.PathLike],
    size: int = 16,
) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(size)
    except OSError:
        return b""


def get_filelike_header(
    source: io.BytesIO,
    size: int = 16,
) -> bytes:
    try:
        position = source.tell()
    except Exception:
        position = 0

    try:
        source.seek(0)
        header = source.read(size)
        source.seek(position)
        return header
    except Exception:
        return b""


# ============================================================
# FILE / ARCHIVE DETECTION
# ============================================================

def is_nonfirst_split_volume(name: str) -> bool:
    normalized = name.lower()
    if re.search(r"\.(?:r\d{2}|z\d{2})$", normalized):
        return True

    match = re.search(
        r"\.part(\d+)\.rar$",
        normalized,
    )

    if match:
        return int(match.group(1)) > 1

    match = re.search(
        r"\.(\d{3})$",
        normalized,
    )

    if match:
        return int(match.group(1)) > 1

    return False


def looks_like_archive(name: str) -> bool:
    name = name.lower()

    if is_nonfirst_split_volume(name):
        return False

    archive_suffixes = (
        ".zip",
        ".rar",
        ".7z",
        ".zip.001",
        ".7z.001",
        ".part1.rar",
    )

    return name.endswith(archive_suffixes)


def detect_archive_type(
    path: Path,
    aggressive_magic: bool = False,
) -> Optional[str]:

    name = path.name.lower()

    if is_nonfirst_split_volume(name):
        return None

    # Fast path:
    # only inspect magic bytes for likely archives unless
    # aggressive mode is enabled.
    if aggressive_magic or looks_like_archive(name):
        header = get_magic_header(path)

        detected = magic_to_archive_type(header)

        if detected:
            return detected

        # Extension fallback.
        if name.endswith(".zip"):
            return "zip"

        if name.endswith(".rar") or name.endswith(".part1.rar"):
            return "rar"

        if name.endswith(".7z") or name.endswith(".7z.001"):
            return "7z"

    return None


# ============================================================
# ARCHIVE MEMBER RISK ANALYSIS
# ============================================================

def archive_member_risk(
    name: str,
    unix_mode: int = 0,
) -> Optional[str]:

    normalized = name.replace("\\", "/")

    parts = [
        part
        for part in normalized.split("/")
        if part not in ("", ".")
    ]

    if normalized.startswith(("/", "\\")):
        return "ABSOLUTE PATH"

    if re.match(r"^[A-Za-z]:", normalized):
        return "ABSOLUTE PATH"

    if "\x00" in name:
        return "NUL IN NAME"

    if any(part == ".." for part in parts):
        return "PATH TRAVERSAL"

    if unix_mode and stat.S_ISLNK(unix_mode):
        return "SYMLINK ENTRY"

    return None


# ============================================================
# FAST FILESYSTEM WALKER
# ============================================================

def iter_files_fast(
    root: Path,
    counters: ScanCounters,
    cancel_event: threading.Event,
    log_queue: Optional[queue.Queue] = None,
) -> Iterable[Path]:

    # Explicit stack avoids os.walk's additional abstraction overhead.
    stack = [root]

    while stack:

        if cancel_event.is_set():
            return

        current = stack.pop()

        try:
            with os.scandir(current) as entries:

                for entry in entries:

                    if cancel_event.is_set():
                        return

                    try:
                        if entry.is_symlink():
                            counters.skipped_files += 1
                            counters.warnings += 1

                            if log_queue:
                                log_queue.put(
                                    (
                                        "log",
                                        "warning",
                                        f"Skipped symbolic link: {entry.path}",
                                    )
                                )

                            continue

                        if entry.is_dir(follow_symlinks=False):
                            counters.filesystem_directories += 1
                            stack.append(Path(entry.path))
                            continue

                        if entry.is_file(follow_symlinks=False):
                            counters.filesystem_files += 1
                            yield Path(entry.path)

                    except OSError as exc:
                        counters.skipped_files += 1
                        counters.warnings += 1

                        if log_queue:
                            log_queue.put(
                                (
                                    "log",
                                    "warning",
                                    f"Filesystem entry skipped: "
                                    f"{safe_report_text(entry.path)} "
                                    f"[{safe_report_text(exc)}]",
                                )
                            )

        except OSError as exc:

            counters.warnings += 1

            if log_queue:
                log_queue.put(
                    (
                        "log",
                        "warning",
                        f"Directory access error: "
                        f"{safe_report_text(current)} "
                        f"[{safe_report_text(exc)}]",
                    )
                )


# ============================================================
# LIMITED STREAM READER
# ============================================================

def read_stream_limited(
    stream,
    limit: int,
    cancel_event: threading.Event,
    safety: Optional[ArchiveSafetyContext] = None,
) -> bytes:

    if limit < 0:
        raise ValueError("read limit must not be negative")
    if safety is not None:
        limit = min(limit, safety.remaining_bytes)
    result = bytearray()

    chunk_size = 1024 * 1024

    while True:

        if cancel_event.is_set():
            raise InterruptedError("scan cancelled")

        remaining = limit + 1 - len(result)

        if remaining <= 0:
            raise ValueError("nested member exceeded read limit")

        chunk = stream.read(
            min(chunk_size, remaining)
        )

        if not chunk:
            break

        if safety is not None:
            safety.consume(len(chunk))
        result.extend(chunk)

        if len(result) > limit:
            raise ValueError(
                "nested member exceeded read limit"
            )

    return bytes(result)


# ============================================================
# ZIP INSPECTION
# ============================================================

def extract_zip_contents(
    source: ArchiveSource,
    virtual_prefix: str = "",
    depth: int = 0,
    max_depth: int = NORMAL_MAX_DEPTH,
    safety: Optional[ArchiveSafetyContext] = None,
    cancel_event: Optional[threading.Event] = None,
    aggressive_magic: bool = False,
) -> Generator[ArchiveYield, None, None]:

    max_depth = min(max(0, max_depth), MAX_ARCHIVE_RECURSION_DEPTH)
    if depth > max_depth:
        yield ("[ARCHIVE DEPTH LIMIT - SKIPPED]", 0, "warning")
        return
    if cancel_event is not None and cancel_event.is_set():
        yield ("[SCAN CANCELLED]", 0, "warning")
        return
    if safety is None:
        safety = ArchiveSafetyContext()

    if cancel_event is None:
        cancel_event = threading.Event()

    is_path = isinstance(
        source,
        (str, os.PathLike, Path),
    )

    if is_path:

        path = Path(source)

        if magic_to_archive_type(
            get_magic_header(path)
        ) != "zip":

            yield (
                "[NOT A VALID ZIP - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = path

    else:

        if magic_to_archive_type(
            get_filelike_header(source)
        ) != "zip":

            yield (
                "[NOT A VALID NESTED ZIP - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = source

    try:

        with zipfile.ZipFile(
            open_source,
            "r",
        ) as zf:

            try:
                infos = zf.infolist()

            except RuntimeError as exc:

                message = str(exc)

                if (
                    "password" in message.lower()
                    or "encrypt" in message.lower()
                ):
                    yield (
                        "[PASSWORD PROTECTED ZIP]",
                        0,
                        "error",
                    )
                else:
                    yield (
                        f"[BROKEN ZIP] {safe_report_text(message)}",
                        0,
                        "error",
                    )

                return

            for info in infos:

                if cancel_event.is_set():
                    yield (
                        "[SCAN CANCELLED]",
                        0,
                        "warning",
                    )
                    return

                safety.entries_seen += 1

                if safety.entries_seen > safety.max_entries:
                    yield (
                        "[TOO MANY ARCHIVE ENTRIES - TRAVERSAL STOPPED]",
                        0,
                        "warning",
                    )
                    return

                if info.is_dir():
                    continue

                member_name = safe_report_text(
                    info.filename.replace("/", "\\")
                )

                full_name = (
                    f"{virtual_prefix}\\{member_name}"
                    if virtual_prefix
                    else member_name
                )

                file_size = max(
                    0,
                    int(info.file_size or 0),
                )

                yield (
                    full_name,
                    file_size,
                    "file",
                )

                unix_mode = (
                    int(info.external_attr or 0)
                    >> 16
                ) & 0xFFFF

                risk = archive_member_risk(
                    info.filename,
                    unix_mode,
                )

                if risk:

                    yield (
                        f"{full_name} "
                        f"[ARCHIVE MEMBER RISK: {risk}]",
                        0,
                        "warning",
                    )

                if info.flag_bits & 0x1:
                    yield (f"{full_name} [PASSWORD PROTECTED ZIP MEMBER]", 0, "warning")
                    continue

                if risk:
                    continue

                if depth >= max_depth:
                    continue

                candidate_by_name = looks_like_archive(
                    info.filename
                )

                # Aggressive mode allows magic inspection of
                # extensionless nested members.
                should_probe = (
                    candidate_by_name
                    or aggressive_magic
                )

                if not should_probe:
                    continue

                if is_nonfirst_split_volume(
                    info.filename
                ):

                    yield (
                        f"{full_name} "
                        "[NON-FIRST SPLIT VOLUME - SKIPPED]",
                        0,
                        "warning",
                    )

                    continue

                if info.flag_bits & 0x1:

                    yield (
                        f"{full_name} "
                        "[PASSWORD PROTECTED NESTED MEMBER]",
                        0,
                        "warning",
                    )

                    continue

                compressed_size = max(
                    0,
                    int(info.compress_size or 0),
                )

                if (
                    compressed_size > 0
                    and file_size > 0
                ):

                    ratio = (
                        file_size
                        / compressed_size
                    )

                    if ratio > MAX_NESTED_COMPRESSION_RATIO:

                        yield (
                            f"{full_name} "
                            "[SUSPICIOUS COMPRESSION RATIO - SKIPPED]",
                            0,
                            "warning",
                        )

                        continue

                if file_size > MAX_NESTED_ARCHIVE_SIZE:

                    if candidate_by_name:

                        yield (
                            f"{full_name} "
                            f"[NESTED ARCHIVE > "
                            f"{format_size(MAX_NESTED_ARCHIVE_SIZE)} "
                            f"- SKIPPED]",
                            0,
                            "warning",
                        )

                    continue

                try:

                    with zf.open(
                        info,
                        "r",
                    ) as stream:

                        if safety.remaining_bytes < 16:
                            raise ValueError("nested read budget exhausted before header probe")
                        inner_header = stream.read(16)
                        safety.consume(len(inner_header))

                except Exception as exc:

                    if candidate_by_name:

                        yield (
                            f"{full_name} "
                            f"[NESTED HEADER ERROR: "
                            f"{safe_report_text(exc)[:160]}]",
                            0,
                            "error",
                        )

                    continue

                inner_type = magic_to_archive_type(
                    inner_header
                )

                if inner_type is None:

                    if candidate_by_name:

                        yield (
                            f"{full_name} "
                            "[ARCHIVE EXTENSION/MAGIC MISMATCH]",
                            0,
                            "warning",
                        )

                    continue

                if not safety.can_read_nested(file_size):

                    yield (
                        f"{full_name} "
                        "[NESTED READ BUDGET EXCEEDED - SKIPPED]",
                        0,
                        "warning",
                    )

                    continue

                try:

                    with zf.open(
                        info,
                        "r",
                    ) as stream:

                        inner_bytes = read_stream_limited(
                            stream,
                            MAX_NESTED_ARCHIVE_SIZE,
                            cancel_event,
                            safety,
                        )

                    inner_source = io.BytesIO(
                        inner_bytes
                    )

                    yield (
                        f"{full_name} "
                        f"[NESTED ARCHIVE: "
                        f"{inner_type.upper()} | "
                        f"DEPTH {depth + 1}]",
                        0,
                        "nested",
                    )

                    if inner_type == "zip":

                        yield from extract_zip_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "rar":

                        yield from extract_rar_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "7z":

                        yield from extract_7z_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                except InterruptedError:

                    yield (
                        "[SCAN CANCELLED]",
                        0,
                        "warning",
                    )

                    return

                except ValueError as exc:
                    yield (f"{full_name} [NESTED SAFETY LIMIT: {safe_report_text(exc)}]", 0, "warning")
                    continue

                except Exception as exc:

                    yield (
                        f"{full_name} "
                        f"[NESTED INSPECTION ERROR: "
                        f"{safe_report_text(exc)[:180]}]",
                        0,
                        "error",
                    )

    except zipfile.BadZipFile as exc:

        yield (
            f"[BAD ZIP] {safe_report_text(exc)}",
            0,
            "error",
        )

    except PermissionError as exc:

        yield (
            f"[PERMISSION DENIED] "
            f"{safe_report_text(exc)}",
            0,
            "error",
        )

    except RuntimeError as exc:

        message = str(exc)

        if (
            "password" in message.lower()
            or "encrypt" in message.lower()
        ):

            yield (
                "[PASSWORD PROTECTED ZIP]",
                0,
                "error",
            )

        else:

            yield (
                f"[BROKEN ZIP] "
                f"{safe_report_text(message)}",
                0,
                "error",
            )

    except Exception as exc:

        yield (
            f"[BROKEN ZIP] "
            f"{safe_report_text(exc)}",
            0,
            "error",
        )


# ============================================================
# RAR INSPECTION
# ============================================================

def extract_rar_contents(
    source: ArchiveSource,
    virtual_prefix: str = "",
    depth: int = 0,
    max_depth: int = NORMAL_MAX_DEPTH,
    safety: Optional[ArchiveSafetyContext] = None,
    cancel_event: Optional[threading.Event] = None,
    aggressive_magic: bool = False,
) -> Generator[ArchiveYield, None, None]:

    max_depth = min(max(0, max_depth), MAX_ARCHIVE_RECURSION_DEPTH)
    if depth > max_depth:
        yield ("[ARCHIVE DEPTH LIMIT - SKIPPED]", 0, "warning")
        return
    if cancel_event is not None and cancel_event.is_set():
        yield ("[SCAN CANCELLED]", 0, "warning")
        return
    if safety is None:
        safety = ArchiveSafetyContext()

    if cancel_event is None:
        cancel_event = threading.Event()

    if not RAR_AVAILABLE or rarfile is None:

        yield (
            "[RAR SUPPORT NOT AVAILABLE - INSTALL RARFILE]",
            0,
            "error",
        )

        return

    is_path = isinstance(
        source,
        (str, os.PathLike, Path),
    )

    if is_path:

        path = Path(source)

        if magic_to_archive_type(
            get_magic_header(path)
        ) != "rar":

            yield (
                "[NOT A VALID RAR - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = path

    else:

        if magic_to_archive_type(
            get_filelike_header(source)
        ) != "rar":

            yield (
                "[NOT A VALID NESTED RAR - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = source

    try:

        with rarfile.RarFile(
            open_source
        ) as rf:

            try:

                if rf.needs_password():

                    yield (
                        "[PASSWORD PROTECTED RAR]",
                        0,
                        "warning",
                    )

            except Exception:
                pass

            for info in rf.infolist():

                if cancel_event.is_set():

                    yield (
                        "[SCAN CANCELLED]",
                        0,
                        "warning",
                    )

                    return

                safety.entries_seen += 1

                if safety.entries_seen > safety.max_entries:

                    yield (
                        "[TOO MANY ARCHIVE ENTRIES - TRAVERSAL STOPPED]",
                        0,
                        "warning",
                    )

                    return

                if info.isdir():
                    continue

                member_name = str(
                    getattr(
                        info,
                        "filename",
                        "",
                    )
                )

                safe_name = safe_report_text(
                    member_name.replace("/", "\\")
                )

                full_name = (
                    f"{virtual_prefix}\\{safe_name}"
                    if virtual_prefix
                    else safe_name
                )

                size = max(
                    0,
                    int(
                        getattr(
                            info,
                            "file_size",
                            0,
                        )
                        or 0
                    ),
                )

                yield (
                    full_name,
                    size,
                    "file",
                )

                mode = int(
                    getattr(
                        info,
                        "mode",
                        0,
                    )
                    or 0
                )

                risk = archive_member_risk(
                    member_name,
                    mode,
                )

                if risk:

                    yield (
                        f"{full_name} "
                        f"[ARCHIVE MEMBER RISK: {risk}]",
                        0,
                        "warning",
                    )

                if risk:
                    continue

                if depth >= max_depth:
                    continue

                candidate = (
                    looks_like_archive(
                        member_name
                    )
                    or aggressive_magic
                )

                if not candidate:
                    continue

                if size <= 0:
                    continue

                if size > MAX_NESTED_ARCHIVE_SIZE:

                    yield (
                        f"{full_name} "
                        "[NESTED ARCHIVE TOO LARGE - SKIPPED]",
                        0,
                        "warning",
                    )

                    continue

                compressed_size = max(0, int(getattr(info, "compress_size", 0) or 0))
                if compressed_size and size / compressed_size > MAX_NESTED_COMPRESSION_RATIO:
                    yield (f"{full_name} [SUSPICIOUS COMPRESSION RATIO - SKIPPED]", 0, "warning")
                    continue

                if not safety.can_read_nested(size):

                    yield (
                        f"{full_name} "
                        "[NESTED READ BUDGET EXCEEDED]",
                        0,
                        "warning",
                    )

                    continue

                try:

                    with rf.open(info) as stream:

                        inner_bytes = read_stream_limited(
                            stream,
                            MAX_NESTED_ARCHIVE_SIZE,
                            cancel_event,
                            safety,
                        )

                    inner_header = inner_bytes[:16]

                    inner_type = magic_to_archive_type(
                        inner_header
                    )

                    if inner_type is None:

                        if looks_like_archive(
                            member_name
                        ):

                            yield (
                                f"{full_name} "
                                "[ARCHIVE EXTENSION/MAGIC MISMATCH]",
                                0,
                                "warning",
                            )

                        continue

                    yield (
                        f"{full_name} "
                        f"[NESTED ARCHIVE: "
                        f"{inner_type.upper()} | "
                        f"DEPTH {depth + 1}]",
                        0,
                        "nested",
                    )

                    inner_source = io.BytesIO(
                        inner_bytes
                    )

                    if inner_type == "zip":

                        yield from extract_zip_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "rar":

                        yield from extract_rar_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "7z":

                        yield from extract_7z_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                except InterruptedError:

                    yield (
                        "[SCAN CANCELLED]",
                        0,
                        "warning",
                    )

                    return

                except ValueError as exc:
                    yield (f"{full_name} [NESTED SAFETY LIMIT: {safe_report_text(exc)}]", 0, "warning")
                    continue

                except Exception as exc:

                    yield (
                        f"{full_name} "
                        f"[NESTED RAR INSPECTION ERROR: "
                        f"{safe_report_text(exc)[:160]}]",
                        0,
                        "error",
                    )

    except Exception as exc:

        message = safe_report_text(exc)
        lowered = message.lower()

        if "password" in lowered or "encrypt" in lowered:

            yield (
                "[PASSWORD PROTECTED RAR]",
                0,
                "error",
            )

        elif "cannotexec" in lowered:

            yield (
                "[RAR BACKEND MISSING - INSTALL UNRAR OR 7-ZIP]",
                0,
                "error",
            )

        else:

            yield (
                f"[BROKEN RAR] {message}",
                0,
                "error",
            )


# ============================================================
# 7Z INSPECTION
# ============================================================


def read_7z_member_limited(archive, name, safety, cancel_event) -> bytes:
    """Read one safe 7z target with a bounded in-memory writer.

    Solid archives are metadata-only: reaching one member may decompress other
    members outside this writer's accounting. Backend allocations and metadata
    parsing are not a process-wide memory sandbox.
    API: https://py7zr.readthedocs.io/en/latest/advanced.html
    """
    from py7zr.io import Py7zIO, WriterFactory

    if archive_member_risk(name):
        raise ValueError("unsafe 7z member name")
    try:
        solid = archive.archiveinfo().solid
    except AssertionError:
        # py7zr 1.1.3 archiveinfo() asserts on unnamed BytesIO sources.
        # Keep this version-sensitive fallback isolated and fail closed.
        probe = getattr(archive, "_is_solid", None)
        if not callable(probe):
            raise ValueError("7z backend cannot establish whether stream is solid")
        solid = probe()
    if solid:
        raise ValueError("solid 7z: nested content skipped; metadata remains available")

    class LimitedWriter(Py7zIO):
        def __init__(self):
            self.buffer = io.BytesIO()
            self.lock = threading.RLock()

        def write(self, data):
            with self.lock:
                if cancel_event.is_set():
                    raise InterruptedError("scan cancelled")
                safety.consume(len(data))
                if self.buffer.tell() + len(data) > MAX_NESTED_ARCHIVE_SIZE:
                    raise ValueError("nested member exceeded read limit")
                return self.buffer.write(data)

        def read(self, size=None):
            with self.lock:
                return self.buffer.read(-1 if size is None else size)

        def seek(self, offset, whence=0):
            with self.lock:
                position = self.buffer.seek(offset, whence)
                if position > MAX_NESTED_ARCHIVE_SIZE:
                    raise ValueError("nested member seek exceeds limit")
                return position

        def flush(self):
            return None

        def size(self):
            with self.lock:
                return self.buffer.getbuffer().nbytes

    class SingleTargetFactory(WriterFactory):
        def __init__(self):
            self.writer = LimitedWriter()
            self.created = False
            self.lock = threading.Lock()

        def create(self, filename):
            with self.lock:
                if self.created or str(filename).replace("\\", "/") != name.replace("\\", "/"):
                    raise ValueError("unexpected or duplicate 7z output target")
                self.created = True
                return self.writer

    factory = SingleTargetFactory()
    try:
        archive.reset()
        archive.extract(targets=[name], recursive=False, factory=factory)
        if not factory.created:
            raise ValueError("7z backend returned no target content")
        return factory.writer.buffer.getvalue()
    finally:
        factory.writer.buffer.close()


def extract_7z_contents(
    source: ArchiveSource,
    virtual_prefix: str = "",
    depth: int = 0,
    max_depth: int = NORMAL_MAX_DEPTH,
    safety: Optional[ArchiveSafetyContext] = None,
    cancel_event: Optional[threading.Event] = None,
    aggressive_magic: bool = False,
) -> Generator[ArchiveYield, None, None]:

    max_depth = min(max(0, max_depth), MAX_ARCHIVE_RECURSION_DEPTH)
    if depth > max_depth:
        yield ("[ARCHIVE DEPTH LIMIT - SKIPPED]", 0, "warning")
        return
    if cancel_event is not None and cancel_event.is_set():
        yield ("[SCAN CANCELLED]", 0, "warning")
        return
    if safety is None:
        safety = ArchiveSafetyContext()

    if cancel_event is None:
        cancel_event = threading.Event()

    if not PY7ZR_AVAILABLE or py7zr is None:

        yield (
            "[7Z SUPPORT NOT AVAILABLE - INSTALL PY7ZR]",
            0,
            "error",
        )

        return

    is_path = isinstance(
        source,
        (str, os.PathLike, Path),
    )

    if is_path:

        path = Path(source)

        if magic_to_archive_type(
            get_magic_header(path)
        ) != "7z":

            yield (
                "[NOT A VALID 7Z - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = path

    else:

        if magic_to_archive_type(
            get_filelike_header(source)
        ) != "7z":

            yield (
                "[NOT A VALID NESTED 7Z - MAGIC MISMATCH]",
                0,
                "error",
            )

            return

        open_source = source

    try:

        with py7zr.SevenZipFile(
            open_source,
            "r",
        ) as archive:

            try:

                entries = archive.list()

            except Exception as exc:

                yield (
                    f"[7Z LIST ERROR] "
                    f"{safe_report_text(exc)}",
                    0,
                    "error",
                )

                return

            encrypted = archive.needs_password()
            if encrypted:
                yield ("[PASSWORD PROTECTED 7Z]", 0, "warning")

            for info in entries:

                if cancel_event.is_set():

                    yield (
                        "[SCAN CANCELLED]",
                        0,
                        "warning",
                    )

                    return

                safety.entries_seen += 1

                if safety.entries_seen > safety.max_entries:

                    yield (
                        "[TOO MANY ARCHIVE ENTRIES - TRAVERSAL STOPPED]",
                        0,
                        "warning",
                    )

                    return

                is_directory = getattr(
                    info,
                    "is_directory",
                    False,
                )

                if callable(is_directory):

                    try:
                        is_directory = is_directory()
                    except Exception:
                        is_directory = False

                if is_directory:
                    continue

                member_name = str(
                    getattr(
                        info,
                        "filename",
                        "",
                    )
                )

                safe_name = safe_report_text(
                    member_name.replace("/", "\\")
                )

                full_name = (
                    f"{virtual_prefix}\\{safe_name}"
                    if virtual_prefix
                    else safe_name
                )

                size = max(
                    0,
                    int(
                        getattr(
                            info,
                            "uncompressed",
                            0,
                        )
                        or 0
                    ),
                )

                yield (
                    full_name,
                    size,
                    "file",
                )

                risk = archive_member_risk(
                    member_name
                )
                if getattr(info, "is_symlink", False):
                    risk = "SYMLINK ENTRY"
                elif hasattr(info, "is_file") and not info.is_file:
                    risk = risk or "SPECIAL FILE ENTRY"


                if risk:

                    yield (
                        f"{full_name} "
                        f"[ARCHIVE MEMBER RISK: {risk}]",
                        0,
                        "warning",
                    )

                if risk or encrypted:
                    continue

                if depth >= max_depth:
                    continue

                candidate = (
                    looks_like_archive(
                        member_name
                    )
                    or aggressive_magic
                )

                if not candidate:
                    continue

                if size <= 0:
                    continue

                if size > MAX_NESTED_ARCHIVE_SIZE:

                    yield (
                        f"{full_name} "
                        "[NESTED ARCHIVE TOO LARGE - SKIPPED]",
                        0,
                        "warning",
                    )

                    continue

                if not safety.can_read_nested(size):

                    yield (
                        f"{full_name} "
                        "[NESTED READ BUDGET EXCEEDED]",
                        0,
                        "warning",
                    )

                    continue

                try:
                    inner_bytes = read_7z_member_limited(
                        archive, member_name, safety, cancel_event
                    )

                    inner_type = magic_to_archive_type(
                        inner_bytes[:16]
                    )

                    if inner_type is None:

                        if looks_like_archive(
                            member_name
                        ):

                            yield (
                                f"{full_name} "
                                "[ARCHIVE EXTENSION/MAGIC MISMATCH]",
                                0,
                                "warning",
                            )

                        continue

                    yield (
                        f"{full_name} "
                        f"[NESTED ARCHIVE: "
                        f"{inner_type.upper()} | "
                        f"DEPTH {depth + 1}]",
                        0,
                        "nested",
                    )

                    inner_source = io.BytesIO(
                        inner_bytes
                    )

                    if inner_type == "zip":

                        yield from extract_zip_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "rar":

                        yield from extract_rar_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                    elif inner_type == "7z":

                        yield from extract_7z_contents(
                            inner_source,
                            virtual_prefix=full_name,
                            depth=depth + 1,
                            max_depth=max_depth,
                            safety=safety,
                            cancel_event=cancel_event,
                            aggressive_magic=aggressive_magic,
                        )

                except InterruptedError:
                    yield ("[SCAN CANCELLED]", 0, "warning")
                    return

                except ValueError as exc:
                    yield (f"{full_name} [NESTED SAFETY LIMIT: {safe_report_text(exc)}]", 0, "warning")
                    continue

                except Exception as exc:

                    yield (
                        f"{full_name} "
                        f"[NESTED 7Z INSPECTION ERROR: "
                        f"{safe_report_text(exc)[:160]}]",
                        0,
                        "error",
                    )

    except PermissionError as exc:

        yield (
            f"[PERMISSION DENIED] "
            f"{safe_report_text(exc)}",
            0,
            "error",
        )

    except Exception as exc:

        message = safe_report_text(exc)
        lowered = message.lower()

        if (
            "password" in lowered
            or "encrypt" in lowered
        ):

            yield (
                "[PASSWORD PROTECTED 7Z]",
                0,
                "error",
            )

        else:

            yield (
                f"[BROKEN 7Z] {message}",
                0,
                "error",
            )


# ============================================================
# MAIN APPLICATION
# ============================================================

class RansomLeakProApp(tk.Tk if tk is not None else object):

    def __init__(self) -> None:

        if tk is None:
            raise RuntimeError("Tkinter is unavailable: " + str(TK_IMPORT_ERROR))
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1380x860")
        self.minsize(1120, 720)

        self.configure(
            bg="#0B0F14"
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self._on_close,
        )

        self.style = ttk.Style(self)

        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self._configure_styles()

        # ---------------- STATE ----------------

        self.selected_folder = ""

        self.leaked_entries: list[str] = []

        self.counters = ScanCounters()

        self.scan_start_time = 0.0
        self.last_scan_elapsed = 0.0

        self.last_scan_completed_at: Optional[
            datetime
        ] = None

        self.last_scan_options: Optional[
            ScanOptions
        ] = None

        self.last_scan_cancelled = False
        self.last_saved_path = ""

        self.log_queue: queue.Queue = queue.Queue()

        self.cancel_event = threading.Event()

        self.is_scanning = False
        self.is_saving = False
        self._closing = False

        self._build_ui()
        self._check_dependencies()

        self.after(
            60,
            self._process_log_queue,
        )


    # ========================================================
    # STYLES
    # ========================================================

    def _configure_styles(self) -> None:

        bg = "#0B0F14"
        card = "#111821"
        card2 = "#151E28"
        fg = "#E8EEF5"
        muted = "#8291A3"
        accent = "#4CC9F0"
        danger = "#FF5C77"

        self.style.configure(
            "TFrame",
            background=bg,
        )

        self.style.configure(
            "Card.TFrame",
            background=card,
            relief="flat",
            borderwidth=0,
        )

        self.style.configure(
            "Inner.TFrame",
            background=card2,
            relief="flat",
            borderwidth=0,
        )

        self.style.configure(
            "Title.TLabel",
            background=bg,
            foreground=fg,
            font=("Segoe UI Semibold", 25),
        )

        self.style.configure(
            "Subtitle.TLabel",
            background=bg,
            foreground=muted,
            font=("Segoe UI", 10),
        )

        self.style.configure(
            "CardTitle.TLabel",
            background=card,
            foreground=fg,
            font=("Segoe UI Semibold", 11),
        )

        self.style.configure(
            "CardText.TLabel",
            background=card,
            foreground=fg,
            font=("Segoe UI", 10),
        )

        self.style.configure(
            "Muted.TLabel",
            background=card,
            foreground=muted,
            font=("Segoe UI", 9),
        )

        self.style.configure(
            "StatValue.TLabel",
            background=card,
            foreground=accent,
            font=("Segoe UI Semibold", 21),
        )

        self.style.configure(
            "StatLabel.TLabel",
            background=card,
            foreground=muted,
            font=("Segoe UI", 8),
        )

        self.style.configure(
            "TCheckbutton",
            background=card,
            foreground=fg,
            font=("Segoe UI", 9),
        )

        self.style.map(
            "TCheckbutton",
            background=[
                ("active", card),
            ],
            foreground=[
                ("active", fg),
            ],
        )

        self.style.configure(
            "TEntry",
            fieldbackground="#0C131B",
            foreground=fg,
            insertcolor=fg,
            borderwidth=0,
            padding=7,
            font=("Segoe UI", 10),
        )

        self.style.configure(
            "Primary.TButton",
            background=accent,
            foreground="#071018",
            padding=(18, 10),
            font=("Segoe UI Semibold", 10),
            borderwidth=0,
        )

        self.style.map(
            "Primary.TButton",
            background=[
                ("active", "#72D9F5"),
                ("pressed", "#35B5D9"),
            ],
        )

        self.style.configure(
            "Danger.TButton",
            background=danger,
            foreground="white",
            padding=(15, 9),
            font=("Segoe UI Semibold", 9),
            borderwidth=0,
        )

        self.style.map(
            "Danger.TButton",
            background=[
                ("active", "#FF7890"),
                ("pressed", "#E54863"),
            ],
        )

        self.style.configure(
            "Secondary.TButton",
            background="#1B2633",
            foreground=fg,
            padding=(13, 8),
            font=("Segoe UI", 9),
            borderwidth=0,
        )

        self.style.map(
            "Secondary.TButton",
            background=[
                ("active", "#263547"),
                ("pressed", "#16212D"),
            ],
        )

        self.style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#16202B",
            background=accent,
            thickness=8,
        )


    # ========================================================
    # UI
    # ========================================================

    def _build_ui(self) -> None:

        # ---------------- HEADER ----------------

        header = ttk.Frame(
            self,
            style="TFrame",
        )

        header.pack(
            fill="x",
            padx=26,
            pady=(20, 8),
        )

        title_box = ttk.Frame(
            header,
            style="TFrame",
        )

        title_box.pack(
            side="left",
            fill="x",
            expand=True,
        )

        ttk.Label(
            title_box,
            text="RANSOMLEAK PRO",
            style="Title.TLabel",
        ).pack(
            anchor="w"
        )

        ttk.Label(
            title_box,
            text=(
                "v8.1  •  Deep Forensic Archive Inventory  "
                "•  Read-Only Analysis Engine"
            ),
            style="Subtitle.TLabel",
        ).pack(
            anchor="w",
            pady=(2, 0),
        )

        self.header_status = ttk.Label(
            header,
            text="READY",
            foreground="#4CC9F0",
            background="#0B0F14",
            font=("Segoe UI Semibold", 10),
        )

        self.header_status.pack(
            side="right",
            padx=8,
        )

        # ---------------- MAIN ----------------

        main = ttk.Frame(
            self,
            style="TFrame",
        )

        main.pack(
            fill="both",
            expand=True,
            padx=26,
            pady=10,
        )

        # ---------------- LEFT ----------------

        left = ttk.Frame(
            main,
            style="TFrame",
            width=355,
        )

        left.pack(
            side="left",
            fill="y",
            padx=(0, 15),
        )

        left.pack_propagate(False)

        self._build_metadata_card(left)
        self._build_folder_card(left)
        self._build_scan_options_card(left)
        self._build_action_buttons(left)

        # ---------------- RIGHT ----------------

        right = ttk.Frame(
            main,
            style="TFrame",
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
        )

        self._build_stats(right)
        self._build_log_card(right)
        self._build_progress(right)


    def _build_metadata_card(
        self,
        parent: ttk.Frame,
    ) -> None:

        card = ttk.Frame(
            parent,
            style="Card.TFrame",
        )

        card.pack(
            fill="x",
            pady=(0, 10),
        )

        ttk.Label(
            card,
            text="CASE METADATA",
            style="CardTitle.TLabel",
        ).pack(
            anchor="w",
            padx=16,
            pady=(15, 9),
        )

        ttk.Label(
            card,
            text="Victim / Case Name",
            style="CardText.TLabel",
        ).pack(
            anchor="w",
            padx=16,
        )

        self.victim_entry = ttk.Entry(
            card,
        )

        self.victim_entry.pack(
            fill="x",
            padx=16,
            pady=(4, 9),
        )

        self.victim_entry.insert(
            0,
            "victim",
        )

        ttk.Label(
            card,
            text="Domain",
            style="CardText.TLabel",
        ).pack(
            anchor="w",
            padx=16,
        )

        self.domain_entry = ttk.Entry(
            card,
        )

        self.domain_entry.pack(
            fill="x",
            padx=16,
            pady=(4, 15),
        )

        self.domain_entry.insert(
            0,
            "xxxxx",
        )


    def _build_folder_card(
        self,
        parent: ttk.Frame,
    ) -> None:

        card = ttk.Frame(
            parent,
            style="Card.TFrame",
        )

        card.pack(
            fill="x",
            pady=(0, 10),
        )

        ttk.Label(
            card,
            text="SOURCE DATASET",
            style="CardTitle.TLabel",
        ).pack(
            anchor="w",
            padx=16,
            pady=(15, 8),
        )

        self.folder_var = tk.StringVar(
            value="No directory selected."
        )

        ttk.Label(
            card,
            textvariable=self.folder_var,
            style="Muted.TLabel",
            wraplength=315,
        ).pack(
            fill="x",
            padx=16,
            pady=(0, 9),
        )

        self.browse_btn = ttk.Button(
            card,
            text="Select Directory",
            style="Secondary.TButton",
            command=self._browse_folder,
        )

        self.browse_btn.pack(
            fill="x",
            padx=16,
            pady=(0, 15),
        )


    def _build_scan_options_card(
        self,
        parent: ttk.Frame,
    ) -> None:

        card = ttk.Frame(
            parent,
            style="Card.TFrame",
        )

        card.pack(
            fill="x",
            pady=(0, 10),
        )

        ttk.Label(
            card,
            text="SCAN ENGINE",
            style="CardTitle.TLabel",
        ).pack(
            anchor="w",
            padx=16,
            pady=(15, 8),
        )

        self.deep_var = tk.StringVar(
            value="deep"
        )

        modes = (
            (
                "Normal",
                "normal",
                "Fast archive inventory — 8 nested layers",
            ),
            (
                "Deep",
                "deep",
                "20 nested layers + recursive archive discovery",
            ),
            (
                "Ultra Deep",
                "ultra",
                "32 nested layers + aggressive archive detection",
            ),
        )

        for title, value, description in modes:

            frame = ttk.Frame(
                card,
                style="Card.TFrame",
            )

            frame.pack(
                fill="x",
                padx=13,
                pady=2,
            )

            ttk.Radiobutton(
                frame,
                text=title,
                value=value,
                variable=self.deep_var,
                style="TCheckbutton",
            ).pack(
                anchor="w"
            )

            ttk.Label(
                frame,
                text=description,
                style="Muted.TLabel",
            ).pack(
                anchor="w",
                padx=(24, 0),
            )

        ttk.Label(
            card,
            text="",
            style="Muted.TLabel",
        ).pack(
            pady=2
        )

        self.aggressive_magic_var = tk.BooleanVar(
            value=False
        )

        ttk.Checkbutton(
            card,
            text="Scan magic bytes on all files",
            variable=self.aggressive_magic_var,
        ).pack(
            anchor="w",
            padx=16,
            pady=2,
        )

        self.verbose_var = tk.BooleanVar(
            value=True
        )

        ttk.Checkbutton(
            card,
            text="Detailed live diagnostics",
            variable=self.verbose_var,
        ).pack(
            anchor="w",
            padx=16,
            pady=2,
        )

        self.auto_save_var = tk.BooleanVar(
            value=True
        )

        ttk.Checkbutton(
            card,
            text="Open report save dialog on completion",
            variable=self.auto_save_var,
        ).pack(
            anchor="w",
            padx=16,
            pady=(2, 15),
        )


    def _build_action_buttons(
        self,
        parent: ttk.Frame,
    ) -> None:

        self.scan_btn = ttk.Button(
            parent,
            text="START DEEP SCAN",
            style="Primary.TButton",
            command=self._start_scan,
        )

        self.scan_btn.pack(
            fill="x",
            pady=(5, 4),
        )

        self.cancel_btn = ttk.Button(
            parent,
            text="CANCEL SCAN",
            style="Danger.TButton",
            command=self._cancel_scan,
            state="disabled",
        )

        self.cancel_btn.pack(
            fill="x",
            pady=4,
        )

        self.save_btn = ttk.Button(
            parent,
            text="SAVE FORENSIC REPORT",
            style="Secondary.TButton",
            command=self._save_report,
            state="disabled",
        )

        self.save_btn.pack(
            fill="x",
            pady=4,
        )

        self.clear_btn = ttk.Button(
            parent,
            text="CLEAR LIVE LOG",
            style="Secondary.TButton",
            command=self._clear_log,
        )

        self.clear_btn.pack(
            fill="x",
            pady=4,
        )

        self.dep_label = ttk.Label(
            parent,
            text="",
            foreground="#6F8194",
            background="#0B0F14",
            font=("Segoe UI", 8),
        )

        self.dep_label.pack(
            anchor="w",
            padx=4,
            pady=(14, 0),
        )


    # ========================================================
    # STAT CARDS
    # ========================================================

    def _build_stats(
        self,
        parent: ttk.Frame,
    ) -> None:

        stats = ttk.Frame(
            parent,
            style="TFrame",
        )

        stats.pack(
            fill="x",
            pady=(0, 10),
        )

        self._create_stat_card(
            stats,
            "REPORT ROWS",
            "0",
            "rows_label",
        )

        self._create_stat_card(
            stats,
            "ON-DISK SIZE",
            "0 B",
            "size_label",
        )

        self._create_stat_card(
            stats,
            "ARCHIVES",
            "0",
            "archives_label",
        )

        self._create_stat_card(
            stats,
            "NESTED",
            "0",
            "nested_label",
        )

        self._create_stat_card(
            stats,
            "ISSUES",
            "0",
            "issues_label",
        )


    def _create_stat_card(
        self,
        parent: ttk.Frame,
        title: str,
        value: str,
        attr: str,
    ) -> None:

        card = ttk.Frame(
            parent,
            style="Card.TFrame",
        )

        card.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 8),
        )

        label = ttk.Label(
            card,
            text=value,
            style="StatValue.TLabel",
        )

        label.pack(
            pady=(10, 1)
        )

        setattr(
            self,
            attr,
            label,
        )

        ttk.Label(
            card,
            text=title,
            style="StatLabel.TLabel",
        ).pack(
            pady=(0, 10)
        )


    # ========================================================
    # LOG
    # ========================================================

    def _build_log_card(
        self,
        parent: ttk.Frame,
    ) -> None:

        card = ttk.Frame(
            parent,
            style="Card.TFrame",
        )

        card.pack(
            fill="both",
            expand=True,
        )

        top = ttk.Frame(
            card,
            style="Card.TFrame",
        )

        top.pack(
            fill="x",
            padx=15,
            pady=(11, 6),
        )

        ttk.Label(
            top,
            text="LIVE FORENSIC ACTIVITY",
            style="CardTitle.TLabel",
        ).pack(
            side="left"
        )

        self.log_text = ScrolledText(
            card,
            font=("Cascadia Mono", 9),
            bg="#080C11",
            fg="#C9D4DF",
            insertbackground="#FFFFFF",
            selectbackground="#26384A",
            relief="flat",
            borderwidth=0,
            wrap="none",
        )

        self.log_text.pack(
            fill="both",
            expand=True,
            padx=13,
            pady=(0, 13),
        )

        self.log_text.tag_config(
            "info",
            foreground="#AFC1D2",
        )

        self.log_text.tag_config(
            "archive",
            foreground="#4CC9F0",
        )

        self.log_text.tag_config(
            "nested",
            foreground="#C792EA",
        )

        self.log_text.tag_config(
            "warning",
            foreground="#FFD166",
        )

        self.log_text.tag_config(
            "error",
            foreground="#FF6B7A",
        )

        self.log_text.tag_config(
            "success",
            foreground="#66E3A4",
        )


    # ========================================================
    # PROGRESS
    # ========================================================

    def _build_progress(
        self,
        parent: ttk.Frame,
    ) -> None:

        self.progress = ttk.Progressbar(
            parent,
            mode="determinate",
            maximum=100,
            style="Horizontal.TProgressbar",
        )

        self.progress.pack(
            fill="x",
            pady=(10, 5),
        )

        self.status_label = ttk.Label(
            parent,
            text="Ready.",
            foreground="#8291A3",
            background="#0B0F14",
            font=("Segoe UI", 9),
        )

        self.status_label.pack(
            anchor="w"
        )


    # ========================================================
    # DEPENDENCIES
    # ========================================================

    def _check_dependencies(self) -> None:

        rar_status = (
            "RAR: READY"
            if RAR_AVAILABLE
            else "RAR: NOT INSTALLED"
        )

        seven_status = (
            "7Z: READY"
            if PY7ZR_AVAILABLE
            else "7Z: NOT INSTALLED"
        )

        self.dep_label.config(
            text=(
                "Built-in ZIP  •  "
                f"{rar_status}  •  "
                f"{seven_status}"
            )
        )


    # ========================================================
    # FOLDER
    # ========================================================

    def _browse_folder(self) -> None:

        folder = filedialog.askdirectory(
            title="Select Dataset Directory"
        )

        if not folder:
            return

        self.selected_folder = folder

        self.folder_var.set(
            folder
        )

        self.log_message(
            f"Source directory selected: {folder}",
            "info",
        )


    # ========================================================
    # QUEUE
    # ========================================================

    def log_message(
        self,
        message: str,
        level: str = "info",
    ) -> None:

        self.log_queue.put(
            (
                "log",
                level,
                message,
            )
        )


    def _queue_progress(
        self,
        message: str,
        percent: float,
    ) -> None:

        self.log_queue.put(
            (
                "progress",
                message,
                max(
                    0.0,
                    min(
                        100.0,
                        percent,
                    ),
                ),
            )
        )


    def _queue_stats(
        self,
        counters: ScanCounters,
    ) -> None:

        self.log_queue.put(
            (
                "stats",
                counters.report_rows,
                counters.total_size_bytes,
                counters.archives_found,
                counters.nested_archives_found,
                counters.archives_broken
                + counters.warnings,
            )
        )


    # ========================================================
    # QUEUE PROCESSOR
    # ========================================================

    def _process_log_queue(self) -> None:

        if self._closing:
            return

        try:

            deadline = time.monotonic() + 0.012
            for _ in range(200):
                if time.monotonic() >= deadline:
                    break
                item = self.log_queue.get_nowait()

                event_type = item[0]

                if event_type == "progress":

                    _, message, percent = item

                    self.status_label.config(
                        text=message
                    )

                    self.progress["value"] = percent

                elif event_type == "stats":

                    (
                        _,
                        rows,
                        size,
                        archives,
                        nested,
                        issues,
                    ) = item

                    self._update_stats(
                        rows,
                        size,
                        archives,
                        nested,
                        issues,
                    )

                elif event_type == "finished":

                    _, error, cancelled = item

                    self._scan_finished(
                        error,
                        cancelled,
                    )

                elif event_type == "save_progress":

                    _, completed, total = item

                    percent = (
                        completed
                        / total
                        * 100
                        if total
                        else 100
                    )

                    self.progress["value"] = percent

                    self.status_label.config(
                        text=(
                            "Writing forensic report: "
                            f"{completed:,}/{total:,} "
                            f"({percent:.1f}%)"
                        )
                    )

                elif event_type == "save_finished":

                    _, error, path = item

                    self._save_finished(
                        error,
                        path,
                    )

                elif event_type == "log":

                    _, level, message = item

                    self._insert_log_message(
                        str(message),
                        str(level),
                    )

        except queue.Empty:
            pass

        except tk.TclError:
            return

        if not self._closing:

            try:

                self.after(
                    60,
                    self._process_log_queue,
                )

            except tk.TclError:
                pass


    def _insert_log_message(
        self,
        message: str,
        level: str,
    ) -> None:

        timestamp = datetime.now().strftime(
            "%H:%M:%S"
        )

        text = (
            f"[{timestamp}] "
            f"{message}\n"
        )

        valid_tags = {
            "info",
            "archive",
            "nested",
            "warning",
            "error",
            "success",
        }

        tag = (
            level
            if level in valid_tags
            else "info"
        )

        self.log_text.insert(
            "end",
            text,
            tag,
        )

        line_count = int(self.log_text.index("end-1c").split(".")[0])
        if line_count > 5000:
            self.log_text.delete("1.0", f"{line_count - 5000 + 1}.0")

        self.log_text.see(
            "end"
        )


    # ========================================================
    # STATS UPDATE
    # ========================================================

    def _update_stats(
        self,
        rows: int,
        size: int,
        archives: int,
        nested: int,
        issues: int,
    ) -> None:

        self.rows_label.config(
            text=f"{rows:,}"
        )

        self.size_label.config(
            text=format_size(size)
        )

        self.archives_label.config(
            text=f"{archives:,}"
        )

        self.nested_label.config(
            text=f"{nested:,}"
        )

        self.issues_label.config(
            text=f"{issues:,}"
        )


    # ========================================================
    # START SCAN
    # ========================================================

    def _start_scan(self) -> None:

        if self.is_scanning or self.is_saving:
            return

        if not self.selected_folder:

            messagebox.showwarning(
                "No Source Selected",
                "Please select a dataset directory first.",
            )

            return

        root = Path(
            self.selected_folder
        )

        if not root.exists() or not root.is_dir():

            messagebox.showerror(
                "Invalid Directory",
                "The selected directory is no longer valid.",
            )

            return

        mode = self.deep_var.get()

        options = ScanOptions(
            root_path=root,
            deep_mode=mode,
            aggressive_magic=bool(
                self.aggressive_magic_var.get()
            ),
            verbose=bool(
                self.verbose_var.get()
            ),
            victim=(
                self.victim_entry.get().strip()
                or "victim"
            ),
            domain=normalize_domain(
                self.domain_entry.get().strip()
                or "xxxxx"
            ),
            started_at=datetime.now(),
            auto_save_prompt=bool(
                self.auto_save_var.get()
            ),
        )

        self.last_scan_options = options
        self.last_scan_cancelled = False
        self.last_scan_completed_at = None
        self.last_scan_elapsed = 0
        self.last_saved_path = ""

        self.is_scanning = True

        self.cancel_event.clear()

        self.scan_btn.config(
            state="disabled",
            text="SCANNING...",
        )

        self.cancel_btn.config(
            state="normal"
        )

        self.save_btn.config(
            state="disabled"
        )

        self.browse_btn.config(
            state="disabled"
        )

        self.clear_btn.config(
            state="disabled"
        )

        self.header_status.config(
            text="SCANNING"
        )

        self.progress["value"] = 0

        self.status_label.config(
            text="Initializing deep forensic scan..."
        )

        self.leaked_entries = []

        self.counters = ScanCounters()

        self.log_text.delete(
            "1.0",
            "end",
        )

        self._update_stats(
            0,
            0,
            0,
            0,
            0,
        )

        self.scan_start_time = time.monotonic()

        threading.Thread(
            target=self._scan_worker,
            args=(options,),
            daemon=True,
        ).start()


    # ========================================================
    # CANCEL
    # ========================================================

    def _cancel_scan(self) -> None:

        if not self.is_scanning:
            return

        self.cancel_event.set()

        self.cancel_btn.config(
            state="disabled"
        )

        self.status_label.config(
            text=(
                "Cancellation requested. "
                "Waiting for the current safe operation to finish..."
            )
        )

        self.log_message(
            "Cancellation request received.",
            "warning",
        )


    # ========================================================
    # SCAN WORKER
    # ========================================================

    def _scan_worker(
        self,
        options: ScanOptions,
    ) -> None:

        counters = ScanCounters()

        error = False
        cancelled = False

        try:

            if options.deep_mode == "normal":

                max_depth = NORMAL_MAX_DEPTH

            elif options.deep_mode == "deep":

                max_depth = DEEP_MAX_DEPTH

            else:

                max_depth = ULTRA_MAX_DEPTH

            aggressive_magic = (
                options.aggressive_magic
                or options.deep_mode == "ultra"
            )

            self.log_message(
                "Initializing single-pass filesystem traversal...",
                "info",
            )

            self.log_message(
                f"Scan mode: {options.deep_mode.upper()}",
                "success",
            )

            self.log_message(
                f"Maximum nested archive depth: {max_depth}",
                "success",
            )

            self.log_message(
                (
                    "Aggressive magic detection: "
                    f"{'ENABLED' if aggressive_magic else 'DISABLED'}"
                ),
                "info",
            )

            self.log_message(
                f"Source: {options.root_path}",
                "info",
            )

            # ------------------------------------------------
            # IMPORTANT PERFORMANCE CHANGE:
            # We do NOT perform a preliminary full traversal.
            # This avoids scanning the filesystem twice.
            # ------------------------------------------------

            for file_path in iter_files_fast(
                options.root_path,
                counters,
                self.cancel_event,
                self.log_queue,
            ):

                if self.cancel_event.is_set():

                    cancelled = True

                    self.log_message(
                        "Scan cancelled by user.",
                        "warning",
                    )

                    break

                counters.processed_files += 1

                try:

                    st = os.lstat(
                        file_path
                    )

                    if stat.S_ISLNK(
                        st.st_mode
                    ):

                        counters.skipped_files += 1
                        counters.warnings += 1

                        continue

                    if not stat.S_ISREG(
                        st.st_mode
                    ):

                        counters.skipped_files += 1

                        continue

                    size = max(
                        0,
                        int(st.st_size),
                    )

                    relative = safe_report_text(
                        file_path.relative_to(
                            options.root_path
                        ).as_posix().replace(
                            "/",
                            "\\",
                        )
                    )

                    counters.real_file_entries += 1
                    counters.total_size_bytes += size
                    counters.report_rows += 1

                    self.leaked_entries.append(
                        f"{relative}[{format_size(size)}]"
                    )

                    archive_type = detect_archive_type(
                        file_path,
                        aggressive_magic,
                    )

                    if archive_type:

                        counters.archives_found += 1
                        if not looks_like_archive(file_path.name):
                            counters.hidden_archives_found += 1

                        self.log_message(
                            (
                                f"Archive detected: "
                                f"{file_path.name} "
                                f"({archive_type.upper()})"
                            ),
                            "archive",
                        )

                        self._scan_archive(
                            file_path,
                            relative,
                            archive_type,
                            max_depth,
                            counters,
                            options.verbose,
                            aggressive_magic,
                        )

                    if (
                        counters.processed_files
                        % PROGRESS_UPDATE_EVERY_FILES
                        == 0
                    ):

                        self._emit_progress(
                            counters
                        )

                    if (
                        counters.processed_files
                        % STATS_UPDATE_EVERY_FILES
                        == 0
                    ):

                        self._queue_stats(
                            counters
                        )

                except OSError as exc:

                    counters.skipped_files += 1
                    counters.warnings += 1

                    self.log_message(
                        (
                            f"File skipped: "
                            f"{safe_report_text(file_path)} "
                            f"[{safe_report_text(exc)}]"
                        ),
                        "warning",
                    )

            # ------------------------------------------------
            # COMPLETION
            # ------------------------------------------------

            cancelled = cancelled or self.cancel_event.is_set()

            self.leaked_entries.sort(
                key=lambda item: (
                    item.lstrip("@").casefold()
                )
            )

            self.counters = counters

            self._queue_stats(
                counters
            )

            elapsed = max(
                0,
                time.monotonic()
                - self.scan_start_time,
            )

            if cancelled:

                self._queue_progress(
                    (
                        "Scan cancelled | "
                        f"{counters.processed_files:,} "
                        f"files processed | "
                        f"{format_eta(elapsed)}"
                    ),
                    100,
                )

            else:

                self._queue_progress(
                    (
                        "Scan completed | "
                        f"{counters.processed_files:,} "
                        f"files processed | "
                        f"{format_eta(elapsed)}"
                    ),
                    100,
                )

                self.log_message(
                    (
                        f"Scan completed successfully: "
                        f"{counters.report_rows:,} report rows | "
                        f"{format_size(counters.total_size_bytes)} "
                        f"on disk"
                    ),
                    "success",
                )

                self.log_message(
                    (
                        f"Archives: {counters.archives_found:,} | "
                        f"Nested: {counters.nested_archives_found:,} | "
                        f"Broken: {counters.archives_broken:,} | "
                        f"Warnings: {counters.warnings:,}"
                    ),
                    "success",
                )

        except Exception as exc:

            error = True

            self.log_message(
                (
                    f"CRITICAL ERROR "
                    f"{type(exc).__name__}: "
                    f"{safe_report_text(exc)}"
                ),
                "error",
            )

            trace = traceback.format_exc(
                limit=6
            ).strip().splitlines()

            if trace:

                self.log_message(
                    f"Trace: {safe_report_text(trace[-1])}",
                    "error",
                )

        finally:

            cancelled = cancelled or self.cancel_event.is_set()
            self.counters = counters
            self.last_scan_cancelled = cancelled

            self.last_scan_elapsed = max(
                0,
                time.monotonic()
                - self.scan_start_time,
            )

            self.last_scan_completed_at = datetime.now()

            self.log_queue.put(
                (
                    "finished",
                    error,
                    cancelled,
                )
            )


    # ========================================================
    # ARCHIVE SCANNER
    # ========================================================

    def _scan_archive(
        self,
        file_path: Path,
        archive_rel: str,
        archive_type: str,
        max_depth: int,
        counters: ScanCounters,
        verbose: bool,
        aggressive_magic: bool,
    ) -> None:

        safety = ArchiveSafetyContext()

        if archive_type == "zip":

            generator = extract_zip_contents(
                file_path,
                virtual_prefix=archive_rel,
                depth=0,
                max_depth=max_depth,
                safety=safety,
                cancel_event=self.cancel_event,
                aggressive_magic=aggressive_magic,
            )

        elif archive_type == "rar":

            generator = extract_rar_contents(
                file_path,
                virtual_prefix=archive_rel,
                depth=0,
                max_depth=max_depth,
                safety=safety,
                cancel_event=self.cancel_event,
                aggressive_magic=aggressive_magic,
            )

        elif archive_type == "7z":

            generator = extract_7z_contents(
                file_path,
                virtual_prefix=archive_rel,
                depth=0,
                max_depth=max_depth,
                safety=safety,
                cancel_event=self.cancel_event,
                aggressive_magic=aggressive_magic,
            )

        else:

            return

        inner_count = 0
        broken_counted = False
        encrypted_counted = False

        for name, size, kind in generator:

            if self.cancel_event.is_set():
                break

            inner_count += 1

            formatted_size = format_size(
                size
            )

            self.leaked_entries.append(
                f"@{safe_report_text(name)}[{formatted_size}]"
            )

            counters.report_rows += 1

            if kind == "file":

                counters.real_file_entries += 1

            elif kind == "warning":

                counters.warnings += 1

            elif kind == "error":

                if not broken_counted:
                    counters.archives_broken += 1
                    broken_counted = True

            elif kind == "nested":

                counters.nested_archives_found += 1

            if "PASSWORD PROTECTED" in name and not encrypted_counted:
                counters.archives_encrypted += 1
                encrypted_counted = True

            if verbose:

                if kind == "error":

                    self.log_message(
                        f"  └─ {name}",
                        "error",
                    )

                elif kind == "warning":

                    self.log_message(
                        f"  └─ {name}",
                        "warning",
                    )

                elif kind == "nested":

                    self.log_message(
                        f"  └─ {name}",
                        "nested",
                    )

                elif inner_count <= LOG_PREVIEW_INNER_FILES:

                    self.log_message(
                        f"  └─ {name} [{formatted_size}]",
                        "info",
                    )

                elif (
                    inner_count
                    == LOG_PREVIEW_INNER_FILES + 1
                ):

                    self.log_message(
                        "  └─ additional members "
                        "recorded in the report",
                        "info",
                    )

        if inner_count == 0 and verbose:

            self.log_message(
                "  └─ Archive contains no readable file members.",
                "info",
            )


    # ========================================================
    # PROGRESS
    # ========================================================

    def _emit_progress(
        self,
        counters: ScanCounters,
    ) -> None:

        # Because this version intentionally avoids
        # the expensive preliminary filesystem pass,
        # progress is based on activity rather than a
        # potentially misleading estimated total.

        elapsed = max(
            0.001,
            time.monotonic()
            - self.scan_start_time,
        )

        rate = (
            counters.processed_files
            / elapsed
        )

        status = (
            f"Processed: "
            f"{counters.processed_files:,} files | "
            f"Rate: {rate:,.0f} files/s | "
            f"Rows: {counters.report_rows:,} | "
            f"Archives: {counters.archives_found:,} | "
            f"Nested: {counters.nested_archives_found:,} | "
            f"Disk: {format_size(counters.total_size_bytes)}"
        )

        # Indeterminate progress is more honest than
        # inventing a total when the filesystem can change
        # during the scan.
        self._queue_progress(
            status,
            0,
        )


    # ========================================================
    # SCAN FINISHED
    # ========================================================

    def _scan_finished(
        self,
        error: bool,
        cancelled: bool,
    ) -> None:

        self.is_scanning = False

        self.scan_btn.config(
            state="normal",
            text="START DEEP SCAN",
        )

        self.cancel_btn.config(
            state="disabled"
        )

        self.browse_btn.config(
            state="normal"
        )

        self.clear_btn.config(
            state="normal"
        )

        self.header_status.config(
            text="READY"
        )

        self.save_btn.config(
            state=(
                "normal"
                if self.leaked_entries
                and not error
                else "disabled"
            )
        )

        if error:

            self.status_label.config(
                text="Scan terminated with a critical error."
            )

            messagebox.showerror(
                "Scan Error",
                "The scan terminated with a critical error.\n\n"
                "Review the live diagnostic log for details.",
            )

            return

        options = self.last_scan_options

        should_save = bool(
            options
            and options.auto_save_prompt
            and self.leaked_entries
        )

        if cancelled:

            self.status_label.config(
                text=(
                    "Scan cancelled. "
                    "Partial forensic report is available."
                )
            )

            messagebox.showwarning(
                APP_TITLE,
                (
                    "The scan was cancelled.\n\n"
                    f"Report rows: "
                    f"{self.counters.report_rows:,}\n"
                    f"On-disk size: "
                    f"{format_size(self.counters.total_size_bytes)}\n\n"
                    "The partial report can still be saved."
                ),
            )

            if should_save:
                self.after_idle(
                    self._save_report
                )

            return

        self.status_label.config(
            text=(
                "Deep forensic inventory completed successfully."
            )
        )

        messagebox.showinfo(
            "Scan Completed",
            (
                "Deep forensic inventory completed.\n\n"
                f"Report rows: "
                f"{self.counters.report_rows:,}\n"
                f"Filesystem files: "
                f"{self.counters.filesystem_files:,}\n"
                f"On-disk size: "
                f"{format_size(self.counters.total_size_bytes)}\n"
                f"Archives: "
                f"{self.counters.archives_found:,}\n"
                f"Nested archives: "
                f"{self.counters.nested_archives_found:,}\n"
                f"Broken archives: "
                f"{self.counters.archives_broken:,}\n"
                f"Warnings: "
                f"{self.counters.warnings:,}\n"
                f"Elapsed: "
                f"{format_eta(self.last_scan_elapsed)}"
            ),
        )

        if should_save:

            self.after_idle(
                self._save_report
            )


    # ========================================================
    # SAVE REPORT
    # ========================================================

    def _save_report(self) -> None:

        if self.is_scanning or self.is_saving:
            return

        if not self.leaked_entries:

            messagebox.showwarning(
                "No Data",
                "There is no inventory data to save.",
            )

            return

        options = self.last_scan_options

        victim = (
            options.victim
            if options
            else self.victim_entry.get().strip()
            or "victim"
        )

        victim_filename = safe_filename(
            victim
        )

        initial_dir = (
            str(options.root_path.parent)
            if options
            else None
        )

        output = filedialog.asksaveasfilename(
            title="Save Forensic Inventory",
            defaultextension=".txt",
            filetypes=[
                (
                    "Forensic TXT Report",
                    "*.txt",
                ),
                (
                    "All Files",
                    "*.*",
                ),
            ],
            initialfile=(
                f"forensic_inventory_"
                f"{victim_filename.lower()}.txt"
            ),
            initialdir=initial_dir,
        )

        if not output:
            return

        entries_snapshot = tuple(
            self.leaked_entries
        )

        counters_snapshot = ScanCounters(
            **vars(self.counters)
        )

        completed_at = (
            self.last_scan_completed_at
            or datetime.now()
        )

        self.is_saving = True

        self.scan_btn.config(
            state="disabled"
        )

        self.save_btn.config(
            state="disabled"
        )

        self.browse_btn.config(
            state="disabled"
        )

        self.clear_btn.config(
            state="disabled"
        )

        self.progress["value"] = 0

        self.status_label.config(
            text="Preparing atomic forensic report..."
        )

        threading.Thread(
            target=self._save_report_worker,
            args=(
                Path(output),
                entries_snapshot,
                counters_snapshot,
                options,
                self.last_scan_cancelled,
                completed_at,
                self.last_scan_elapsed,
            ),
            daemon=True,
        ).start()


    # ========================================================
    # REPORT WRITER
    # ========================================================

    def _save_report_worker(
        self,
        output_path: Path,
        entries: tuple[str, ...],
        counters: ScanCounters,
        options: Optional[ScanOptions],
        cancelled: bool,
        completed_at: datetime,
        elapsed: float,
    ) -> None:

        temporary_path: Optional[Path] = None

        try:

            root = (options.root_path if options else Path(self.selected_folder)).resolve()
            destination = output_path.resolve()
            if destination == root or root in destination.parents:
                raise ValueError("Save the report outside the scanned source directory")
            parent = output_path.parent

            if not parent.exists():

                raise OSError(
                    f"Destination directory does not exist: "
                    f"{parent}"
                )

            victim = (
                options.victim
                if options
                else "victim"
            )

            domain = normalize_domain(
                options.domain
                if options
                else "xxxxx"
            )

            root_path = (
                options.root_path
                if options
                else Path(
                    self.selected_folder
                )
            )

            started_at = (
                options.started_at
                if options
                else completed_at
            )

            deep_mode = (
                options.deep_mode
                if options
                else "unknown"
            )

            aggressive_magic = (
                (options.aggressive_magic or options.deep_mode == "ultra")
                if options
                else False
            )

            digest = hashlib.sha256()

            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=parent,
                prefix=f".{output_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temp:

                temporary_path = Path(
                    temp.name
                )

                # ----------------------------------------
                # REPORT HEADER
                # ----------------------------------------

                temp.write(
                    f"# REPORT FORMAT VERSION: "
                    f"{REPORT_FORMAT_VERSION}\n"
                )

                temp.write(
                    f"# GENERATED BY: "
                    f"{APP_TITLE}\n"
                )

                temp.write(
                    f"# SCAN STARTED: "
                    f"{started_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )

                temp.write(
                    f"# SCAN COMPLETED: "
                    f"{completed_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )

                temp.write(
                    f"# REPORT SAVED: "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                )

                temp.write(
                    f"# SCAN DURATION: "
                    f"{elapsed:.3f} seconds\n"
                )

                temp.write(
                    f"# VICTIM / CASE: "
                    f"{safe_report_text(victim)}\n"
                )

                temp.write(
                    f"# DOMAIN: "
                    f"https://{safe_report_text(domain)}\n"
                )

                temp.write(
                    f"# ROOT PATH: "
                    f"{safe_report_text(root_path)}\n"
                )

                temp.write(
                    f"# SCAN MODE: "
                    f"{safe_report_text(deep_mode).upper()}\n"
                )

                temp.write(
                    f"# AGGRESSIVE MAGIC: "
                    f"{'ENABLED' if aggressive_magic else 'DISABLED'}\n"
                )

                temp.write(
                    f"# FILESYSTEM FILES: "
                    f"{counters.filesystem_files:,}\n"
                )

                temp.write(
                    f"# FILESYSTEM DIRECTORIES: "
                    f"{counters.filesystem_directories:,}\n"
                )

                temp.write(
                    f"# PROCESSED FILES: "
                    f"{counters.processed_files:,}\n"
                )

                temp.write(
                    f"# TOTAL REPORT ROWS: "
                    f"{counters.report_rows:,}\n"
                )

                temp.write(
                    f"# REAL FILE ENTRIES: "
                    f"{counters.real_file_entries:,}\n"
                )

                temp.write(
                    f"# ON-DISK SIZE: "
                    f"{format_size(counters.total_size_bytes)}\n"
                )

                temp.write(
                    f"# ON-DISK SIZE BYTES: "
                    f"{counters.total_size_bytes}\n"
                )

                temp.write(
                    f"# ARCHIVES FOUND: "
                    f"{counters.archives_found:,}\n"
                )

                temp.write(
                    f"# NESTED ARCHIVES FOUND: "
                    f"{counters.nested_archives_found:,}\n"
                )

                temp.write(
                    f"# HIDDEN ARCHIVE CANDIDATES: "
                    f"{counters.hidden_archives_found:,}\n"
                )

                temp.write(
                    f"# BROKEN ARCHIVES: "
                    f"{counters.archives_broken:,}\n"
                )

                temp.write(f"# ENCRYPTED ARCHIVE CONTEXTS: {counters.archives_encrypted:,}\n")
                temp.write("# SCOPE: Metadata inventory; not a full content integrity check.\n")
                temp.write("# LIMITS: Solid 7z recursion skipped; no OS-level resource isolation.\n")
                temp.write(
                    f"# WARNINGS: "
                    f"{counters.warnings:,}\n"
                )

                temp.write(
                    f"# SKIPPED FILESYSTEM ITEMS: "
                    f"{counters.skipped_files:,}\n"
                )

                temp.write(
                    f"# CANCELLED: "
                    f"{'YES' if cancelled else 'NO'}\n"
                )

                temp.write(
                    "# NOTE: Lines beginning with @ represent "
                    "archive members. Archive-member sizes are "
                    "excluded from the on-disk size total.\n"
                )

                temp.write(
                    "# NOTE: This report contains metadata only. "
                    "No archive content was extracted to disk.\n\n"
                )

                # ----------------------------------------
                # DATA
                # ----------------------------------------

                total = len(entries)

                for index, line in enumerate(
                    entries,
                    start=1,
                ):

                    clean = safe_report_text(
                        line
                    )

                    encoded = (
                        clean + "\n"
                    ).encode(
                        "utf-8"
                    )

                    digest.update(
                        encoded
                    )

                    temp.write(
                        clean + "\n"
                    )

                    if (
                        index
                        % SAVE_PROGRESS_EVERY_ROWS
                        == 0
                        or index == total
                    ):

                        self.log_queue.put(
                            (
                                "save_progress",
                                index,
                                total,
                            )
                        )

                temp.write(
                    "\n"
                )

                temp.write(
                    "# DATA LINES SHA256: "
                    f"{digest.hexdigest()}\n"
                )

                temp.flush()

                os.fsync(
                    temp.fileno()
                )

            os.replace(
                temporary_path,
                output_path,
            )

            temporary_path = None

            self.log_queue.put(
                (
                    "save_finished",
                    None,
                    str(output_path),
                )
            )

        except Exception as exc:

            if temporary_path is not None:

                try:
                    temporary_path.unlink(
                        missing_ok=True
                    )
                except OSError:
                    pass

            self.log_queue.put(
                (
                    "save_finished",
                    (
                        f"{type(exc).__name__}: "
                        f"{safe_report_text(exc)}"
                    ),
                    str(output_path),
                )
            )


    # ========================================================
    # SAVE FINISHED
    # ========================================================

    def _save_finished(
        self,
        error_message: Optional[str],
        output_path: str,
    ) -> None:

        self.is_saving = False

        self.scan_btn.config(
            state="normal"
        )

        self.save_btn.config(
            state=(
                "normal"
                if self.leaked_entries
                else "disabled"
            )
        )

        self.browse_btn.config(
            state="normal"
        )

        self.clear_btn.config(
            state="normal"
        )

        if error_message:

            self.status_label.config(
                text="Report save failed."
            )

            self.log_message(
                f"Report save error: {error_message}",
                "error",
            )

            messagebox.showerror(
                "Report Save Error",
                (
                    "The report could not be saved.\n\n"
                    f"{error_message}"
                ),
            )

            return

        self.last_saved_path = output_path

        self.progress["value"] = 100

        self.status_label.config(
            text=(
                f"Report saved successfully: "
                f"{output_path}"
            )
        )

        self.log_message(
            (
                "Forensic report saved atomically: "
                f"{output_path}"
            ),
            "success",
        )

        messagebox.showinfo(
            "Report Saved",
            (
                "The forensic inventory report "
                "was saved successfully.\n\n"
                f"{output_path}"
            ),
        )


    # ========================================================
    # CLEAR LOG
    # ========================================================

    def _clear_log(self) -> None:

        if self.is_scanning or self.is_saving:

            messagebox.showwarning(
                "Operation In Progress",
                "The live log cannot be cleared while "
                "a scan or report save is running.",
            )

            return

        self.log_text.delete(
            "1.0",
            "end",
        )


    # ========================================================
    # CLOSE
    # ========================================================

    def _on_close(self) -> None:

        if self.is_saving:

            messagebox.showwarning(
                "Report Save In Progress",
                (
                    "A report is currently being written.\n\n"
                    "Please wait until the save operation finishes."
                ),
            )

            return

        if self.is_scanning:

            close = messagebox.askyesno(
                "Scan In Progress",
                (
                    "A scan is still running.\n\n"
                    "Closing the application will request cancellation.\n\n"
                    "Exit anyway?"
                ),
            )

            if not close:
                return

            self.cancel_event.set()

        self._closing = True

        self.destroy()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    if tk is None:
        raise SystemExit("GUI requires Python with working Tk/Tcl support: " + str(TK_IMPORT_ERROR))
    app = RansomLeakProApp()

    app.mainloop()