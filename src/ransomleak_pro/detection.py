"""Archive detection and archive-member risk checks."""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Optional, Union

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
