"""Core data models used by the scan engine and report writer."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Union
import io
import os

from .config import MAX_ARCHIVE_ENTRIES, MAX_NESTED_ARCHIVE_SIZE, MAX_TOTAL_NESTED_READ_BYTES

ArchiveSource = Union[str, os.PathLike, Path, io.BytesIO]
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
    auto_save_prompt: bool = False

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

    def copy(self) -> "ScanCounters":
        return ScanCounters(**vars(self))

@dataclass(frozen=True)
class ScanResult:
    entries: tuple[str, ...]
    counters: ScanCounters
    started_at: datetime
    completed_at: datetime
    elapsed_seconds: float
    cancelled: bool
