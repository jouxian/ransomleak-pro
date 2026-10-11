"""GUI-independent forensic scan engine."""
from __future__ import annotations

import os
import stat
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from .archives import extract_7z_contents, extract_rar_contents, extract_zip_contents
from .config import (
    DEEP_MAX_DEPTH,
    LOG_PREVIEW_INNER_FILES,
    NORMAL_MAX_DEPTH,
    PROGRESS_UPDATE_EVERY_FILES,
    STATS_UPDATE_EVERY_FILES,
    ULTRA_MAX_DEPTH,
)
from .detection import detect_archive_type, looks_like_archive
from .filesystem import iter_files_fast
from .models import ArchiveSafetyContext, ScanCounters, ScanOptions, ScanResult
from .utils import format_eta, format_size, safe_report_text

LogCallback = Callable[[str, str], None]
ProgressCallback = Callable[[str], None]
StatsCallback = Callable[[ScanCounters], None]


def _noop_log(message: str, level: str = "info") -> None:
    return None


def _noop_progress(message: str) -> None:
    return None


def _noop_stats(counters: ScanCounters) -> None:
    return None


class ForensicScanner:
    """Read-only scan engine that has no GUI dependency."""

    def __init__(
        self,
        cancel_event: threading.Event | None = None,
        log_callback: LogCallback | None = None,
        progress_callback: ProgressCallback | None = None,
        stats_callback: StatsCallback | None = None,
    ) -> None:
        self.cancel_event = cancel_event or threading.Event()
        self.log = log_callback or _noop_log
        self.progress = progress_callback or _noop_progress
        self.stats = stats_callback or _noop_stats

    def scan(self, options: ScanOptions) -> ScanResult:
        counters = ScanCounters()
        entries: list[str] = []
        started_monotonic = time.monotonic()
        cancelled = False

        if options.deep_mode == "normal":
            max_depth = NORMAL_MAX_DEPTH
        elif options.deep_mode == "deep":
            max_depth = DEEP_MAX_DEPTH
        elif options.deep_mode == "ultra":
            max_depth = ULTRA_MAX_DEPTH
        else:
            raise ValueError(f"Unknown scan mode: {options.deep_mode}")

        aggressive_magic = options.aggressive_magic or options.deep_mode == "ultra"

        self.log("Initializing single-pass filesystem traversal...", "info")
        self.log(f"Scan mode: {options.deep_mode.upper()}", "success")
        self.log(f"Maximum nested archive depth: {max_depth}", "success")
        self.log(
            "Aggressive magic detection: "
            + ("ENABLED" if aggressive_magic else "DISABLED"),
            "info",
        )
        self.log(f"Source: {options.root_path}", "info")

        for file_path in iter_files_fast(
            options.root_path,
            counters,
            self.cancel_event,
            self.log,
        ):
            if self.cancel_event.is_set():
                cancelled = True
                self.log("Scan cancelled by user.", "warning")
                break

            counters.processed_files += 1
            try:
                st = os.lstat(file_path)
                if stat.S_ISLNK(st.st_mode):
                    counters.skipped_files += 1
                    counters.warnings += 1
                    continue
                if not stat.S_ISREG(st.st_mode):
                    counters.skipped_files += 1
                    continue

                size = max(0, int(st.st_size))
                relative = safe_report_text(
                    file_path.relative_to(options.root_path).as_posix().replace("/", "\\")
                )

                counters.real_file_entries += 1
                counters.total_size_bytes += size
                counters.report_rows += 1
                entries.append(f"{relative}[{format_size(size)}]")

                archive_type = detect_archive_type(file_path, aggressive_magic)
                if archive_type:
                    counters.archives_found += 1
                    if not looks_like_archive(file_path.name):
                        counters.hidden_archives_found += 1
                    self.log(
                        f"Archive detected: {file_path.name} ({archive_type.upper()})",
                        "archive",
                    )
                    self._scan_archive(
                        file_path,
                        relative,
                        archive_type,
                        max_depth,
                        counters,
                        entries,
                        options.verbose,
                        aggressive_magic,
                    )

                if counters.processed_files % PROGRESS_UPDATE_EVERY_FILES == 0:
                    self._emit_progress(counters, started_monotonic)
                if counters.processed_files % STATS_UPDATE_EVERY_FILES == 0:
                    self.stats(counters.copy())

            except OSError as exc:
                counters.skipped_files += 1
                counters.warnings += 1
                self.log(
                    f"File skipped: {safe_report_text(file_path)} "
                    f"[{safe_report_text(exc)}]",
                    "warning",
                )

        cancelled = cancelled or self.cancel_event.is_set()
        entries.sort(key=lambda item: item.lstrip("@").casefold())
        self.stats(counters.copy())
        elapsed = max(0.0, time.monotonic() - started_monotonic)

        status = "cancelled" if cancelled else "completed"
        self.progress(
            f"Scan {status} | {counters.processed_files:,} files processed | "
            f"{format_eta(elapsed)}"
        )
        if not cancelled:
            self.log(
                f"Scan completed successfully: {counters.report_rows:,} report rows | "
                f"{format_size(counters.total_size_bytes)} on disk",
                "success",
            )
            self.log(
                f"Archives: {counters.archives_found:,} | "
                f"Nested: {counters.nested_archives_found:,} | "
                f"Broken: {counters.archives_broken:,} | "
                f"Warnings: {counters.warnings:,}",
                "success",
            )

        return ScanResult(
            entries=tuple(entries),
            counters=counters.copy(),
            started_at=options.started_at,
            completed_at=datetime.now(),
            elapsed_seconds=elapsed,
            cancelled=cancelled,
        )

    def _scan_archive(
        self,
        file_path: Path,
        archive_rel: str,
        archive_type: str,
        max_depth: int,
        counters: ScanCounters,
        entries: list[str],
        verbose: bool,
        aggressive_magic: bool,
    ) -> None:
        safety = ArchiveSafetyContext()
        common = dict(
            virtual_prefix=archive_rel,
            depth=0,
            max_depth=max_depth,
            safety=safety,
            cancel_event=self.cancel_event,
            aggressive_magic=aggressive_magic,
        )
        if archive_type == "zip":
            generator = extract_zip_contents(file_path, **common)
        elif archive_type == "rar":
            generator = extract_rar_contents(file_path, **common)
        elif archive_type == "7z":
            generator = extract_7z_contents(file_path, **common)
        else:
            return

        inner_count = 0
        broken_counted = False
        encrypted_counted = False
        for name, size, kind in generator:
            if self.cancel_event.is_set():
                break
            inner_count += 1
            formatted_size = format_size(size)
            entries.append(f"@{safe_report_text(name)}[{formatted_size}]")
            counters.report_rows += 1

            if kind == "file":
                counters.real_file_entries += 1
            elif kind == "warning":
                counters.warnings += 1
            elif kind == "error" and not broken_counted:
                counters.archives_broken += 1
                broken_counted = True
            elif kind == "nested":
                counters.nested_archives_found += 1

            if "PASSWORD PROTECTED" in name and not encrypted_counted:
                counters.archives_encrypted += 1
                encrypted_counted = True

            if verbose:
                if kind in {"error", "warning", "nested"}:
                    self.log(f"  └─ {name}", kind)
                elif inner_count <= LOG_PREVIEW_INNER_FILES:
                    self.log(f"  └─ {name} [{formatted_size}]", "info")
                elif inner_count == LOG_PREVIEW_INNER_FILES + 1:
                    self.log("  └─ additional members recorded in the report", "info")

        if inner_count == 0 and verbose:
            self.log("  └─ Archive contains no readable file members.", "info")

    def _emit_progress(self, counters: ScanCounters, started_monotonic: float) -> None:
        elapsed = max(0.001, time.monotonic() - started_monotonic)
        rate = counters.processed_files / elapsed
        self.progress(
            f"Processed: {counters.processed_files:,} files | "
            f"Rate: {rate:,.0f} files/s | Rows: {counters.report_rows:,} | "
            f"Archives: {counters.archives_found:,} | "
            f"Nested: {counters.nested_archives_found:,} | "
            f"Disk: {format_size(counters.total_size_bytes)}"
        )
