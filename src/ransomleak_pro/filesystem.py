"""Fast, cancellation-aware read-only filesystem traversal."""
from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterable
from pathlib import Path

from .models import ScanCounters
from .utils import safe_report_text

LogCallback = Callable[[str, str], None]


def iter_files_fast(
    root: Path,
    counters: ScanCounters,
    cancel_event: threading.Event,
    log_callback: LogCallback | None = None,
) -> Iterable[Path]:
    """Yield regular files without following symlinks.

    Traversal errors are counted and reported through a callback instead of
    coupling the core walker to a GUI queue implementation.
    """
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
                            if log_callback:
                                log_callback(f"Skipped symbolic link: {entry.path}", "warning")
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
                        if log_callback:
                            log_callback(
                                "Filesystem entry skipped: "
                                f"{safe_report_text(entry.path)} [{safe_report_text(exc)}]",
                                "warning",
                            )

        except OSError as exc:
            counters.warnings += 1
            if log_callback:
                log_callback(
                    "Directory access error: "
                    f"{safe_report_text(current)} [{safe_report_text(exc)}]",
                    "warning",
                )
