"""RAR archive reader."""
from __future__ import annotations

import io
import os
import threading
from collections.abc import Generator
from pathlib import Path

from ..config import (
    MAX_ARCHIVE_RECURSION_DEPTH,
    MAX_NESTED_ARCHIVE_SIZE,
    MAX_NESTED_COMPRESSION_RATIO,
    NORMAL_MAX_DEPTH,
)
from ..detection import (
    archive_member_risk,
    get_filelike_header,
    get_magic_header,
    looks_like_archive,
    magic_to_archive_type,
)
from ..models import ArchiveSafetyContext, ArchiveSource, ArchiveYield
from ..utils import safe_report_text
from .common import read_stream_limited

try:
    import rarfile  # type: ignore
    RAR_AVAILABLE = True
except ImportError:
    rarfile = None
    RAR_AVAILABLE = False

def extract_rar_contents(
    source: ArchiveSource,
    virtual_prefix: str = "",
    depth: int = 0,
    max_depth: int = NORMAL_MAX_DEPTH,
    safety: ArchiveSafetyContext | None = None,
    cancel_event: threading.Event | None = None,
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

                        from .zip_reader import extract_zip_contents

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

                        from .sevenzip_reader import extract_7z_contents

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
