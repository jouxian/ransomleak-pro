"""ZIP archive reader."""
from __future__ import annotations

import io
import os
import threading
import zipfile
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
    is_nonfirst_split_volume,
    looks_like_archive,
    magic_to_archive_type,
)
from ..models import ArchiveSafetyContext, ArchiveSource, ArchiveYield
from ..utils import format_size, safe_report_text
from .common import read_stream_limited


def extract_zip_contents(
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

                        from .rar_reader import extract_rar_contents

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
