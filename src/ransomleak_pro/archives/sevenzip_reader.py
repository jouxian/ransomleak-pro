"""7Z archive reader."""
from __future__ import annotations

import io
import os
import threading
from pathlib import Path
from typing import Generator, Optional

from ..config import MAX_ARCHIVE_RECURSION_DEPTH, MAX_NESTED_ARCHIVE_SIZE, NORMAL_MAX_DEPTH
from ..detection import archive_member_risk, get_filelike_header, get_magic_header, looks_like_archive, magic_to_archive_type
from ..models import ArchiveSafetyContext, ArchiveSource, ArchiveYield
from ..utils import safe_report_text

try:
    import py7zr  # type: ignore
    PY7ZR_AVAILABLE = True
except ImportError:
    py7zr = None
    PY7ZR_AVAILABLE = False

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
