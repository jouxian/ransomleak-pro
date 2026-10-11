"""Shared bounded stream helpers for archive readers."""
from __future__ import annotations

import threading
from typing import Optional

from ..models import ArchiveSafetyContext

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
