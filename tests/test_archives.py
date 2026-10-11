import io
import threading

import pytest

from ransomleak_pro.archives import read_stream_limited
from ransomleak_pro.models import ArchiveSafetyContext


def test_limited_stream_reader_accepts_small_stream():
    safety = ArchiveSafetyContext(max_nested_bytes=100)
    data = read_stream_limited(io.BytesIO(b"hello"), 10, threading.Event(), safety)
    assert data == b"hello"
    assert safety.nested_bytes_read == 5


def test_limited_stream_reader_rejects_over_limit():
    with pytest.raises(ValueError):
        read_stream_limited(io.BytesIO(b"0123456789"), 5, threading.Event())
