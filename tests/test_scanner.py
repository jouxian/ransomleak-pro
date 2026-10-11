import io
import zipfile
from datetime import datetime
from pathlib import Path

from ransomleak_pro.models import ScanOptions
from ransomleak_pro.scanner import ForensicScanner


def _zip_bytes(name: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, content)
    return buffer.getvalue()


def test_scanner_finds_files_and_nested_zip(tmp_path: Path):
    root = tmp_path / "dataset"
    root.mkdir()
    (root / "plain.txt").write_text("hello", encoding="utf-8")
    inner = _zip_bytes("inside.txt", b"inside")
    with zipfile.ZipFile(root / "outer.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested.zip", inner)

    options = ScanOptions(
        root_path=root,
        deep_mode="normal",
        aggressive_magic=False,
        verbose=False,
        victim="case",
        domain="example.com",
        started_at=datetime.now(),
    )
    result = ForensicScanner().scan(options)
    assert result.cancelled is False
    assert result.counters.filesystem_files == 2
    assert result.counters.archives_found == 1
    assert result.counters.nested_archives_found >= 1
    assert any("plain.txt" in row for row in result.entries)
    assert any("inside.txt" in row for row in result.entries)
