from datetime import datetime
from pathlib import Path

from ransomleak_pro.models import ScanCounters, ScanOptions, ScanResult
from ransomleak_pro.reporting import write_forensic_report


def test_report_is_atomic_and_contains_digest(tmp_path: Path):
    root = tmp_path / "dataset"
    root.mkdir()
    output = tmp_path / "report.txt"
    options = ScanOptions(
        root_path=root,
        deep_mode="normal",
        aggressive_magic=False,
        verbose=False,
        victim="case",
        domain="example.com",
        started_at=datetime.now(),
    )
    result = ScanResult(
        entries=("file.txt[5 B]",),
        counters=ScanCounters(report_rows=1, filesystem_files=1, processed_files=1, total_size_bytes=5),
        started_at=options.started_at,
        completed_at=datetime.now(),
        elapsed_seconds=0.1,
        cancelled=False,
    )
    digest = write_forensic_report(output, result, options)
    text = output.read_text(encoding="utf-8")
    assert "# REPORT FORMAT VERSION: 5" in text
    assert f"# DATA LINES SHA256: {digest}" in text
    assert "file.txt[5 B]" in text
