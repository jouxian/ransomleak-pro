
from ransomleak_pro.detection import archive_member_risk, magic_to_archive_type


def test_magic_detection():
    assert magic_to_archive_type(b"PK\x03\x04rest") == "zip"
    assert magic_to_archive_type(b"Rar!\x1a\x07rest") == "rar"
    assert magic_to_archive_type(b"7z\xbc\xaf\x27\x1crest") == "7z"
    assert magic_to_archive_type(b"plain text") is None


def test_archive_member_risk():
    assert archive_member_risk("../escape.txt") == "PATH TRAVERSAL"
    assert archive_member_risk("/etc/passwd") == "ABSOLUTE PATH"
    assert archive_member_risk(r"C:\\Windows\\x") == "ABSOLUTE PATH"
    assert archive_member_risk("safe/folder/file.txt") is None
