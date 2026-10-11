from ransomleak_pro.utils import format_eta, format_size, normalize_domain, safe_filename, safe_report_text


def test_format_size_and_eta():
    assert format_size(0) == "0 B"
    assert format_size(1024) == "1 KB"
    assert format_eta(65) == "1m 5s"


def test_normalize_domain_and_filename():
    assert normalize_domain("https://example.com/") == "example.com"
    assert safe_filename('bad:name?.txt') == "bad_name_.txt"


def test_safe_report_text_escapes_controls():
    assert safe_report_text("a\tb\nc") == "a\\tb\\nc"
