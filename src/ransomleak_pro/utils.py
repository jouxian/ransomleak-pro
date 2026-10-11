"""Formatting, sanitization, and filename helpers."""
from __future__ import annotations

import math
import re
import unicodedata


def format_size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "0 B"

    try:
        size = int(size_bytes)
    except (TypeError, ValueError):
        return "0 B"

    if size <= 0:
        return "0 B"

    units = ("B", "KB", "MB", "GB", "TB", "PB")

    exponent = min(
        int(math.floor(math.log(size, 1024))),
        len(units) - 1,
    )

    value = size / (1024 ** exponent)

    if abs(value - round(value)) < 1e-9:
        text = str(int(round(value)))
    else:
        text = f"{value:.2f}".rstrip("0").rstrip(".")

    return f"{text} {units[exponent]}"


def format_eta(seconds: float | None) -> str:
    if (
        seconds is None
        or seconds < 0
        or math.isinf(seconds)
        or math.isnan(seconds)
    ):
        return "N/A"

    seconds = int(seconds)

    if seconds < 60:
        return f"{seconds}s"

    minutes, seconds = divmod(seconds, 60)

    if minutes < 60:
        return f"{minutes}m {seconds}s"

    hours, minutes = divmod(minutes, 60)

    if hours < 24:
        return f"{hours}h {minutes}m"

    days, hours = divmod(hours, 24)

    return f"{days}d {hours}h"


def safe_report_text(value: object) -> str:
    text = str(value)

    text = (
        text
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )

    return "".join(
        (f"\\u{ord(ch):04x}" if ord(ch) > 255 else f"\\x{ord(ch):02x}")
        if unicodedata.category(ch) in {"Cc", "Cs"}
        or unicodedata.bidirectional(ch) in {"LRE", "RLE", "LRO", "RLO", "PDF", "LRI", "RLI", "FSI", "PDI"}
        or ch in {"\u2028", "\u2029"}
        else ch
        for ch in text
    )


def safe_filename(name: str, fallback: str = "victim") -> str:
    cleaned = re.sub(
        r'[<>:"/\\|?*\x00-\x1F]',
        "_",
        name,
    )

    cleaned = cleaned.strip(" ._")

    cleaned = cleaned[:120].rstrip(" ._") or fallback
    if cleaned.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        cleaned = "_" + cleaned
    return cleaned


def normalize_domain(domain: str) -> str:
    value = (domain or "xxxxx").strip()

    value = re.sub(
        r"^https?://",
        "",
        value,
        flags=re.IGNORECASE,
    )

    value = value.strip().strip("/")

    return value or "xxxxx"
