"""Pure-function tests for parsing, rendering, and truncation."""

from __future__ import annotations

from maltiverse_mcp.formatting import (
    _TRUNCATE_MARKER,
    parse_indicator,
    render_indicator_text,
    truncate,
)


def test_truncate_marks_cut_text() -> None:
    assert truncate("short", 100) == "short"
    out = truncate("x" * 500, 50)
    assert len(out) == 50
    assert out.endswith(_TRUNCATE_MARKER)


def test_parse_caps_huge_blacklist_and_truncates_text() -> None:
    raw = {
        "type": "ip",
        "ip_addr": "1.1.1.1",
        "classification": "malicious",
        "blacklist": [
            {"description": f"Threat-{i}", "source": f"feed-{i}", "last_seen": "2024-01-01"}
            for i in range(200)
        ],
    }
    report = parse_indicator(raw, "ip", "1.1.1.1", "detailed")
    # Distinct threat names are capped so the response stays bounded.
    assert len(report.threat_names) <= 25
    text = render_indicator_text(report, "detailed")
    assert len(text) <= 8000


def test_unknown_classification_is_normalised() -> None:
    report = parse_indicator({"type": "ip", "ip_addr": "2.2.2.2"}, "ip", "2.2.2.2", "concise")
    assert report.classification == "unknown"
    assert report.is_malicious is False
    assert "No threat intelligence" in render_indicator_text(report, "concise")
