"""Transform raw Maltiverse JSON into typed models + concise text renderings.

The agent reads the text in ``content``; the client application reads the typed
``structured_content``. Both come from the same parse. Everything here is pure
(no I/O) so it is trivial to unit-test.
"""

from __future__ import annotations

from typing import Any, get_args

from maltiverse_mcp.models import (
    Classification,
    IndicatorReport,
    IndicatorType,
    ResponseFormat,
    SearchHit,
    SearchResult,
    ThreatLabel,
)

_VALID_CLASSIFICATIONS = set(get_args(Classification))
# Cap individual long text fields so a single response stays well under the
# 10k-token warning threshold Claude Code applies.
_MAX_LABELS = 25
_TRUNCATE_MARKER = "…[truncated]"


def truncate(text: str, max_chars: int) -> str:
    """Shorten ``text`` to ``max_chars`` with an explicit marker."""
    if len(text) <= max_chars:
        return text
    keep = max(0, max_chars - len(_TRUNCATE_MARKER))
    return text[:keep] + _TRUNCATE_MARKER


def _classification(raw: dict[str, Any]) -> Classification:
    value = str(raw.get("classification", "")).lower()
    return value if value in _VALID_CLASSIFICATIONS else "unknown"  # type: ignore[return-value]


def _active_flags(raw: dict[str, Any]) -> list[str]:
    return sorted(k for k, v in raw.items() if k.startswith("is_") and v is True)


def _blacklist(raw: dict[str, Any]) -> list[ThreatLabel]:
    entries: list[ThreatLabel] = []
    for item in raw.get("blacklist", []) or []:
        if not isinstance(item, dict):
            continue
        entries.append(
            ThreatLabel(
                description=str(item.get("description", "unknown")),
                source=str(item.get("source", "unknown")),
                labels=[str(x) for x in item.get("labels", []) or []],
                first_seen=item.get("first_seen"),
                last_seen=item.get("last_seen"),
                count=item.get("count"),
            )
        )
    return entries


def _distinct(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for v in values:
        if v and v not in seen:
            seen[v] = None
    return list(seen)


def _value_for(raw: dict[str, Any], itype: IndicatorType, fallback: str) -> str:
    key = {
        "ip": "ip_addr",
        "hostname": "hostname",
        "url": "url",
        "sample": "sha256",
    }[itype]
    return str(raw.get(key) or fallback)


def parse_indicator(
    raw: dict[str, Any],
    itype: IndicatorType,
    queried_value: str,
    response_format: ResponseFormat,
) -> IndicatorReport:
    """Build an :class:`IndicatorReport` from a raw Maltiverse object."""
    blacklist = _blacklist(raw)
    threat_names = _distinct([b.description for b in blacklist])[:_MAX_LABELS]
    sources = _distinct([b.source for b in blacklist])[:_MAX_LABELS]
    firsts = [b.first_seen for b in blacklist if b.first_seen]
    lasts = [b.last_seen for b in blacklist if b.last_seen]
    classification = _classification(raw)

    report = IndicatorReport(
        type=itype,
        value=_value_for(raw, itype, queried_value),
        classification=classification,
        is_malicious=classification == "malicious",
        threat_names=threat_names,
        sources=sources,
        tags=[str(t) for t in raw.get("tag", []) or []][:_MAX_LABELS],
        active_flags=_active_flags(raw),
        first_seen=min(firsts) if firsts else None,
        last_seen=max(lasts) if lasts else None,
        summary="",  # filled below
        as_name=raw.get("as_name") if itype == "ip" else None,
        country_code=raw.get("country_code") if itype in ("ip", "hostname") else None,
        hostname=raw.get("hostname") if itype == "hostname" else None,
        filetype=raw.get("filetype") if itype == "sample" else None,
        av_ratio=str(raw["av_ratio"]) if itype == "sample" and "av_ratio" in raw else None,
        blacklist=blacklist if response_format == "detailed" else None,
    )
    report.summary = _summary(report)
    return report


def _summary(report: IndicatorReport) -> str:
    verdict = report.classification.upper()
    parts = [f"{report.type.upper()} {report.value} — {verdict}."]
    if report.threat_names:
        shown = ", ".join(report.threat_names[:5])
        more = "" if len(report.threat_names) <= 5 else f" (+{len(report.threat_names) - 5} more)"
        parts.append(f"{len(report.threat_names)} threat(s): {shown}{more}.")
    if report.sources:
        parts.append(f"{len(report.sources)} feed(s).")
    if report.as_name:
        parts.append(f"AS: {report.as_name}.")
    if report.country_code:
        parts.append(f"Country: {report.country_code}.")
    if report.filetype:
        parts.append(f"Type: {report.filetype}.")
    return " ".join(parts)


def render_indicator_text(report: IndicatorReport, response_format: ResponseFormat) -> str:
    """Concise human/LLM-readable rendering of an indicator report."""
    lines = [report.summary]
    if report.first_seen or report.last_seen:
        lines.append(f"Seen: {report.first_seen or '?'} → {report.last_seen or '?'}")
    if report.active_flags:
        lines.append("Flags: " + ", ".join(report.active_flags))
    if report.tags:
        lines.append("Tags: " + ", ".join(report.tags))
    if response_format == "detailed" and report.blacklist:
        lines.append("Attributions:")
        for b in report.blacklist[:_MAX_LABELS]:
            seen = f" [{b.first_seen} → {b.last_seen}]" if b.last_seen else ""
            lines.append(f"  • {b.description} — {b.source}{seen}")
    elif report.classification == "unknown" and not report.threat_names:
        lines.append(
            "No threat intelligence on record for this indicator (unknown / not blacklisted)."
        )
    return truncate("\n".join(lines), 8000)


def parse_search(
    raw: dict[str, Any],
    query: str,
    offset: int,
    limit: int,
) -> SearchResult:
    """Parse an Elasticsearch-style search response into a :class:`SearchResult`."""
    hits_obj = raw.get("hits", {})
    total_obj = hits_obj.get("total", 0)
    # ES may report total as an int or as {"value": N, "relation": "eq"}.
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj or 0)
    raw_hits = hits_obj.get("hits", []) or []

    results: list[SearchHit] = []
    for hit in raw_hits:
        src = hit.get("_source", {}) if isinstance(hit, dict) else {}
        if not isinstance(src, dict):
            continue
        itype = str(src.get("type", "unknown"))
        value = str(
            src.get("ip_addr")
            or src.get("hostname")
            or src.get("url")
            or src.get("sha256")
            or hit.get("_id", "")
        )
        threats = _distinct([b.description for b in _blacklist(src)])[:5]
        lasts = [b.last_seen for b in _blacklist(src) if b.last_seen]
        results.append(
            SearchHit(
                type=itype,
                value=value,
                classification=str(src.get("classification", "unknown")),
                threat_names=threats,
                last_seen=max(lasts) if lasts else None,
            )
        )

    returned = len(results)
    has_more = (offset + returned) < total
    return SearchResult(
        query=query,
        total=total,
        returned=returned,
        has_more=has_more,
        next_offset=(offset + limit) if has_more else None,
        results=results,
    )


def render_search_text(result: SearchResult) -> str:
    """Concise rendering of a search result page."""
    more = f" — more available (next_offset={result.next_offset})" if result.has_more else ""
    header = f"{result.returned} of {result.total} result(s) for {result.query!r}{more}"
    lines = [header]
    for hit in result.results:
        threats = f" [{', '.join(hit.threat_names)}]" if hit.threat_names else ""
        lines.append(f"  • {hit.type}: {hit.value} ({hit.classification}){threats}")
    if not result.results:
        lines.append("  (no matches — try a broader query)")
    return truncate("\n".join(lines), 8000)
