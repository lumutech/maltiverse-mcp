"""Pydantic output models. These define each tool's ``output_schema`` and the
shape of ``structured_content`` the client application receives."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

IndicatorType = Literal["ip", "hostname", "url", "sample"]
Classification = Literal["malicious", "suspicious", "neutral", "whitelist", "unknown"]
ResponseFormat = Literal["concise", "detailed"]


class ThreatLabel(BaseModel):
    """One entry from an indicator's blacklist (a single threat attribution)."""

    description: str = Field(description="Threat/campaign name, e.g. 'Cobalt Strike'.")
    source: str = Field(description="Feed that reported it, e.g. 'ThreatFox Abuse.ch'.")
    labels: list[str] = Field(default_factory=list, description="STIX-style labels.")
    first_seen: str | None = None
    last_seen: str | None = None
    count: int | None = None


class IndicatorReport(BaseModel):
    """Reputation report for one IP, hostname, URL, or malware sample."""

    type: IndicatorType
    value: str = Field(description="The indicator that was looked up.")
    classification: Classification = Field(
        description="Maltiverse verdict: malicious, suspicious, neutral, whitelist, or unknown."
    )
    is_malicious: bool = Field(description="True when classification is 'malicious'.")
    threat_names: list[str] = Field(
        default_factory=list, description="Distinct threat/campaign names across all feeds."
    )
    sources: list[str] = Field(
        default_factory=list, description="Distinct feeds that reported this indicator."
    )
    tags: list[str] = Field(default_factory=list)
    active_flags: list[str] = Field(
        default_factory=list,
        description="Behaviour flags that are true, e.g. 'is_cnc', 'is_tor_node'.",
    )
    first_seen: str | None = None
    last_seen: str | None = None
    summary: str = Field(description="One-line human-readable summary of the verdict.")

    # IP-specific
    as_name: str | None = None
    country_code: str | None = None

    # hostname/URL-specific
    hostname: str | None = None

    # sample-specific
    filetype: str | None = None
    av_ratio: str | None = None

    # Populated only when response_format='detailed'.
    blacklist: list[ThreatLabel] | None = Field(
        default=None, description="Full per-feed attributions (detailed mode only)."
    )


class SearchHit(BaseModel):
    """A compact indicator summary returned by a search."""

    type: str = Field(description="Maltiverse object type, e.g. 'ip', 'hostname', 'url', 'sample'.")
    value: str = Field(description="The indicator (ip_addr/hostname/url/sha256).")
    classification: str
    threat_names: list[str] = Field(default_factory=list)
    last_seen: str | None = None


class SearchResult(BaseModel):
    """A page of search results, with cursor-style pagination."""

    query: str
    total: int = Field(description="Total matching indicators in Maltiverse.")
    returned: int = Field(description="Number of hits in this page.")
    has_more: bool
    next_offset: int | None = Field(
        default=None,
        description="Pass as 'offset' to maltiverse_search to fetch the next page; null at end.",
    )
    results: list[SearchHit] = Field(default_factory=list)
