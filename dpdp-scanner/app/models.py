"""Shared data models passed between agents."""
from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field

FindingType = Literal[
    "form_field", "cookie", "third_party_script", "consent_banner", "privacy_policy"
]
DataCategory = Literal[
    "contact", "financial", "health", "children", "behavioral", "identity", "none"
]
DPDPRelevance = Literal[
    "notice", "consent", "security_safeguard", "children_data",
    "cross_border_transfer", "none",
]
Confidence = Literal["high", "medium", "low"]
Severity = Literal["high", "medium", "low"]


class RawFinding(BaseModel):
    """What the Crawler Agent extracts, before classification."""
    url: str
    type: FindingType
    detail: str
    # crawler-native metadata, used both for classifier context and detail_hash
    field_name: Optional[str] = None
    field_type: Optional[str] = None
    domain: Optional[str] = None
    raw: dict = Field(default_factory=dict)


class ClassifiedFinding(BaseModel):
    """What the Classifier Agent outputs — matches the spec's JSON schema."""
    url: str
    type: FindingType
    detail: str
    data_category: DataCategory = "none"
    third_party_domain: Optional[str] = None
    dpdp_relevance: DPDPRelevance = "none"
    confidence: Confidence = "medium"
    detail_hash: str = ""  # filled in by classifier/diff normalization step


class PageCrawlResult(BaseModel):
    url: str
    status_code: Optional[int] = None
    html_hash: Optional[str] = None
    forms: list[dict] = Field(default_factory=list)
    cookies: list[dict] = Field(default_factory=list)
    scripts: list[dict] = Field(default_factory=list)
    consent_banner: Optional[dict] = None
    is_privacy_policy: bool = False
    privacy_policy_hash: Optional[str] = None
    privacy_policy_text_excerpt: Optional[str] = None
    error: Optional[str] = None


class CrawlReport(BaseModel):
    domain: str
    started_at: str
    finished_at: str
    pages: list[PageCrawlResult] = Field(default_factory=list)
    page_count: int = 0


class DiffEntry(BaseModel):
    finding: dict          # classified finding dict (as stored)
    severity: Severity
    reason: str             # short human-readable "why this severity"


class DiffResult(BaseModel):
    client_id: int
    prev_scan_id: Optional[int]
    curr_scan_id: int
    new: list[DiffEntry] = Field(default_factory=list)
    changed: list[DiffEntry] = Field(default_factory=list)
    removed: list[DiffEntry] = Field(default_factory=list)
    severity: Severity = "low"  # max severity across new+changed
