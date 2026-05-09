"""Pydantic response models for n0s1 MCP tool outputs.

All models are transport-agnostic.  Raw secret values must never appear in
any instance of these models — redaction is enforced in tools.py before
findings reach this layer.
"""
from enum import Enum
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    """A single redacted secret finding."""

    file: str
    line: Optional[int] = None
    type: str
    severity: Severity
    redacted_match: str


class Usage(BaseModel):
    """Token-usage accounting block."""

    tokens_in_estimate: int
    tokens_out_actual: int
    tokens_saved_estimate: int
    savings_pct: float


class ScanSummary(BaseModel):
    """Aggregate counts from a completed scan."""

    total_findings: int
    by_severity: Dict[Severity, int]
    by_type: Dict[str, int]


class ScanResult(BaseModel):
    """Full result returned by every scan_* tool."""

    report_uuid: str
    status: Literal["pending", "running", "complete", "failed"]
    summary: ScanSummary
    findings: Optional[List[Finding]] = None
    next_cursor: Optional[str] = None
    usage: Usage


class Status(BaseModel):
    """Lightweight status check for an existing scan."""

    report_uuid: str
    status: Literal["pending", "running", "complete", "failed"]
    progress_pct: Optional[float] = None
    error: Optional[str] = None


class FindingsPage(BaseModel):
    """Paginated findings list for an existing scan."""

    report_uuid: str
    findings: List[Finding]
    next_cursor: Optional[str] = None
    total: int
    usage: Usage
