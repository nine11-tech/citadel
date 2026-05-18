from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    command: str | None = None
    source: str | None = None
    output: str | None = None
    file_path: str | None = None
    line_number: int | None = None


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    asset: str
    evidence: list[Evidence] = Field(default_factory=list)
    impact: str
    remediation: str
    references: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    score: int
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanReport(BaseModel):
    tool_name: str = "CITADEL"
    version: str = "0.1.0"
    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    summary: ScanSummary
