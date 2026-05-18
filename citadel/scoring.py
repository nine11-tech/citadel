from __future__ import annotations

from citadel.models import Finding, ScanSummary, Severity


SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def calculate_summary(findings: list[Finding]) -> ScanSummary:
    score = 100
    counts = {severity: 0 for severity in Severity}

    for finding in findings:
        counts[finding.severity] += 1
        score -= SEVERITY_PENALTIES[finding.severity]

    return ScanSummary(
        score=max(score, 0),
        total_findings=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
    )
