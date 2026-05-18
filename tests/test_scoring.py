from citadel.models import Finding, Severity
from citadel.scoring import calculate_summary


def make_finding(severity: Severity) -> Finding:
    return Finding(
        id=f"TEST-{severity.value}",
        title=f"{severity.value.title()} test finding",
        description="Test finding",
        severity=severity,
        category="test",
        asset="localhost",
        evidence=[],
        impact="Test impact",
        remediation="Test remediation",
        references=[],
    )


def test_score_with_no_findings_is_100() -> None:
    summary = calculate_summary([])

    assert summary.score == 100
    assert summary.total_findings == 0


def test_score_with_one_critical_is_80() -> None:
    summary = calculate_summary([make_finding(Severity.CRITICAL)])

    assert summary.score == 80


def test_score_never_below_zero() -> None:
    findings = [make_finding(Severity.CRITICAL) for _ in range(10)]

    summary = calculate_summary(findings)

    assert summary.score == 0


def test_severity_counts() -> None:
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
        make_finding(Severity.MEDIUM),
        make_finding(Severity.LOW),
        make_finding(Severity.INFO),
    ]

    summary = calculate_summary(findings)

    assert summary.total_findings == 6
    assert summary.critical == 1
    assert summary.high == 2
    assert summary.medium == 1
    assert summary.low == 1
    assert summary.info == 1
