from datetime import datetime

from citadel.advisor import AdvisorMode, build_ai_prompt, build_offline_advisory, generate_advisory
from citadel.models import Finding, ScanReport, ScanSummary, Severity


def make_report() -> ScanReport:
    findings = [
        Finding(
            id="DOCKER-001",
            title="Privileged container enabled",
            description="The service runs with privileged container access.",
            severity=Severity.CRITICAL,
            category="docker",
            asset="app",
            evidence=[],
            impact="Privileged containers can bypass normal container isolation controls.",
            remediation="Remove privileged mode.",
            references=[],
        ),
        Finding(
            id="DOCKER-004",
            title="Image tag is latest or missing",
            description="The service image does not pin an explicit version tag.",
            severity=Severity.MEDIUM,
            category="docker",
            asset="app",
            evidence=[],
            impact="Unpinned images can change unexpectedly.",
            remediation="Pin images to a specific version tag or digest.",
            references=[],
        ),
    ]
    return ScanReport(
        target="examples/vulnerable-docker",
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        finished_at=datetime(2026, 1, 1, 12, 1, 0),
        findings=findings,
        summary=ScanSummary(
            score=75,
            total_findings=2,
            critical=1,
            high=0,
            medium=1,
            low=0,
            info=0,
        ),
    )


def test_offline_advisory_contains_title() -> None:
    advisory = build_offline_advisory(make_report())

    assert "CITADEL Risk Advisory" in advisory


def test_offline_advisory_contains_target() -> None:
    advisory = build_offline_advisory(make_report())

    assert "examples/vulnerable-docker" in advisory


def test_offline_advisory_contains_score() -> None:
    advisory = build_offline_advisory(make_report())

    assert "75/100" in advisory


def test_offline_advisory_includes_top_findings() -> None:
    advisory = build_offline_advisory(make_report())

    assert "Top findings" in advisory
    assert "DOCKER-001" in advisory
    assert "Privileged container enabled" in advisory


def test_generate_advisory_with_ollama_includes_offline_fallback() -> None:
    advisory = generate_advisory(make_report(), AdvisorMode.OLLAMA)

    assert "Ollama advisory mode is planned" in advisory
    assert "CITADEL Risk Advisory" in advisory


def test_build_ai_prompt_includes_defensive_instructions_and_avoids_exploit_focus() -> None:
    prompt = build_ai_prompt(make_report())

    assert "defensive cybersecurity analyst" in prompt
    assert "Avoid exploit instructions" in prompt
    assert "remediation" in prompt.lower()
