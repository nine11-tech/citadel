from __future__ import annotations

from enum import Enum

from citadel.models import Finding, ScanReport, Severity


class AdvisorMode(str, Enum):
    OFFLINE = "offline"
    OLLAMA = "ollama"
    OPENAI = "openai"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def build_offline_advisory(report: ScanReport) -> str:
    top_findings = sorted(report.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])[:5]

    lines = [
        "# CITADEL Risk Advisory",
        "",
        f"**Target:** {report.target}",
        f"**Global score:** {report.summary.score}/100",
        "",
        "## Severity summary",
        "",
        f"- Critical: {report.summary.critical}",
        f"- High: {report.summary.high}",
        f"- Medium: {report.summary.medium}",
        f"- Low: {report.summary.low}",
        f"- Info: {report.summary.info}",
        f"- Total findings: {report.summary.total_findings}",
        "",
        "## Executive summary",
        "",
        _executive_summary(report),
        "",
        "## Top findings",
        "",
    ]

    if top_findings:
        for index, finding in enumerate(top_findings, start=1):
            lines.extend(_finding_summary(index, finding))
    else:
        lines.append("No findings were identified in this report.")

    lines.extend(
        [
            "",
            "## Remediation priority",
            "",
            "1. Resolve critical findings first, especially issues that weaken container isolation "
            "or expose host control surfaces.",
            "2. Address high findings second, focusing on reduced privileges, network exposure, "
            "and sensitive configuration handling.",
            "3. Remediate medium findings third by pinning versions, reducing exposed services, "
            "and enforcing safer runtime defaults.",
            "",
            "## Defensive next steps",
            "",
            "- Validate each finding against the intended deployment architecture.",
            "- Apply least privilege to container users, capabilities, mounts, and network settings.",
            "- Move sensitive values out of Compose files and into an approved secret management flow.",
            "- Re-run CITADEL after remediation to confirm score and finding count improvements.",
            "- Preserve generated JSON and Markdown reports for audit evidence and change tracking.",
            "",
            "## Limitations",
            "",
            "Offline mode uses deterministic rule-based analysis. It does not call external AI services, "
            "does not infer business context beyond the scan report, and should be reviewed by a "
            "qualified cybersecurity specialist before operational decisions are finalized.",
        ]
    )

    return "\n".join(lines) + "\n"


def build_ai_prompt(report: ScanReport) -> str:
    findings = "\n".join(
        (
            f"- {finding.id} | {finding.severity.value} | {finding.category} | "
            f"{finding.asset} | {finding.title} | Impact: {finding.impact} | "
            f"Remediation: {finding.remediation}"
        )
        for finding in report.findings
    )
    if not findings:
        findings = "- No findings reported."

    return (
        "Act as a defensive cybersecurity analyst reviewing a local-first CITADEL audit report.\n"
        "Summarize the report, prioritize remediation, and explain operational impact clearly.\n"
        "Avoid exploit instructions, offensive procedures, payloads, or step-by-step abuse guidance.\n"
        "Keep the output professional, concise, and remediation-oriented.\n\n"
        f"Target: {report.target}\n"
        f"Score: {report.summary.score}/100\n"
        "Severity counts:\n"
        f"- Critical: {report.summary.critical}\n"
        f"- High: {report.summary.high}\n"
        f"- Medium: {report.summary.medium}\n"
        f"- Low: {report.summary.low}\n"
        f"- Info: {report.summary.info}\n\n"
        "Findings:\n"
        f"{findings}\n"
    )


def generate_advisory(report: ScanReport, mode: AdvisorMode = AdvisorMode.OFFLINE) -> str:
    offline_advisory = build_offline_advisory(report)

    if mode is AdvisorMode.OFFLINE:
        return offline_advisory

    if mode is AdvisorMode.OLLAMA:
        return (
            "> Ollama advisory mode is planned but not implemented yet. "
            "Falling back to offline rule-based advisory.\n\n"
            f"{offline_advisory}"
        )

    if mode is AdvisorMode.OPENAI:
        return (
            "> OpenAI advisory mode is planned but not implemented yet. "
            "Falling back to offline rule-based advisory.\n\n"
            f"{offline_advisory}"
        )

    return offline_advisory


def _executive_summary(report: ScanReport) -> str:
    if report.summary.total_findings == 0:
        return (
            "CITADEL did not identify findings in this report. Continue to validate the target "
            "against internal hardening standards and monitor for configuration drift."
        )

    highest = min((finding.severity for finding in report.findings), key=lambda item: SEVERITY_ORDER[item])
    return (
        f"CITADEL identified {report.summary.total_findings} finding(s), with the highest severity "
        f"rated as {highest.value}. The current score is {report.summary.score}/100. "
        "Remediation should prioritize issues that reduce isolation, expose sensitive services, "
        "or place secrets and privileged access in runtime configuration."
    )


def _finding_summary(index: int, finding: Finding) -> list[str]:
    return [
        f"{index}. **{finding.id}: {finding.title}**",
        f"   - Severity: {finding.severity.value}",
        f"   - Asset: {finding.asset}",
        f"   - Impact: {finding.impact}",
        f"   - Remediation: {finding.remediation}",
        "",
    ]
