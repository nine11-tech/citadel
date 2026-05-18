from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from citadel.advisor import AdvisorMode, generate_advisory
from citadel.models import Evidence, Finding, ScanReport, Severity
from citadel.scanners.docker import scan_docker_compose
from citadel.scoring import calculate_summary

app = typer.Typer(help="CITADEL - Local-first blue-team security assessment toolkit")
console = Console()


@app.command()
def version():
    """Show CITADEL version."""
    console.print("[bold cyan]CITADEL[/bold cyan] v0.1.0")


@app.command()
def scan(
    target: str = typer.Argument("."),
    json_output: Path | None = typer.Option(
        None,
        "--json-output",
        help="Write the scan report as JSON to this path.",
    ),
):
    """Run a basic security scan."""
    started_at = datetime.now()
    console.print(f"[bold green]Scanning target:[/bold green] {target}")

    findings = scan_docker_compose(target)
    if not findings:
        findings = [
            Finding(
                id="CIT-DEMO-001",
                title="Demo finding for report pipeline validation",
                description="This placeholder finding exercises CITADEL's reporting and scoring flow.",
                severity=Severity.LOW,
                category="configuration",
                asset=target,
                evidence=[
                    Evidence(
                        source="demo",
                        output="Scanner modules are not implemented yet.",
                    )
                ],
                impact="No real issue was detected. This finding is for demonstration only.",
                remediation="Replace the demo scanner with real defensive audit checks.",
                references=[],
            )
        ]
    summary = calculate_summary(findings)
    finished_at = datetime.now()

    table = Table(title="Findings")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="magenta")
    table.add_column("Category")
    table.add_column("Asset")
    table.add_column("Title")

    for finding in findings:
        table.add_row(
            finding.id,
            finding.severity.value,
            finding.category,
            finding.asset,
            finding.title,
        )

    console.print(table)
    console.print(f"[bold]Final score:[/bold] {summary.score}")

    if json_output is not None:
        report = ScanReport(
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            findings=findings,
            summary=summary,
        )
        json_output.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(report, "model_dump_json"):
            report_json = report.model_dump_json(indent=2)
        else:
            report_json = report.json(indent=2)
        json_output.write_text(f"{report_json}\n", encoding="utf-8")
        console.print(f"[bold green]JSON report written:[/bold green] {json_output}")


@app.command()
def advisor(
    report_json: Path = typer.Argument(..., help="Path to a CITADEL ScanReport JSON file."),
    mode: AdvisorMode = typer.Option(
        AdvisorMode.OFFLINE,
        "--mode",
        help="Advisory mode: offline, ollama, or openai.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        help="Write the advisory Markdown to this path.",
    ),
):
    """Generate a risk advisory from a scan report."""
    report_data = report_json.read_text(encoding="utf-8")
    if hasattr(ScanReport, "model_validate_json"):
        report = ScanReport.model_validate_json(report_data)
    else:
        report = ScanReport.parse_raw(report_data)

    advisory_text = generate_advisory(report, mode)

    if output is None:
        console.print(advisory_text)
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(advisory_text, encoding="utf-8")
    console.print(f"[bold green]Advisory written:[/bold green] {output}")


if __name__ == "__main__":
    app()
