import typer
from rich.console import Console

app = typer.Typer(help="CITADEL - Local-first blue-team security assessment toolkit")
console = Console()


@app.command()
def version():
    """Show CITADEL version."""
    console.print("[bold cyan]CITADEL[/bold cyan] v0.1.0")


@app.command()
def scan(target: str = "."):
    """Run a basic security scan."""
    console.print(f"[bold green]Scanning target:[/bold green] {target}")
    console.print("[yellow]Scanner modules will be implemented next.[/yellow]")


if __name__ == "__main__":
    app()
