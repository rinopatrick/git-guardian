"""CLI entry point for Git Guardian."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from git_guardian.models.package import RiskLevel, ScanResult

app = typer.Typer(
    name="git-guardian",
    help="AI-powered supply chain security scanner for npm packages.",
    add_completion=False,
)
console = Console()


def _risk_style(level: RiskLevel) -> str:
    """Get Rich style for risk level."""
    styles = {
        RiskLevel.SAFE: "green",
        RiskLevel.LOW: "yellow",
        RiskLevel.MEDIUM: "dark_orange",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }
    return styles.get(level, "white")


def _print_scan_result(result: ScanResult) -> None:
    """Print scan result in a nice format."""
    # Package info panel
    pkg = result.package
    info_text = f"[bold]{pkg.name}[/bold] v{pkg.latest_version}\n"
    if pkg.description:
        info_text += f"{pkg.description}\n"
    if pkg.author:
        info_text += f"Author: {pkg.author.name or 'N/A'}\n"
    info_text += f"License: {pkg.license or 'N/A'}\n"

    console.print(Panel(info_text, title="Package Info", border_style="blue"))

    # Risk level
    risk_style = _risk_style(result.risk_level)
    console.print(
        f"\n[bold]Risk Level:[/bold] [{risk_style}]{result.risk_level.value.upper()}[/{risk_style}]"
    )
    console.print(f"Scan Duration: {result.scan_duration_seconds:.2f}s\n")

    # Findings table
    if result.findings:
        table = Table(title="Security Findings", show_lines=True)
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Risk", width=10)
        table.add_column("Title", width=30)
        table.add_column("File", width=25)
        table.add_column("Description", width=50)

        for finding in result.findings:
            risk_style = _risk_style(finding.risk_level)
            table.add_row(
                finding.rule_id,
                f"[{risk_style}]{finding.risk_level.value.upper()}[/{risk_style}]",
                finding.title,
                finding.file_path or "-",
                finding.description[:100] + "..."
                if len(finding.description) > 100
                else finding.description,
            )

        console.print(table)
    else:
        console.print("[green]No security issues found.[/green]")

    # AI Analysis
    if result.ai_analysis:
        console.print(
            Panel(result.ai_analysis, title="AI Analysis", border_style="magenta")
        )

    # Summary
    counts = result.finding_count
    console.print("\n[bold]Summary:[/bold]")
    for level, count in counts.items():
        if count > 0:
            style = _risk_style(level)
            console.print(f"  [{style}]{level.value.upper()}: {count}[/{style}]")


@app.command()
def scan(
    package_name: str = typer.Argument(..., help="npm package name to scan"),
    version: str | None = typer.Option(None, "--version", "-v", help="Specific version to scan"),
    deep: bool = typer.Option(False, "--deep", "-d", help="Enable AI-powered deep analysis"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analysis"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Scan an npm package for security issues."""
    from git_guardian.scanner.service import ScanService

    console.print(f"\n[bold blue]Scanning package:[/bold blue] {package_name}\n")

    try:
        with ScanService(enable_ai=deep and not no_ai) as service:
            console.print("Fetching package metadata...")
            result = service.scan_package(package_name, version)

        # Output
        if json_output:
            import json

            print(json.dumps(result.model_dump(), indent=2, default=str))
        else:
            _print_scan_result(result)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def rules() -> None:
    """List all detection rules."""
    from git_guardian.scanner.patterns import PatternDetector

    detector = PatternDetector()
    rules_list = detector.get_rules()

    table = Table(title="Detection Rules")
    table.add_column("ID", style="cyan", width=12)
    table.add_column("Risk", width=10)
    table.add_column("Title", width=30)
    table.add_column("Description", width=50)

    for rule in rules_list:
        risk_style = _risk_style(rule.risk_level)
        table.add_row(
            rule.rule_id,
            f"[{risk_style}]{rule.risk_level.value.upper()}[/{risk_style}]",
            rule.title,
            rule.description[:80] + "..."
            if len(rule.description) > 80
            else rule.description,
        )

    console.print(table)
    console.print(f"\nTotal rules: {len(rules_list)}")


@app.command()
def version() -> None:
    """Show version information."""
    from git_guardian import __version__

    console.print(f"Git Guardian v{__version__}")


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to bind"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
) -> None:
    """Start the web server."""
    import uvicorn

    console.print(f"[bold blue]Starting Git Guardian web server...[/bold blue]")
    console.print(f"Open http://{host}:{port} in your browser")

    uvicorn.run(
        "git_guardian.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
