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

    console.print("[bold blue]Starting Git Guardian web server...[/bold blue]")
    console.print(f"Open http://{host}:{port} in your browser")

    uvicorn.run(
        "git_guardian.api.app:app",
        host=host,
        port=port,
        reload=reload,
    )


# === Watchlist Commands ===

@app.command()
def watchlist_add(
    package_name: str = typer.Argument(..., help="npm package name to watch"),
    notes: str | None = typer.Option(None, "--notes", "-n", help="Notes about this package"),
) -> None:
    """Add a package to the watchlist."""
    import asyncio

    from git_guardian.db.database import async_session, init_db
    from git_guardian.services.watchlist_service import WatchlistService

    async def _run():
        await init_db()
        async with async_session() as session:
            service = WatchlistService(session)
            entry = await service.add_package(package_name, notes)
            await session.commit()
            console.print(f"[green]Added[/green] {entry.package_name} to watchlist (id: {entry.id})")

    asyncio.run(_run())


@app.command()
def watchlist_list() -> None:
    """List watchlist entries."""
    import asyncio

    from git_guardian.db.database import async_session, init_db
    from git_guardian.services.watchlist_service import WatchlistService

    async def _run():
        await init_db()
        async with async_session() as session:
            service = WatchlistService(session)
            entries = await service.list_entries()

            if not entries:
                console.print("[yellow]Watchlist is empty[/yellow]")
                return

            table = Table(title="Package Watchlist")
            table.add_column("Package", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Last Risk", style="red")
            table.add_column("Scans", justify="right")
            table.add_column("Last Scan")

            for e in entries:
                last_scan = e.last_scan_at.strftime("%Y-%m-%d %H:%M") if e.last_scan_at else "Never"
                table.add_row(
                    e.package_name,
                    e.status,
                    e.last_risk_level or "-",
                    str(e.scan_count),
                    last_scan,
                )

            console.print(table)

    asyncio.run(_run())


@app.command()
def watchlist_remove(
    package_name: str = typer.Argument(..., help="Package to remove from watchlist"),
) -> None:
    """Remove a package from the watchlist."""
    import asyncio

    from git_guardian.db.database import async_session, init_db
    from git_guardian.services.watchlist_service import WatchlistService

    async def _run():
        await init_db()
        async with async_session() as session:
            service = WatchlistService(session)
            removed = await service.remove_package(package_name)
            await session.commit()

            if removed:
                console.print(f"[green]Removed[/green] {package_name} from watchlist")
            else:
                console.print(f"[red]{package_name} not found in watchlist[/red]")

    asyncio.run(_run())


# === Dependency Commands ===

@app.command()
def deps(
    package_name: str = typer.Argument(..., help="npm package to scan dependencies"),
    max_depth: int = typer.Option(3, "--depth", "-d", help="Max dependency depth"),
    max_packages: int = typer.Option(50, "--max", "-m", help="Max packages to scan"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Scan transitive dependencies of a package."""
    import json

    from git_guardian.services.dependency_scanner import DependencyScanner

    console.print(f"\n[bold blue]Scanning dependencies:[/bold blue] {package_name}\n")

    try:
        with DependencyScanner(max_depth=max_depth, max_packages=max_packages) as scanner:
            result = scanner.scan_dependencies(package_name)

        if json_output:
            print(json.dumps(result.to_dict(), indent=2, default=str))
        else:
            console.print(f"Root: [bold]{result.root_package}[/bold] v{result.root_version}")
            console.print(f"Packages scanned: {result.total_packages}")
            console.print(f"Total findings: {result.total_findings}")
            console.print(f"Packages with findings: {result.packages_with_findings}")
            console.print(f"Max depth reached: {result.max_depth_reached}")
            console.print(f"Duration: {result.scan_duration_seconds:.2f}s")

            # Print tree
            _print_dep_tree(result.graph)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


def _print_dep_tree(node, prefix="", is_last=True):
    """Print dependency tree."""
    connector = "└── " if is_last else "├── "
    risk_style = _risk_style(node.risk_level) if hasattr(node.risk_level, 'value') else "white"
    risk_val = node.risk_level.value if hasattr(node.risk_level, 'value') else node.risk_level

    findings_info = f" [{risk_style}]{risk_val.upper()}[/{risk_style}]" if risk_val != "safe" else ""
    error_info = f" [red]({node.error})[/red]" if node.error else ""

    console.print(f"{prefix}{connector}{node.name}@{node.version}{findings_info}{error_info}")

    if node.children:
        extension = "    " if is_last else "│   "
        for i, child in enumerate(node.children):
            _print_dep_tree(child, prefix + extension, i == len(node.children) - 1)


# === Export Commands ===

@app.command()
def export(
    format: str = typer.Option("json", "--format", "-f", help="Export format (json/csv)"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max records"),
    risk: str | None = typer.Option(None, "--risk", "-r", help="Filter by risk level"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Export scan history."""
    import asyncio

    from git_guardian.db.database import async_session, init_db
    from git_guardian.services.export_service import ExportService

    async def _run():
        await init_db()
        async with async_session() as session:
            service = ExportService(session)

            if format == "csv":
                data = await service.export_scans_csv(limit=limit, risk_level=risk)
            else:
                data = await service.export_scans_json(limit=limit, risk_level=risk)

            if output:
                with open(output, "w") as f:
                    f.write(data)
                console.print(f"[green]Exported to {output}[/green]")
            else:
                print(data)

    asyncio.run(_run())


# === Task Commands ===

@app.command()
def tasks() -> None:
    """List background tasks."""
    from git_guardian.workers.task_manager import get_task_manager

    manager = get_task_manager()
    all_tasks = manager.get_all_tasks()

    if not all_tasks:
        console.print("[yellow]No background tasks[/yellow]")
        return

    table = Table(title="Background Tasks")
    table.add_column("ID", style="cyan", width=8)
    table.add_column("Type", width=15)
    table.add_column("Status", width=12)
    table.add_column("Progress", width=10)
    table.add_column("Package(s)", width=30)

    for t in all_tasks:
        status_style = {
            "pending": "yellow",
            "running": "blue",
            "completed": "green",
            "failed": "red",
            "cancelled": "dim",
        }.get(t.status.value, "white")

        pkg = t.package_name or ", ".join(t.packages[:3])
        if len(t.packages) > 3:
            pkg += f" (+{len(t.packages) - 3})"

        table.add_row(
            t.id[:8],
            t.task_type.value,
            f"[{status_style}]{t.status.value}[/{status_style}]",
            f"{t.progress}/{t.total}",
            pkg,
        )

    console.print(table)


# === Alert Commands ===

@app.command()
def alerts() -> None:
    """List security alerts."""
    import asyncio

    from git_guardian.db.database import async_session, init_db
    from git_guardian.services.alert_service import AlertService

    async def _run():
        await init_db()
        async with async_session() as session:
            service = AlertService(session)
            alert_list = await service.list_alerts(limit=20)

            if not alert_list:
                console.print("[green]No alerts[/green]")
                return

            table = Table(title="Security Alerts")
            table.add_column("Severity", width=10)
            table.add_column("Package", style="cyan")
            table.add_column("Title", width=40)
            table.add_column("Read", width=5)
            table.add_column("Resolved", width=8)

            for a in alert_list:
                sev_style = {
                    "critical": "bold red",
                    "warning": "yellow",
                    "info": "blue",
                }.get(a.severity, "white")

                table.add_row(
                    f"[{sev_style}]{a.severity.upper()}[/{sev_style}]",
                    a.package_name,
                    a.title[:40],
                    "✓" if a.is_read else "✗",
                    "✓" if a.is_resolved else "✗",
                )

            console.print(table)

    asyncio.run(_run())


# === Phase 6: License Commands ===

@app.command()
def license_check(
    package_name: str = typer.Argument(..., help="npm package to check license"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Check license compliance of a package."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.license_scanner import LicenseScanner

    console.print(f"\n[bold blue]License scan:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        scanner = LicenseScanner()
        report = scanner.scan_package(pkg_info)

        if json_output:
            import json
            print(json.dumps({
                "package": report.package_name,
                "license": report.license_id,
                "type": report.license_type,
                "is_risky": report.is_risky,
                "is_compliant": report.is_compliant,
                "findings": [f.model_dump() for f in report.findings],
            }, indent=2))
        else:
            risk_style = _risk_style(RiskLevel.HIGH if report.is_risky else RiskLevel.SAFE)
            console.print(f"License: [bold]{report.license_id or 'NONE'}[/bold]")
            console.print(f"Type: [{risk_style}]{report.license_type}[/{risk_style}]")
            console.print(f"Risky: {'Yes' if report.is_risky else 'No'}")
            console.print(f"Compliant: {'Yes' if report.is_compliant else 'No'}")

            if report.findings:
                table = Table(title="License Findings", show_lines=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Risk", width=10)
                table.add_column("Title", width=30)
                table.add_column("Description", width=50)
                for f in report.findings:
                    table.add_row(f.rule_id, f"[{_risk_style(f.risk_level)}]{f.risk_level.value.upper()}[/{_risk_style(f.risk_level)}]", f.title, f.description[:80])
                console.print(table)

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def health(
    package_name: str = typer.Argument(..., help="npm package to score"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Score package health across multiple dimensions."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.health_scorer import HealthScorer

    console.print(f"\n[bold blue]Health score:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        scorer = HealthScorer()
        report = scorer.score_package(pkg_info)

        if json_output:
            import json
            print(json.dumps({
                "package": report.package_name,
                "score": report.overall_score,
                "grade": report.grade,
                "risk_level": report.risk_level.value,
                "dimensions": [{"name": d.name, "score": d.score, "weight": d.weight, "issues": d.issues} for d in report.dimensions],
                "recommendations": report.recommendations,
            }, indent=2))
        else:
            grade_colors = {"A": "green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "red"}
            color = grade_colors.get(report.grade, "white")
            console.print(f"Score: [{color}]{report.overall_score}/100 ({report.grade})[/{color}]")
            console.print(f"Risk: [{_risk_style(report.risk_level)}]{report.risk_level.value.upper()}[/{_risk_style(report.risk_level)}]\n")

            table = Table(title="Health Dimensions")
            table.add_column("Dimension", style="cyan")
            table.add_column("Score", justify="right")
            table.add_column("Weight", justify="right")
            table.add_column("Issues")
            for d in report.dimensions:
                score_color = "green" if d.score >= 70 else "yellow" if d.score >= 50 else "red"
                table.add_row(d.name, f"[{score_color}]{d.score}[/{score_color}]", f"{d.weight:.0%}", "; ".join(d.issues) or "None")
            console.print(table)

            if report.recommendations:
                console.print("\n[bold]Recommendations:[/bold]")
                for r in report.recommendations[:10]:
                    console.print(f"  - {r}")

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def audit(
    package_name: str = typer.Argument(..., help="npm package to audit"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Audit package.json for risky configurations."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.package_audit import PackageAuditor

    console.print(f"\n[bold blue]Package audit:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        files = npm.get_package_files(package_name)

        # Parse package.json
        pkg_json_content = files.get("package.json", "{}")
        import json
        pkg_json = json.loads(pkg_json_content)

        auditor = PackageAuditor()
        report = auditor.audit_package_json(pkg_json, package_name)

        if json_output:
            print(json.dumps({
                "package": report.package_name,
                "is_clean": report.is_clean,
                "scripts": report.scripts,
                "risky_configs": report.risky_configs,
                "findings": [f.model_dump() for f in report.findings],
            }, indent=2, default=str))
        else:
            status = "[green]CLEAN[/green]" if report.is_clean else f"[red]{len(report.findings)} ISSUE(S)[/red]"
            console.print(f"Status: {status}")

            if report.scripts:
                console.print(f"\n[bold]Scripts ({len(report.scripts)}):[/bold]")
                for name, cmd in report.scripts.items():
                    style = "red" if name in ("preinstall", "postinstall", "install") else "white"
                    console.print(f"  [{style}]{name}[/{style}]: {cmd[:100]}")

            if report.findings:
                table = Table(title="Audit Findings", show_lines=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Risk", width=10)
                table.add_column("Title", width=30)
                table.add_column("Description", width=50)
                for f in report.findings:
                    table.add_row(f.rule_id, f"[{_risk_style(f.risk_level)}]{f.risk_level.value.upper()}[/{_risk_style(f.risk_level)}]", f.title, f.description[:80])
                console.print(table)

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def network(
    package_name: str = typer.Argument(..., help="npm package to profile"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Profile network behavior of a package."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.network_profiler import NetworkProfiler

    console.print(f"\n[bold blue]Network profile:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        files = npm.get_package_files(package_name)
        profiler = NetworkProfiler()
        report = profiler.profile_package(package_name, files)

        if json_output:
            import json
            print(json.dumps({
                "package": report.package_name,
                "endpoint_count": report.endpoint_count,
                "has_telemetry": report.has_telemetry,
                "has_suspicious": report.has_suspicious,
                "domains": list(report.domains),
                "endpoints": [{"url": e.url, "domain": e.domain, "category": e.category, "file": e.file_path} for e in report.endpoints],
                "findings": [f.model_dump() for f in report.findings],
            }, indent=2))
        else:
            console.print(f"Endpoints: [bold]{report.endpoint_count}[/bold]")
            console.print(f"Domains: {len(report.domains)}")
            console.print(f"Telemetry: {'Yes' if report.has_telemetry else 'No'}")
            console.print(f"Suspicious: [red]Yes[/red]" if report.has_suspicious else "Suspicious: No")

            if report.endpoints:
                table = Table(title="Network Endpoints", show_lines=True)
                table.add_column("Category", width=12)
                table.add_column("Domain", width=30)
                table.add_column("File", width=25)
                table.add_column("URL", width=40)
                for e in report.endpoints[:30]:
                    cat_style = {"telemetry": "yellow", "suspicious": "red", "local": "dim", "unknown": "white"}.get(e.category, "white")
                    table.add_row(f"[{cat_style}]{e.category}[/{cat_style}]", e.domain, e.file_path[:25], e.url[:40])
                console.print(table)

            if report.findings:
                console.print("\n[bold]Findings:[/bold]")
                for f in report.findings:
                    console.print(f"  [{_risk_style(f.risk_level)}]{f.title}[/{_risk_style(f.risk_level)}]: {f.description[:80]}")

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def malware(
    package_name: str = typer.Argument(..., help="npm package to check"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Check package against malware signature database."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.malware_db import MalwareDatabase

    console.print(f"\n[bold blue]Malware check:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        files = npm.get_package_files(package_name)

        db = MalwareDatabase()
        findings, matches = db.scan_package(package_name, pkg_info.latest_version, files)

        if json_output:
            import json
            print(json.dumps({
                "package": package_name,
                "version": pkg_info.latest_version,
                "matches": len(matches),
                "findings": [f.model_dump() for f in findings],
                "db_stats": db.get_stats(),
            }, indent=2))
        else:
            stats = db.get_stats()
            console.print(f"Database: {stats['total_signatures']} signatures")
            console.print(f"Matches: [bold]{len(matches)}[/bold]")

            if findings:
                table = Table(title="Malware Findings", show_lines=True)
                table.add_column("ID", style="cyan", width=14)
                table.add_column("Risk", width=10)
                table.add_column("Title", width=30)
                table.add_column("Description", width=50)
                for f in findings:
                    table.add_row(f.rule_id, f"[{_risk_style(f.risk_level)}]{f.risk_level.value.upper()}[/{_risk_style(f.risk_level)}]", f.title, f.description[:80])
                console.print(table)
            else:
                console.print("[green]No malware signatures matched.[/green]")

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def deep(
    package_name: str = typer.Argument(..., help="npm package for deep analysis"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Deep AI analysis of ALL files in a package (heavy token usage)."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.deep_analyzer import DeepAnalyzer

    console.print(f"\n[bold blue]Deep AI analysis:[/bold blue] {package_name}")
    console.print("[dim]This will analyze ALL files and consume significant tokens...[/dim]\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        files = npm.get_package_files(package_name)

        analyzer = DeepAnalyzer()
        result = analyzer.analyze_package(pkg_info, files)

        if json_output:
            import json
            print(json.dumps({
                "package": result.package_name,
                "files_analyzed": result.files_analyzed,
                "total_tokens": result.total_tokens,
                "risk_level": result.risk_level.value,
                "summary": result.summary,
                "attack_vector": result.attack_vector,
                "recommended_action": result.recommended_action,
                "findings": [f.model_dump() for f in result.findings],
            }, indent=2))
        else:
            console.print(f"Files analyzed: [bold]{result.files_analyzed}[/bold]")
            console.print(f"Tokens consumed: [bold]{result.total_tokens:,}[/bold]")
            console.print(f"Risk: [{_risk_style(result.risk_level)}]{result.risk_level.value.upper()}[/{_risk_style(result.risk_level)}]")
            console.print(f"Action: [bold]{result.recommended_action}[/bold]")

            if result.summary:
                console.print(f"\nSummary: {result.summary}")
            if result.attack_vector:
                console.print(f"Attack vector: {result.attack_vector}")

            if result.findings:
                table = Table(title="Deep Analysis Findings", show_lines=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Risk", width=10)
                table.add_column("Title", width=30)
                table.add_column("File", width=25)
                table.add_column("Description", width=40)
                for f in result.findings:
                    table.add_row(f.rule_id, f"[{_risk_style(f.risk_level)}]{f.risk_level.value.upper()}[/{_risk_style(f.risk_level)}]", f.title, f.file_path or "-", f.description[:60])
                console.print(table)

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


# === Phase 6 continued: Lockfile, Advisory, SBOM, Report ===

@app.command()
def lockfile(
    package_name: str = typer.Argument(..., help="npm package to analyze lockfile"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Analyze package lockfile for injection attacks and integrity issues."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.lockfile_analyzer import LockfileAnalyzer

    console.print(f"\n[bold blue]Lockfile analysis:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        files = npm.get_package_files(package_name)

        analyzer = LockfileAnalyzer()
        findings_all = []
        reports = []

        # Try package-lock.json
        if "package-lock.json" in files:
            pkg_json = {}
            if "package.json" in files:
                import json
                try:
                    pkg_json = json.loads(files["package.json"])
                except json.JSONDecodeError:
                    pass
            report = analyzer.analyze_npm_lockfile(
                files["package-lock.json"],
                package_name,
                pkg_json.get("dependencies"),
            )
            reports.append(report)
            findings_all.extend(report.findings)

        # Try yarn.lock
        if "yarn.lock" in files:
            report = analyzer.analyze_yarn_lockfile(files["yarn.lock"], package_name)
            reports.append(report)
            findings_all.extend(report.findings)

        # Try pnpm-lock.yaml
        if "pnpm-lock.yaml" in files:
            report = analyzer.analyze_pnpm_lockfile(files["pnpm-lock.yaml"], package_name)
            reports.append(report)
            findings_all.extend(report.findings)

        if not reports:
            console.print("[yellow]No lockfile found in package.[/yellow]")
            npm.close()
            return

        if json_output:
            import json
            print(json.dumps({
                "package": package_name,
                "lockfiles": [r.lockfile_type for r in reports],
                "total_entries": sum(r.total_entries for r in reports),
                "findings": [f.model_dump() for f in findings_all],
                "injected_deps": [d for r in reports for d in r.injected_deps],
                "integrity_issues": [i for r in reports for i in r.integrity_issues],
            }, indent=2))
        else:
            for report in reports:
                console.print(f"\n[bold]{report.lockfile_type} lockfile[/bold] ({report.total_entries} entries)")
                status = "[green]CLEAN[/green]" if report.is_clean else f"[red]{len(report.findings)} ISSUE(S)[/red]"
                console.print(f"Status: {status}")
                if report.injected_deps:
                    console.print(f"[red]Injected deps: {', '.join(report.injected_deps)}[/red]")
                if report.integrity_issues:
                    console.print(f"[yellow]Integrity issues: {', '.join(report.integrity_issues[:10])}[/yellow]")

            if findings_all:
                table = Table(title="Lockfile Findings", show_lines=True)
                table.add_column("ID", style="cyan", width=12)
                table.add_column("Risk", width=10)
                table.add_column("Title", width=35)
                table.add_column("Description", width=50)
                for f in findings_all:
                    table.add_row(f.rule_id, f"[{_risk_style(f.risk_level)}]{f.risk_level.value.upper()}[/{_risk_style(f.risk_level)}]", f.title, f.description[:80])
                console.print(table)

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def advisory(
    package_name: str = typer.Argument(..., help="npm package to check advisories"),
    version: str = typer.Option(None, "--version", "-v", help="Current version to check"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Check package against GitHub Advisory Database for known CVEs."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.advisory_client import AdvisoryClient

    console.print(f"\n[bold blue]Advisory check:[/bold blue] {package_name}\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        ver = version or pkg_info.latest_version

        client = AdvisoryClient()
        report = client.scan_package(package_name, ver)

        if json_output:
            import json
            print(json.dumps({
                "package": package_name,
                "version": ver,
                "advisory_count": len(report.advisories),
                "critical": report.critical_count,
                "high": report.high_count,
                "advisories": [{
                    "ghsa_id": a.ghsa_id,
                    "cve_id": a.cve_id,
                    "severity": a.severity,
                    "summary": a.summary,
                    "affected": a.affected_versions,
                    "patched": a.patched_versions,
                    "cvss": a.cvss_score,
                } for a in report.advisories],
                "findings": [f.model_dump() for f in report.findings],
            }, indent=2))
        else:
            if report.has_advisories:
                console.print(f"[red]Found {len(report.advisories)} advisory(ies)[/red]")
                console.print(f"Critical: {report.critical_count} | High: {report.high_count}\n")

                table = Table(title="Security Advisories", show_lines=True)
                table.add_column("GHSA", style="cyan", width=18)
                table.add_column("CVE", width=18)
                table.add_column("Severity", width=10)
                table.add_column("Summary", width=50)
                table.add_column("CVSS", width=6)
                for a in report.advisories:
                    sev_style = _risk_style({
                        "critical": RiskLevel.CRITICAL,
                        "high": RiskLevel.HIGH,
                        "medium": RiskLevel.MEDIUM,
                        "low": RiskLevel.LOW,
                    }.get(a.severity, RiskLevel.LOW))
                    table.add_row(
                        a.ghsa_id,
                        a.cve_id or "-",
                        f"[{sev_style}]{a.severity.upper()}[/{sev_style}]",
                        a.summary[:50],
                        str(a.cvss_score) if a.cvss_score else "-",
                    )
                console.print(table)
            else:
                console.print("[green]No known advisories found.[/green]")

            console.print(f"\nAPI cache: {client.get_stats()['cached_packages']} packages cached")

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def sbom(
    package_name: str = typer.Argument(..., help="npm package to generate SBOM"),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="SBOM format: cyclonedx or spdx"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Generate Software Bill of Materials (SBOM)."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.services.sbom_service import SBOMService
    import json

    console.print(f"\n[bold blue]SBOM generation:[/bold blue] {package_name} ({format})\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)

        # Build dependency info
        deps = {}
        if pkg_info.versions:
            latest = pkg_info.versions[-1]
            for dep_name, dep_ver in latest.dependencies.items():
                deps[dep_name] = {"version": dep_ver}

        service = SBOMService()

        if format == "cyclonedx":
            result = service.generate_cyclonedx(pkg_info, deps)
        elif format == "spdx":
            result = service.generate_spdx(pkg_info, deps)
        else:
            console.print(f"[red]Unknown format: {format}. Use 'cyclonedx' or 'spdx'.[/red]")
            raise typer.Exit(code=1)

        if output:
            Path(output).write_text(result.content)
            console.print(f"[green]SBOM written to {output}[/green]")
        elif json_output:
            print(result.content)
        else:
            console.print(f"Format: {result.format}")
            console.print(f"Components: {result.component_count}")
            console.print(f"Vulnerabilities: {result.vulnerability_count}")
            console.print(f"\n[dim]Use --output <file> to save the SBOM[/dim]")
            # Show preview
            preview = result.content[:500]
            console.print(f"\n{preview}...")

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


@app.command()
def report(
    package_name: str = typer.Argument(..., help="npm package to generate report"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
) -> None:
    """Generate comprehensive AI security report (heavy token usage)."""
    from git_guardian.scanner.npm import NpmRegistryClient
    from git_guardian.scanner.patterns import PatternDetector
    from git_guardian.services.report_service import ReportService
    from git_guardian.services.health_scorer import HealthScorer
    from git_guardian.services.network_profiler import NetworkProfiler
    from git_guardian.services.advisory_client import AdvisoryClient

    console.print(f"\n[bold blue]Security report:[/bold blue] {package_name}")
    console.print("[dim]Generating multi-pass AI report (heavy token usage)...[/dim]\n")

    try:
        npm = NpmRegistryClient()
        pkg_info = npm.get_package(package_name)
        files = npm.get_package_files(package_name)

        # Gather all findings
        detector = PatternDetector()
        pattern_findings = detector.scan_package(files)

        # Network summary
        profiler = NetworkProfiler()
        net_report = profiler.profile_package(package_name, files)
        network_summary = f"{net_report.endpoint_count} endpoints, telemetry: {net_report.has_telemetry}, suspicious: {net_report.has_suspicious}"

        # Health score
        health = HealthScorer()
        health_report = health.score_package(pkg_info)

        # Advisories
        adv_client = AdvisoryClient()
        adv_report = adv_client.scan_package(package_name, pkg_info.latest_version)

        # Dependency info
        dep_info = {"total": 0, "packages": {}}
        if pkg_info.versions:
            latest = pkg_info.versions[-1]
            dep_info["total"] = len(latest.dependencies)
            for dep_name, dep_ver in list(latest.dependencies.items())[:30]:
                dep_info["packages"][dep_name] = {"version": dep_ver}

        # Generate report
        report_service = ReportService()
        sec_report = report_service.generate_report(
            pkg_info,
            pattern_findings,
            dep_info,
            adv_report.findings,
            network_summary,
            health_report.overall_score,
        )

        if json_output:
            import json
            print(json.dumps({
                "package": sec_report.package_name,
                "version": sec_report.version,
                "overall_risk": sec_report.overall_risk.value,
                "total_findings": sec_report.total_findings,
                "risk_breakdown": sec_report.risk_breakdown,
                "total_tokens": sec_report.total_tokens,
                "executive_summary": sec_report.executive_summary,
                "findings_narrative": sec_report.findings_narrative,
                "dependency_risk": sec_report.dependency_risk,
                "recommendations": sec_report.recommendations,
            }, indent=2))
        else:
            risk_style = _risk_style(sec_report.overall_risk)
            console.print(f"[bold]Package:[/bold] {sec_report.package_name} v{sec_report.version}")
            console.print(f"[bold]Risk:[/bold] [{risk_style}]{sec_report.overall_risk.value.upper()}[/{risk_style}]")
            console.print(f"[bold]Findings:[/bold] {sec_report.total_findings}")
            console.print(f"[bold]Tokens consumed:[/bold] {sec_report.total_tokens:,}")

            console.print(Panel(sec_report.executive_summary, title="Executive Summary", border_style="blue"))
            console.print(Panel(sec_report.findings_narrative, title="Detailed Findings", border_style="yellow"))
            console.print(Panel(sec_report.dependency_risk, title="Dependency Risk", border_style="red"))
            console.print(Panel(sec_report.recommendations, title="Recommendations", border_style="green"))

        npm.close()
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
