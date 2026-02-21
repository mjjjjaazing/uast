"""
uast — Unified Agentic Security Testing
Real-time security monitoring for AI coding agents.

Detects supply chain attacks, compromised dependencies, and suspicious
agent behavior that SAST and DAST were never designed to catch.
"""

import datetime
import json as json_mod
import signal
import sys
from pathlib import Path

import click
from rich.console import Console

from uast.config import get_agent_aal, get_threshold, load_config
from uast.display import Display
from uast.logging import setup_logging
from uast.reporter import SessionReporter
from uast.watcher import AgentWatcher

console = Console()

SUPPORTED_AGENTS = ["cursor", "claude-code", "copilot", "windsurf", "codeium", "auto"]

BANNER = """
 ██╗   ██╗ █████╗ ███████╗████████╗
 ██║   ██║██╔══██╗██╔════╝╚══██╔══╝
 ██║   ██║███████║███████╗   ██║
 ██║   ██║██╔══██║╚════██║   ██║
 ╚██████╔╝██║  ██║███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝
"""


def print_banner(agent: str, project: str, version: str = "0.1.0") -> None:
    """Print startup banner."""
    display = Display(console)
    display.banner(agent, project, version)


@click.group()
@click.version_option(version="0.5.0", prog_name="uast")
def cli() -> None:
    """UAST — Unified Agentic Security Testing.

    Real-time security monitoring for AI coding agents.
    Detects what SAST and DAST were never designed to catch.

    \b
    Supported agents: cursor, claude-code, copilot, windsurf, codeium
    GitHub: https://github.com/mjjjjaazing/uast
    """
    pass


@cli.command()
@click.option(
    "--agent",
    "-a",
    type=click.Choice(SUPPORTED_AGENTS, case_sensitive=False),
    default="auto",
    show_default=True,
    help="The AI coding agent to monitor. Use 'auto' to detect automatically.",
)
@click.option(
    "--project",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=".",
    show_default=True,
    help="Path to the project directory to watch.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(file_okay=True, dir_okay=False),
    default=None,
    help="Path for JSON session report. Defaults to ~/.uast/sessions/<timestamp>.json",
)
@click.option(
    "--threshold",
    "-t",
    type=click.FloatRange(0.0, 10.0),
    default=6.0,
    show_default=True,
    help="ARS score threshold to trigger alerts (0.0–10.0).",
)
@click.option(
    "--block/--no-block",
    default=False,
    show_default=True,
    help="Block flagged installs rather than just alerting.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show all package checks, not just alerts.",
)
@click.option(
    "--deep",
    is_flag=True,
    default=False,
    help="Enable deep analysis (static payload scanning via AST).",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="WARNING",
    show_default=True,
    help="Log level for file and console logging.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    default=False,
    help="Suppress all log output to the console (file logging still active).",
)
@click.option(
    "--provenance",
    is_flag=True,
    default=False,
    help="Enable provenance verification (git clone + build + hash comparison).",
)
@click.option(
    "--webhook-url",
    default=None,
    help="Generic webhook URL to POST alerts to.",
)
def start(
    agent: str,
    project: str,
    output: "str | None",
    threshold: float,
    block: bool,
    verbose: bool,
    deep: bool,
    log_level: str,
    quiet: bool,
    provenance: bool,
    webhook_url: "str | None",
) -> None:
    """Start monitoring an AI coding agent session.

    \b
    Examples:
      uast start
      uast start --agent cursor --project ./my-app
      uast start --agent claude-code --threshold 7.0 --block
      uast start --verbose --output ./reports/session.json
      uast start --agent cursor --deep
      uast start --log-level DEBUG
    """
    setup_logging(level=log_level, quiet=quiet)

    project_path = Path(project).resolve()
    display = Display(console, verbose=verbose)

    # Load configuration (project config + user config + defaults)
    cli_overrides: dict = {}
    if threshold != 6.0:
        cli_overrides["threshold"] = threshold
    if webhook_url:
        cli_overrides.setdefault("webhooks", {})["generic_url"] = webhook_url
    config = load_config(project_path=project_path, cli_overrides=cli_overrides or None)

    # Resolve AAL from config (falls back to agent map)
    aal = get_agent_aal(config, agent)

    # Use config threshold (CLI override already merged in)
    effective_threshold = get_threshold(config)

    # Print startup banner
    display.banner(agent, str(project_path))

    # Resolve output path
    if output is None:
        output_dir = Path.home() / ".uast" / "sessions"
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = output_dir / f"session_{timestamp}.json"
    else:
        output_path = Path(output)

    # Initialise reporter and watcher
    reporter = SessionReporter(
        agent=agent,
        project=str(project_path),
        output_path=output_path,
    )

    watcher = AgentWatcher(
        project_path=project_path,
        agent=agent,
        threshold=effective_threshold,
        block=block,
        display=display,
        reporter=reporter,
        aal=aal,
        deep=deep,
        config=config,
        provenance=provenance,
    )

    # Handle Ctrl+C gracefully
    def _shutdown(sig, frame):  # noqa: ANN001
        display.shutdown(output_path)
        reporter.save()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Start watching
    try:
        watcher.start()
    except KeyboardInterrupt:
        pass
    finally:
        display.shutdown(output_path)
        reporter.save()


@cli.command()
@click.argument("report_path", type=click.Path(exists=True))
def report(report_path: str) -> None:
    """Display a saved session report in the terminal.

    \b
    Example:
      uast report ~/.uast/sessions/session_20250101_120000.json
    """
    display = Display(console)
    with open(report_path) as f:
        data = json_mod.load(f)
    display.show_report(data)


@cli.command()
def sessions() -> None:
    """List all saved session reports."""
    sessions_dir = Path.home() / ".uast" / "sessions"
    display = Display(console)

    if not sessions_dir.exists() or not list(sessions_dir.glob("*.json")):
        console.print(
            "\n[dim]No sessions found. Run [bold]uast start[/bold]"
            " to begin monitoring.[/dim]\n"
        )
        return

    display.list_sessions(sessions_dir)


@cli.command()
@click.argument("package_name")
@click.option("--ecosystem", "-e", type=click.Choice(["pypi", "npm"]), default="pypi")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.option(
    "--agent",
    "-a",
    type=click.Choice(SUPPORTED_AGENTS, case_sensitive=False),
    default="auto",
    help="Agent context for ARSM scoring.",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="WARNING",
    help="Log level for file and console logging.",
)
@click.option(
    "--provenance",
    is_flag=True,
    default=False,
    help="Enable provenance verification (git clone + build + hash comparison).",
)
def check(
    package_name: str, ecosystem: str, json_output: bool,
    agent: str, log_level: str, provenance: bool,
) -> None:
    """Manually check a single package against the supply chain analyzer.

    \b
    Examples:
      uast check requests
      uast check lodash --ecosystem npm
      uast check request-utils-async
      uast check some-package --json
      uast check some-package --agent cursor
    """
    from uast.analyzer import SupplyChainAnalyzer

    setup_logging(level=log_level, quiet=json_output)

    config = load_config(project_path=Path("."))
    aal = get_agent_aal(config, agent)
    display = Display(console)
    analyzer = SupplyChainAnalyzer(aal=aal, deep=True, config=config, provenance=provenance)

    if not json_output:
        console.print(f"\n[dim]Analyzing [bold]{package_name}[/bold] ({ecosystem})...[/dim]")

    if ecosystem == "pypi":
        result = analyzer.analyze_pypi(package_name)
    else:
        result = analyzer.analyze_npm(package_name)

    if json_output:
        output = {
            "package_name": result.package_name,
            "ecosystem": result.ecosystem,
            "version": result.version,
            "ars_score": result.ars_score,
            "cvss_base": result.cvss_base,
            "verdict": result.verdict,
            "avt_classes": result.avt_classes,
            "recommendation": result.recommendation,
            "did_you_mean": result.did_you_mean,
            "arsm": result.arsm,
            "signals": [
                {
                    "signal_id": s.signal_id,
                    "severity": s.severity,
                    "title": s.title,
                    "detail": s.detail,
                    "score_contribution": s.score_contribution,
                }
                for s in result.signals
            ],
            "metadata": result.metadata,
            "analyzed_at": result.analyzed_at,
        }
        click.echo(json_mod.dumps(output, indent=2))
    else:
        display.show_analysis_result(result)


@cli.command("show-config")
@click.option(
    "--project",
    "-p",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=".",
    help="Project directory (for .uast.toml lookup).",
)
def show_config(project: str) -> None:
    """Display the resolved UAST configuration.

    \b
    Shows merged configuration from all sources:
      ~/.uast/config.toml  (user-level)
      .uast.toml           (project-level)
      built-in defaults

    \b
    Example:
      uast show-config
      uast show-config --project ./my-app
    """
    project_path = Path(project).resolve()
    config = load_config(project_path=project_path)
    console.print(json_mod.dumps(config, indent=2, default=str))


@cli.command("diff-trees")
@click.argument("session1", type=click.Path(exists=True))
@click.argument("session2", type=click.Path(exists=True))
def diff_trees(session1: str, session2: str) -> None:
    """Compare dependency tree hashes between two session reports.

    \b
    Detects drift in the dependency tree between sessions.

    \b
    Example:
      uast diff-trees session_a.json session_b.json
    """
    from uast.merkle import diff_tree_hashes, load_session_hash

    display = Display(console)

    hash1 = load_session_hash(session1)
    hash2 = load_session_hash(session2)

    if hash1 is None:
        console.print(
            f"\n[yellow]Warning:[/yellow] No dependency_tree_hash in {session1}.\n"
            "[dim]Run analysis with v0.4.0+ to generate tree hashes.[/dim]\n"
        )
        return
    if hash2 is None:
        console.print(
            f"\n[yellow]Warning:[/yellow] No dependency_tree_hash in {session2}.\n"
            "[dim]Run analysis with v0.4.0+ to generate tree hashes.[/dim]\n"
        )
        return

    result = diff_tree_hashes(
        hash1, hash2,
        label_a=Path(session1).name,
        label_b=Path(session2).name,
    )

    display.show_tree_diff(result, Path(session1).name, Path(session2).name)


@cli.command()
@click.argument("session_path", type=click.Path(exists=True))
def notify(session_path: str) -> None:
    """Send a session summary via configured webhooks.

    \b
    Example:
      uast notify ~/.uast/sessions/session_20250101_120000.json
    """
    config = load_config(project_path=Path("."))

    with open(session_path) as f:
        session_data = json_mod.load(f)

    from uast.webhooks import WebhookDispatcher
    dispatcher = WebhookDispatcher(config)

    if not dispatcher.is_configured:
        console.print(
            "\n[yellow]No webhooks configured.[/yellow]\n"
            "[dim]Set webhooks.slack_url or webhooks.generic_url in "
            "~/.uast/config.toml[/dim]\n"
        )
        return

    sent = dispatcher.notify_session(session_data)
    if sent:
        console.print("[green]✓[/green] Session summary sent via webhooks.")
    else:
        summary = session_data.get("summary", {})
        if summary.get("alerts", 0) == 0:
            console.print("[dim]No alerts in session — nothing to notify.[/dim]")
        else:
            console.print("[yellow]Webhook notification failed.[/yellow]")


@cli.command()
@click.option(
    "--host",
    default=None,
    help="Host to bind to. Default: 127.0.0.1",
)
@click.option(
    "--port",
    type=int,
    default=None,
    help="Port to listen on. Default: 8080",
)
@click.option(
    "--sessions-dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=None,
    help="Directory containing session JSON files. Default: ~/.uast/sessions",
)
def dashboard(host: "str | None", port: "int | None", sessions_dir: "str | None") -> None:
    """Launch the UAST web dashboard.

    \b
    Serves a lightweight web UI for browsing session reports.
    Binds to 127.0.0.1:8080 by default (local only).

    \b
    Examples:
      uast dashboard
      uast dashboard --port 9090
      uast dashboard --sessions-dir ./my-sessions
    """
    try:
        from uast.dashboard.app import create_app
    except ImportError:
        console.print(
            "\n[red]Flask is required for the dashboard.[/red]\n"
            "[dim]Install it with: pip install uast[dashboard][/dim]\n"
        )
        sys.exit(1)

    config = load_config(project_path=Path("."))
    dash_config = config.get("dashboard", {})

    effective_host = host or dash_config.get("host", "127.0.0.1")
    effective_port = port or dash_config.get("port", 8080)

    sessions_path = Path(sessions_dir) if sessions_dir else None

    app = create_app(sessions_dir=sessions_path)

    console.print(
        f"\n[bold]UAST Dashboard[/bold] running at "
        f"[link=http://{effective_host}:{effective_port}]"
        f"http://{effective_host}:{effective_port}[/link]\n"
        "[dim]Press Ctrl+C to stop.[/dim]\n"
    )

    app.run(host=effective_host, port=effective_port, debug=False)


if __name__ == "__main__":
    cli()
