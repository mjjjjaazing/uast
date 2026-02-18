"""
uast — Unified Agentic Security Testing
Real-time security monitoring for AI coding agents.

Detects supply chain attacks, compromised dependencies, and suspicious
agent behavior that SAST and DAST were never designed to catch.
"""

import sys
import json as json_mod
import signal
import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from uast.watcher import AgentWatcher
from uast.reporter import SessionReporter
from uast.display import Display
from uast.analyzer import AGENT_AAL

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
@click.version_option(version="0.1.0", prog_name="uast")
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
def start(
    agent: str,
    project: str,
    output: "str | None",
    threshold: float,
    block: bool,
    verbose: bool,
    deep: bool,
) -> None:
    """Start monitoring an AI coding agent session.

    \b
    Examples:
      uast start
      uast start --agent cursor --project ./my-app
      uast start --agent claude-code --threshold 7.0 --block
      uast start --verbose --output ./reports/session.json
      uast start --agent cursor --deep
    """
    project_path = Path(project).resolve()
    display = Display(console, verbose=verbose)

    # Resolve AAL from agent choice
    aal = AGENT_AAL.get(agent, 0.5)

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
        threshold=threshold,
        block=block,
        display=display,
        reporter=reporter,
        aal=aal,
        deep=deep,
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
        console.print("\n[dim]No sessions found. Run [bold]uast start[/bold] to begin monitoring.[/dim]\n")
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
def check(package_name: str, ecosystem: str, json_output: bool, agent: str) -> None:
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

    aal = AGENT_AAL.get(agent, 0.5)
    display = Display(console)
    analyzer = SupplyChainAnalyzer(aal=aal, deep=True)

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


if __name__ == "__main__":
    cli()
