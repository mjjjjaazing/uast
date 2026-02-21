"""
Display — rich terminal output for uast.

All terminal output lives here. Nothing else prints directly.
Keeps formatting centralized and easy to change.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from uast.analyzer import AnalysisResult

VERDICT_COLORS = {
    "clean":      "green",
    "suspicious": "yellow",
    "critical":   "red",
}

VERDICT_ICONS = {
    "clean":      "✓",
    "suspicious": "⚠",
    "critical":   "✗",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high":     "dark_orange",
    "medium":   "yellow",
    "low":      "dim",
    "info":     "blue",
}


class Display:
    """Handles all terminal output for a uast session."""

    def __init__(self, console: Console, verbose: bool = False) -> None:
        self.console = console
        self.verbose = verbose

    # -- Startup --------------------------------------------------------------

    def banner(self, agent: str, project: str, version: str = "0.4.0") -> None:
        self.console.print()
        self.console.print(
            "[bold]UAST[/bold]  [dim]Unified Agentic Security Testing[/dim]"
            f"  [dim]v{version}[/dim]",
            highlight=False,
        )
        self.console.print(
            "[dim]github.com/mjjjjaazing/uast[/dim]",
            highlight=False,
        )
        self.console.print()

    def watching(self, project_path: Path, agent: str, threshold: float) -> None:
        """Print session start confirmation."""
        self.console.print(
            "  [green]✓[/green]  [dim]session started[/dim]"
        )
        self.console.print(
            f"  [green]✓[/green]  [dim]watching[/dim]  [bold]{project_path}[/bold]"
        )
        self.console.print(
            f"  [green]✓[/green]  [dim]agent[/dim]      [bold]{agent}[/bold]"
        )
        self.console.print(
            f"  [green]✓[/green]  [dim]threshold[/dim]  "
            f"[bold]ARS ≥ {threshold:.1f}[/bold] triggers alert"
        )
        self.console.print(
            "  [green]✓[/green]  [dim]process watcher active[/dim]"
        )
        self.console.print(
            "  [green]✓[/green]  [dim]file watcher active[/dim]"
        )
        self.console.print()
        self.console.print(
            "  [dim]Monitoring... press [bold]Ctrl+C[/bold] to stop and save report[/dim]"
        )
        self.console.print()

    # -- Live analysis updates ------------------------------------------------

    def analyzing(self, package_name: str, ecosystem: str, source: str) -> None:
        """Show that analysis is in progress."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"  [dim][{ts}][/dim]  "
            f"detected [bold]{package_name}[/bold] "
            f"[dim]({ecosystem} via {source})[/dim]  "
            f"[dim]analyzing...[/dim]",
            highlight=False,
        )

    def show_result(self, result: AnalysisResult, threshold: float) -> None:
        """Display the analysis result for a single package."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        color = VERDICT_COLORS[result.verdict]
        icon = VERDICT_ICONS[result.verdict]
        is_alert = result.ars_score >= threshold

        if result.verdict == "clean" and not self.verbose:
            self.console.print(
                f"  [{color}]{icon}[/{color}]  "
                f"[dim][{ts}][/dim]  "
                f"[bold]{result.package_name}[/bold]  "
                f"[dim]{result.ecosystem} · ARS {result.ars_score:.1f} · clean[/dim]",
                highlight=False,
            )
            return

        # For flagged or verbose results, print a full breakdown
        self.console.print()

        # Header line
        ars_text = Text()
        ars_text.append(f"  {icon}  ", style=f"bold {color}")
        ars_text.append(f"[{ts}]  ", style="dim")
        ars_text.append(result.package_name, style="bold")
        ars_text.append(f"  {result.ecosystem}  ", style="dim")
        ars_text.append(f"ARS {result.ars_score:.1f}", style=f"bold {color}")

        if result.avt_classes:
            ars_text.append(f"  ·  {' · '.join(result.avt_classes)}", style="dim")

        self.console.print(ars_text, highlight=False)

        # "Did you mean?" suggestion
        if result.did_you_mean:
            self.console.print(
                f"     [dim]💡[/dim]  [bold]Did you mean '{result.did_you_mean}'?[/bold]",
                highlight=False,
            )

        # Signals
        for sig in result.signals:
            if sig.severity == "info" and not self.verbose:
                continue
            sig_color = SEVERITY_COLORS.get(sig.severity, "dim")
            self.console.print(
                f"     [dim]·[/dim]  [{sig_color}][{sig.severity.upper()}][/{sig_color}]  "
                f"{sig.title}",
                highlight=False,
            )
            if self.verbose and sig.detail:
                self.console.print(
                    f"          [dim]{sig.detail}[/dim]",
                    highlight=False,
                )

        # ARSM breakdown in verbose mode
        if self.verbose and result.arsm:
            self._show_arsm_breakdown(result.arsm)

        # Recommendation
        if is_alert or result.verdict != "clean":
            self.console.print(
                f"     [dim]→[/dim]  [bold]{result.recommendation}[/bold]",
                highlight=False,
            )

        self.console.print()

    def _show_arsm_breakdown(self, arsm: dict) -> None:
        """Show ARSM dimension values."""
        self.console.print(
            f"     [dim]ARSM:[/dim]  "
            f"[dim]AAL={arsm.get('aal', 0):.2f}[/dim]  "
            f"[dim]CIS={arsm.get('cis', 0):.2f}[/dim]  "
            f"[dim]PC={arsm.get('pc', 0):.2f}[/dim]  "
            f"[dim]SRF={arsm.get('srf', 0):.2f}[/dim]",
            highlight=False,
        )

    def blocked(self, package_name: str) -> None:
        """Confirm a package was blocked."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"  [red bold]⊘[/red bold]  [dim][{ts}][/dim]  "
            f"[bold red]BLOCKED[/bold red]  {package_name}  "
            f"[dim](install process terminated)[/dim]",
            highlight=False,
        )

    def rolled_back(self, package_name: str) -> None:
        """Confirm a package was rolled back (uninstalled after install completed)."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.console.print(
            f"  [red bold]↩[/red bold]  [dim][{ts}][/dim]  "
            f"[bold red]ROLLED BACK[/bold red]  {package_name}  "
            f"[dim](package uninstalled — install completed before block)[/dim]",
            highlight=False,
        )

    # -- Session end ----------------------------------------------------------

    def shutdown(self, output_path: Path) -> None:
        """Print session end summary."""
        self.console.print()
        self.console.print(Rule(style="dim"))
        self.console.print(
            f"  [dim]session ended  ·  report saved to[/dim]  [bold]{output_path}[/bold]",
            highlight=False,
        )
        self.console.print()

    # -- Standalone check command ---------------------------------------------

    def show_analysis_result(self, result: AnalysisResult) -> None:
        """Display a full single-package analysis (for `uast check`)."""
        color = VERDICT_COLORS[result.verdict]
        icon = VERDICT_ICONS[result.verdict]

        self.console.print()

        # Summary panel
        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="dim", min_width=16)
        summary.add_column()

        summary.add_row("Package", f"[bold]{result.package_name}[/bold]")
        summary.add_row("Ecosystem", result.ecosystem)
        summary.add_row("Version", result.version)
        summary.add_row(
            "ARS Score",
            f"[bold {color}]{result.ars_score:.1f} / 10.0[/bold {color}]",
        )
        summary.add_row(
            "CVSS Base",
            f"[dim]{result.cvss_base:.1f}[/dim]",
        )
        summary.add_row(
            "Verdict",
            f"[bold {color}]{icon}  {result.verdict.upper()}[/bold {color}]",
        )
        if result.avt_classes:
            summary.add_row("AVT Classes", "  ".join(result.avt_classes))
        if result.did_you_mean:
            summary.add_row("Did you mean?", f"[bold]{result.did_you_mean}[/bold]")

        self.console.print(
            Panel(summary, title="[dim]Supply Chain Analysis[/dim]", border_style="dim")
        )

        # ARSM breakdown
        if result.arsm:
            self.console.print()
            self.console.print("  [dim]ARSM Dimensions[/dim]")
            arsm = result.arsm
            arsm_table = Table.grid(padding=(0, 2))
            arsm_table.add_column(style="dim", min_width=6)
            arsm_table.add_column(min_width=30)
            arsm_table.add_column(justify="right")

            arsm_table.add_row(
                "AAL",
                "Agent Autonomy Level",
                f"{arsm.get('aal', 0):.2f}",
            )
            arsm_table.add_row(
                "CIS",
                "Context Integrity Score",
                f"{arsm.get('cis', 0):.2f}",
            )
            arsm_table.add_row(
                "PC",
                "Provenance Confidence",
                f"{arsm.get('pc', 0):.2f}",
            )
            arsm_table.add_row(
                "SRF",
                "Systemic Replication Factor",
                f"{arsm.get('srf', 0):.2f}",
            )
            self.console.print(
                Panel(arsm_table, border_style="dim", padding=(0, 2))
            )

        # Signals
        if result.signals:
            self.console.print()
            self.console.print("  [dim]Detection Signals[/dim]")
            self.console.print()

            for sig in result.signals:
                sig_color = SEVERITY_COLORS.get(sig.severity, "dim")
                self.console.print(
                    f"  [{sig_color}][{sig.severity.upper()}][/{sig_color}]  "
                    f"[bold]{sig.title}[/bold]",
                    highlight=False,
                )
                self.console.print(
                    f"       [dim]{sig.detail}[/dim]",
                    highlight=False,
                )
                self.console.print()

        # Provenance info
        if result.provenance:
            self.console.print()
            self.console.print("  [dim]Provenance Verification[/dim]")
            prov = result.provenance
            prov_table = Table.grid(padding=(0, 2))
            prov_table.add_column(style="dim", min_width=20)
            prov_table.add_column()

            verified = prov.get("source_verified", False)
            method = prov.get("verification_method", "none")
            attestation = prov.get("attestation", "none")

            color = "green" if verified else "yellow"
            prov_table.add_row(
                "Source Verified",
                f"[{color}]{'Yes' if verified else 'No'}[/{color}]",
            )
            prov_table.add_row("Method", method)
            prov_table.add_row("Attestation", attestation or "none")

            self.console.print(
                Panel(prov_table, border_style="dim", padding=(0, 2))
            )

        # Recommendation
        self.console.print(
            f"  [bold]→[/bold]  {result.recommendation}"
        )
        self.console.print()

    # -- Sessions list --------------------------------------------------------

    def list_sessions(self, sessions_dir: Path) -> None:
        """Display a table of saved sessions."""
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="dim",
            show_edge=False,
        )
        table.add_column("Session", style="bold", min_width=32)
        table.add_column("Agent", min_width=12)
        table.add_column("Packages", justify="right")
        table.add_column("Alerts", justify="right")
        table.add_column("Date")

        for report_path in sorted(sessions_dir.glob("*.json"), reverse=True):
            try:
                with open(report_path) as f:
                    data = json.load(f)
                report_summary = data.get("summary", {})
                table.add_row(
                    report_path.name,
                    data.get("agent", "—"),
                    str(report_summary.get("total_packages", 0)),
                    (
                        f"[red]{report_summary.get('alerts', 0)}[/red]"
                        if report_summary.get("alerts", 0) else "0"
                    ),
                    data.get("started_at", "")[:16],
                )
            except (ValueError, KeyError, OSError):
                table.add_row(report_path.name, "—", "—", "—", "—")

        self.console.print()
        self.console.print(table)
        self.console.print()

    # -- Tree diff display ----------------------------------------------------

    def show_tree_diff(self, diff: dict, label_a: str, label_b: str) -> None:
        """Display the result of a dependency tree hash comparison."""
        self.console.print()

        if diff["match"]:
            self.console.print(
                "  [green]✓[/green]  [bold]Dependency trees match[/bold]  "
                "[dim]— no drift detected[/dim]"
            )
        else:
            self.console.print(
                "  [red]✗[/red]  [bold red]Dependency tree drift detected[/bold red]"
            )

        self.console.print()

        table = Table.grid(padding=(0, 2))
        table.add_column(style="dim", min_width=16)
        table.add_column()

        table.add_row(label_a, f"[dim]{diff.get(label_a, 'N/A')[:16]}...[/dim]")
        table.add_row(label_b, f"[dim]{diff.get(label_b, 'N/A')[:16]}...[/dim]")

        self.console.print(
            Panel(table, title="[dim]Tree Hash Comparison[/dim]", border_style="dim")
        )
        self.console.print()

    # -- Report display -------------------------------------------------------

    def show_report(self, data: dict) -> None:
        """Display a saved JSON session report."""
        report_summary = data.get("summary", {})
        results = data.get("results", [])

        self.console.print()
        self.console.print("  [bold]Session Report[/bold]")
        self.console.print(f"  [dim]Agent:[/dim]   {data.get('agent', '—')}")
        self.console.print(f"  [dim]Project:[/dim] {data.get('project', '—')}")
        self.console.print(f"  [dim]Date:[/dim]    {data.get('started_at', '—')[:16]}")
        self.console.print()
        self.console.print(
            f"  [bold]{report_summary.get('total_packages', 0)}[/bold] packages analyzed  ·  "
            f"[red bold]{report_summary.get('alerts', 0)}[/red bold] alerts  ·  "
            f"[yellow]{report_summary.get('suspicious', 0)}[/yellow] suspicious  ·  "
            f"[green]{report_summary.get('clean', 0)}[/green] clean"
        )
        self.console.print()

        for entry in results:
            verdict = entry.get("verdict", "clean")
            color = VERDICT_COLORS.get(verdict, "dim")
            icon = VERDICT_ICONS.get(verdict, "·")
            self.console.print(
                f"  [{color}]{icon}[/{color}]  "
                f"[bold]{entry.get('package_name', '?')}[/bold]  "
                f"[dim]{entry.get('ecosystem', '')}  ·  "
                f"ARS {entry.get('ars_score', 0):.1f}  ·  "
                f"{verdict}[/dim]",
                highlight=False,
            )

        self.console.print()
