"""
Terminal Reporter for AnubisTrace.
Renders interactive, color-coded incident reports with rich or pure ASCII fallback.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Dict, List

from anubistrace.core.event import ForensicEvent, Severity

if TYPE_CHECKING:
    from anubistrace.engine.correlation import CorrelatedFinding

# ANSI Color Codes for terminal
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED + BOLD,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: WHITE,
}


def render_attack_chains(findings: List[CorrelatedFinding]) -> None:
    """Renders correlated multi-stage attack chains."""
    if not findings:
        return

    try:
        from rich.console import Console
        from rich.panel import Panel

        console = Console()
        console.print("\n[bold red]🚨 MULTI-STAGE CORRELATED ATTACK SEQUENCES DETECTED[/bold red]\n")

        for i, f in enumerate(findings, 1):
            body = (
                f"[bold red]Severity:[/bold red] {f.severity.value}\n"
                f"[bold]Description:[/bold] {f.description}\n"
                f"[bold]MITRE Tactics:[/bold] {', '.join(f.mitre_tactics)}\n"
                f"[bold]MITRE Techniques:[/bold] {', '.join(f.mitre_techniques)}\n"
                f"[bold]Contributing Artifacts:[/bold] {len(f.contributing_events)} event(s) across "
                f"{(f.last_seen - f.first_seen).total_seconds():.1f}s"
            )
            console.print(Panel(body, title=f"[bold yellow]Chain #{i}: {f.title}[/bold yellow]", border_style="red"))
        return
    except ImportError:
        pass

    # Pure ASCII Fallback
    print("\n" + "!" * 80)
    print("  🚨 MULTI-STAGE CORRELATED ATTACK SEQUENCES DETECTED")
    print("!" * 80)
    for i, f in enumerate(findings, 1):
        print(f"\n[Chain #{i}] {f.title} (Severity: {f.severity.value})")
        print(f"  Description: {f.description}")
        print(f"  Tactics:     {', '.join(f.mitre_tactics)}")
        print(f"  Techniques:  {', '.join(f.mitre_techniques)}")
        print(f"  Evidences:   {len(f.contributing_events)} event(s)")
    print("!" * 80 + "\n")


def render_terminal_report(events: List[ForensicEvent], stats: Dict[str, object]) -> None:
    """Renders formatted incident summary and chronological timeline to stdout."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table

        console = Console()

        # Header Summary
        sev_counts = stats.get("severity_counts", {})
        summary_text = (
            f"[bold]Total Events Ingested:[/bold] {stats.get('total_events')}  |  "
            f"[bold red]CRITICAL:[/bold red] {sev_counts.get('CRITICAL', 0)}  |  "
            f"[red]HIGH:[/red] {sev_counts.get('HIGH', 0)}  |  "
            f"[yellow]MEDIUM:[/yellow] {sev_counts.get('MEDIUM', 0)}  |  "
            f"[cyan]LOW:[/cyan] {sev_counts.get('LOW', 0)}  |  "
            f"[dim]INFO:[/dim] {sev_counts.get('INFO', 0)}\n"
            f"[bold]Unique IoCs Flagged:[/bold] {len(stats.get('unique_iocs', []))}"
        )
        console.print(Panel(summary_text, title="[bold cyan]⚖️ AnubisTrace Forensic Triage Summary[/bold cyan]", border_style="cyan"))

        # Events Table
        table = Table(title="Chronological Forensic Super Timeline", border_style="bright_black", header_style="bold magenta")
        table.add_column("Timestamp (UTC)", style="dim", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Source", style="cyan")
        table.add_column("Actor", style="yellow")
        table.add_column("Action", style="white")
        table.add_column("Target / Command", style="green", max_width=45, overflow="ellipsis")
        table.add_column("MITRE ATT&CK", style="bold red", max_width=35, overflow="ellipsis")

        for event in events:
            sev = event.severity
            sev_style = "bold red" if sev == Severity.CRITICAL else "red" if sev == Severity.HIGH else "yellow" if sev == Severity.MEDIUM else "cyan" if sev == Severity.LOW else "dim"

            target_or_cmd = event.command_line if event.command_line else event.target
            mitre_tags = "; ".join(event.mitre_techniques) if event.mitre_techniques else "-"

            table.add_row(
                event.timestamp_iso[:19],
                f"[{sev_style}]{sev.value}[/{sev_style}]",
                event.source_type.value,
                event.actor or "-",
                event.action,
                target_or_cmd or "-",
                mitre_tags,
            )

        console.print(table)
        return

    except ImportError:
        pass

    # Pure standard library fallback (zero-dependency USB safe)
    print("=" * 80)
    print("  ANUBISTRACE FORENSIC TRIAGE SUMMARY")
    print("=" * 80)
    sev_counts = stats.get("severity_counts", {})
    print(f"  Total Ingested: {stats.get('total_events')}")
    print(f"  CRITICAL: {sev_counts.get('CRITICAL', 0)} | HIGH: {sev_counts.get('HIGH', 0)} | MEDIUM: {sev_counts.get('MEDIUM', 0)} | LOW: {sev_counts.get('LOW', 0)}")
    print(f"  Unique IoCs: {len(stats.get('unique_iocs', []))}")
    print("-" * 80)
    print(f"{'TIMESTAMP (UTC)':<20} {'SEV':<8} {'ACTOR':<15} {'ACTION':<22} {'TARGET / COMMAND':<30}")
    print("-" * 80)

    for event in events:
        color = SEVERITY_COLORS.get(event.severity, WHITE)
        target_or_cmd = (event.command_line or event.target or "-")[:28]
        actor = (event.actor or "-")[:13]
        action = event.action[:20]
        ts = event.timestamp_iso[:19]
        print(f"{ts:<20} {color}{event.severity.value:<8}{RESET} {actor:<15} {action:<22} {target_or_cmd:<30}")
    print("=" * 80)
