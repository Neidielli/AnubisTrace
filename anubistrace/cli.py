"""
Command-Line Interface for AnubisTrace.
Supports both rich interactive terminal UI and zero-dependency fallback.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from anubistrace import __app_name__, __version__
from anubistrace.core.event import Severity
from anubistrace.core.timeline import TimelineEngine
from anubistrace.engine import (
    TemporalCorrelationEngine,
    apply_rules,
    load_rules_from_directory,
)
from anubistrace.parsers import get_all_parsers
from anubistrace.reporters import (
    export_to_csv,
    export_to_jsonl,
    generate_html_report,
    render_terminal_report,
)
from anubistrace.reporters.terminal import render_attack_chains
from anubistrace.triage import LiveCollector


def print_banner() -> None:
    banner = f"""
    ╔═════════════════════════════════════════════════════════════════╗
    ║   ___             _     _    _____                              ║
    ║  / _ \\           | |   (_)  |_   _|                             ║
    ║ / /_\\ \\_ __  _   | |__  _ ___ | |_ __ __ _  ___ ___            ║
    ║ |  _  | '_ \\| | | | '_ \\| / __|| | '__/ _` |/ __/ _ \\           ║
    ║ | | | | | | | |_| | |_) | \\__ \\| | | | (_| | (_|  __/           ║
    ║ \\_| |_/_| |_|\\__,_|_.__/|_|___/\\_/ |_|  \\__,_|\\___\\___|           ║
    ║                                                                 ║
    ║  {__app_name__} v{__version__} - Forensic Incident Triage & Timeline Engine   ║
    ║  Author: Neidielli Rosado (@Neidielli) • MITRE ATT&CK Correlator ║
    ╚═════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def execute_scan(
    input_path: Path,
    output_dir: Path,
    rules_dir: Path,
    min_severity: str = "INFO",
    output_format: str = "all",
) -> int:
    """Executes artifact ingestion, rules evaluation, correlation, and reporting."""
    print(f"[*] Initializing AnubisTrace forensic engine on: {input_path}")
    parsers = get_all_parsers()
    timeline = TimelineEngine()

    files_to_scan: List[Path] = []
    if input_path.is_file():
        files_to_scan.append(input_path)
    else:
        files_to_scan.extend([p for p in input_path.rglob("*") if p.is_file()])

    for f in files_to_scan:
        for p in parsers:
            if p.can_parse(f):
                try:
                    events = list(p.parse(f))
                    timeline.add_events(events)
                    if events:
                        print(f"  [+] Ingested {len(events):>4} events from {f.name:<25} via {p.name}")
                except Exception as err:
                    print(f"  [-] Error in parser {p.name} on {f.name}: {err}", file=sys.stderr)

    if len(timeline) == 0:
        print("[!] No supported forensic events were detected in the target path.")
        return 0

    # Load & Apply Detection Rules
    detection_rules = load_rules_from_directory(rules_dir)
    rule_hits = 0
    for event in timeline.events:
        matches = apply_rules(event, detection_rules)
        rule_hits += len(matches)

    print(f"[*] Evaluated {len(detection_rules)} detection rules ({rule_hits} rule hits applied)")

    # Run Temporal Correlation
    correlator = TemporalCorrelationEngine(time_window_minutes=30)
    attack_chains = correlator.correlate(timeline.events)

    if attack_chains:
        print(f"[!] 🚨 Correlation Engine identified {len(attack_chains)} active multi-stage attack chains!")
        render_attack_chains(attack_chains)
        # Inject synthetic attack chain events into timeline
        for chain in attack_chains:
            timeline.add_event(chain.to_forensic_event())

    # Filter by requested severity
    min_sev = Severity(min_severity)
    filtered_events = timeline.filter(min_severity=min_sev)
    stats = timeline.get_statistics()

    # Render Terminal UI
    if output_format in ("terminal", "all"):
        render_terminal_report(filtered_events, stats)

    # Export Files
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_format in ("csv", "all"):
        csv_path = output_dir / "timeline.csv"
        export_to_csv(filtered_events, csv_path)
        print(f"[✓] Super Timeline CSV exported to: {csv_path.resolve()}")

    if output_format in ("jsonl", "all"):
        jsonl_path = output_dir / "timeline.jsonl"
        export_to_jsonl(filtered_events, jsonl_path)
        print(f"[✓] SIEM-ready JSONL stream exported to: {jsonl_path.resolve()}")

    if output_format in ("html", "all"):
        html_path = output_dir / "report.html"
        generate_html_report(filtered_events, stats, attack_chains, html_path)
        print(f"[✓] Interactive HTML Dashboard exported to: {html_path.resolve()}")

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="anubistrace",
        description=f"{__app_name__}: Fast Digital Forensics Triage & MITRE ATT&CK Timeline Correlator.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"{__app_name__} v{__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational modes")

    # Command: triage / scan
    scan_parser = subparsers.add_parser("scan", help="Scan forensic artifacts and build timeline")
    scan_parser.add_argument(
        "-i", "--input", required=True, help="Path to artifact file or triage directory"
    )
    scan_parser.add_argument(
        "-o", "--output", default="output", help="Output directory for generated reports (default: output)"
    )
    scan_parser.add_argument(
        "--rules", default="rules", help="Directory containing custom YAML detection rules (default: rules)"
    )
    scan_parser.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Minimum severity threshold to display (default: INFO)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "csv", "jsonl", "html", "all"],
        default="all",
        help="Output report formats (default: all)",
    )

    # Command: live-triage
    live_parser = subparsers.add_parser(
        "live",
        help="Execute rapid live triage on the current host (requires administrative privileges)",
    )
    live_parser.add_argument(
        "-o", "--output", default=f"live_triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory for extracted evidence and triage report",
    )
    live_parser.add_argument(
        "--rules", default="rules", help="Directory containing custom YAML detection rules (default: rules)"
    )
    live_parser.add_argument(
        "--format",
        choices=["terminal", "csv", "jsonl", "html", "all"],
        default="all",
        help="Output report formats (default: all)",
    )

    args = parser.parse_args(argv)

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    print_banner()

    if args.command == "scan":
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[ERROR] Target path does not exist: {input_path}", file=sys.stderr)
            return 1
        return execute_scan(
            input_path=input_path,
            output_dir=Path(args.output),
            rules_dir=Path(args.rules),
            min_severity=args.min_severity,
            output_format=args.format,
        )

    elif args.command == "live":
        out_path = Path(args.output)
        collector = LiveCollector(out_path)
        collector.run_triage()

        print("\n[*] Transitioning directly to analysis of extracted triage artifacts...")
        return execute_scan(
            input_path=out_path,
            output_dir=out_path / "analysis",
            rules_dir=Path(args.rules),
            min_severity="INFO",
            output_format=args.format,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
