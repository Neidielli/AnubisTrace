"""
Command-Line Interface for AnubisTrace.
Supports both rich interactive terminal UI and zero-dependency fallback.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from anubistrace import __app_name__, __version__
from anubistrace.core.event import Severity
from anubistrace.core.timeline import TimelineEngine
from anubistrace.parsers import get_all_parsers
from anubistrace.reporters import export_to_csv, export_to_jsonl, render_terminal_report


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
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Minimum severity threshold to display (default: INFO)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["terminal", "csv", "jsonl", "all"],
        default="all",
        help="Output report formats (default: all)",
    )

    # Command: live-triage
    subparsers.add_parser(
        "live",
        help="Execute rapid live triage on the current host (requires administrative privileges)",
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

        print(f"[*] Initializing AnubisTrace forensic engine on: {input_path}")
        parsers = get_all_parsers()
        timeline = TimelineEngine()

        # Collect files to process
        files_to_scan: List[Path] = []
        if input_path.is_file():
            files_to_scan.append(input_path)
        else:
            files_to_scan.extend([p for p in input_path.rglob("*") if p.is_file()])

        processed_count = 0
        for f in files_to_scan:
            for p in parsers:
                if p.can_parse(f):
                    try:
                        events = list(p.parse(f))
                        timeline.add_events(events)
                        if events:
                            print(f"  [+] Ingested {len(events):>4} events from {f.name:<25} via {p.name}")
                            processed_count += 1
                    except Exception as err:
                        print(f"  [-] Error in parser {p.name} on {f.name}: {err}", file=sys.stderr)

        if len(timeline) == 0:
            print("[!] No supported forensic events were detected in the target path.")
            return 0

        # Filter by requested severity
        min_sev = Severity(args.min_severity)
        filtered_events = timeline.filter(min_severity=min_sev)
        stats = timeline.get_statistics()

        # Render Terminal UI
        if args.format in ("terminal", "all"):
            render_terminal_report(filtered_events, stats)

        # Export Files
        out_dir = Path(args.output)
        if args.format in ("csv", "all"):
            csv_path = out_dir / "timeline.csv"
            export_to_csv(filtered_events, csv_path)
            print(f"[✓] Super Timeline CSV exported to: {csv_path.resolve()}")

        if args.format in ("jsonl", "all"):
            jsonl_path = out_dir / "timeline.jsonl"
            export_to_jsonl(filtered_events, jsonl_path)
            print(f"[✓] SIEM-ready JSONL stream exported to: {jsonl_path.resolve()}")

        return 0

    elif args.command == "live":
        print("[*] Live host triage selected. Administrator privileges check in progress...")
        print("[!] Live collector module will be linked in Phase 5.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
