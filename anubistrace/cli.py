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
from anubistrace.core.mitre import MitreEngine
from anubistrace.core.timeline import TimelineEngine


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
        "-o", "--output", help="Output directory for generated reports and timeline files"
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

        print(f"[*] Initializing AnubisTrace engine on: {input_path}")
        print(f"[*] Severity threshold: {args.min_severity}")
        print("[!] Parsers will execute in Phase 2.")
        return 0

    elif args.command == "live":
        print("[*] Live host triage selected. Administrator privileges check in progress...")
        print("[!] Live collector module will be linked in Phase 5.")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
