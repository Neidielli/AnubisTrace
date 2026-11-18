"""
Command-Line Interface for AnubisTrace.
Supports both rich interactive terminal UI and zero-dependency fallback.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import socket
import sys
import webbrowser
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


def _configure_console_encoding() -> None:
    """Configures stdout/stderr to UTF-8 safely on Windows consoles (cp1252/cp850)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _resolve_rules_dir(rules_arg: str) -> Path:
    """Resolves the rules directory, falling back to PyInstaller bundled rules if frozen."""
    candidate = Path(rules_arg)
    if candidate.exists():
        return candidate
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundled = Path(getattr(sys, "_MEIPASS")) / "rules"
        if bundled.exists():
            return bundled
    return candidate


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
    try:
        print(banner)
    except UnicodeEncodeError:
        print(f"\n=== {__app_name__} v{__version__} - Forensic Incident Triage & Timeline Engine ===\n")


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


def _get_base_dir() -> Path:
    """
    Returns the directory containing the executable when frozen (e.g. USB drive),
    so 'Run as Administrator' does not default to C:\\Windows\\System32.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path.cwd()


def _is_admin() -> bool:
    """Checks if the process has administrative / root privileges."""
    if platform.system().lower() == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _pause(message: str = "\nPressione ENTER para voltar ao menu...") -> None:
    """Waits for Enter safely without crashing if stdin is closed."""
    try:
        input(message)
    except (KeyboardInterrupt, EOFError):
        pass


def _maybe_open_report(report_path: Path) -> None:
    """Offers to open the generated HTML dashboard in the default browser."""
    if not report_path.exists():
        return
    try:
        answer = input(f"\n[?] Deseja abrir o Dashboard HTML ({report_path.name}) no navegador? [S/n]: ").strip().lower()
        if answer in ("", "s", "sim", "y", "yes"):
            webbrowser.open(report_path.resolve().as_uri())
            print("[✓] Dashboard aberto no navegador.")
    except Exception as err:
        print(f"[!] Nao foi possivel abrir o navegador automaticamente: {err}")


def run_interactive_menu(parser: argparse.ArgumentParser) -> int:
    """Interactive menu when launched via double-click or without arguments."""
    base_dir = _get_base_dir()
    rules_dir = _resolve_rules_dir(str(base_dir / "rules"))

    while True:
        print_banner()
        is_admin = _is_admin()
        priv_status = "ADMINISTRADOR [OK]" if is_admin else "USUARIO PADRAO (execute como Admin para coleta completa de EVTX/Prefetch)"

        print(f"  Host Atual   : {socket.gethostname()} ({platform.system()} {platform.release()})")
        print(f"  Diretorio    : {base_dir}")
        print(f"  Privilegios  : {priv_status}")
        print("  " + "=" * 65)
        print("  [1] Live Triage   - Coletar evidencias desta maquina e analisar")
        print("  [2] Scan Offline  - Analisar pasta ou arquivo forense existente")
        print("  [3] Ajuda CLI     - Exibir opcoes de linha de comando")
        print("  [0] Sair")
        print("  " + "=" * 65)

        try:
            choice = input("\n  Escolha uma opcao [0-3]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Encerrando AnubisTrace.")
            return 0

        if choice == "0":
            print("\n[*] Encerrando AnubisTrace.")
            return 0

        elif choice == "1":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_out = base_dir / "Casos_Evidencias" / f"Incidente_{socket.gethostname()}_{timestamp}"
            try:
                custom_out = input(f"\n  Pasta de destino [Enter para padrao: {default_out}]: ").strip().strip('"').strip("'")
                out_path = Path(custom_out) if custom_out else default_out

                collector = LiveCollector(out_path)
                collector.run_triage()

                print("\n[*] Iniciando analise automatica dos artefatos coletados...")
                analysis_dir = out_path / "analysis"
                execute_scan(
                    input_path=out_path,
                    output_dir=analysis_dir,
                    rules_dir=rules_dir,
                    min_severity="INFO",
                    output_format="all",
                )
                _maybe_open_report(analysis_dir / "report.html")
            except Exception as err:
                print(f"\n[ERROR] Falha durante a triagem ao vivo: {err}")

            _pause()

        elif choice == "2":
            try:
                raw_input = input("\n  Caminho da pasta ou arquivo de evidencias (pode arrastar aqui): ").strip().strip('"').strip("'")
                if not raw_input:
                    print("[!] Nenhum caminho informado.")
                    _pause()
                    continue

                input_path = Path(raw_input)
                if not input_path.exists():
                    print(f"[ERROR] Caminho nao encontrado: {input_path}")
                    _pause()
                    continue

                sev_raw = input("  Severidade minima (INFO/LOW/MEDIUM/HIGH/CRITICAL) [Enter = INFO]: ").strip().upper()
                min_sev = sev_raw if sev_raw in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") else "INFO"

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                default_out = base_dir / "Casos_Evidencias" / f"Scan_{timestamp}"
                custom_out = input(f"  Pasta de saida dos relatorios [Enter para padrao: {default_out}]: ").strip().strip('"').strip("'")
                out_path = Path(custom_out) if custom_out else default_out

                execute_scan(
                    input_path=input_path,
                    output_dir=out_path,
                    rules_dir=rules_dir,
                    min_severity=min_sev,
                    output_format="all",
                )
                _maybe_open_report(out_path / "report.html")
            except Exception as err:
                print(f"\n[ERROR] Falha durante o scan offline: {err}")

            _pause()

        elif choice == "3":
            print()
            parser.print_help()
            _pause()

        else:
            print("\n[!] Opcao invalida. Escolha 0, 1, 2 ou 3.")
            _pause("Pressione ENTER para continuar...")


def main(argv: Optional[List[str]] = None) -> int:
    _configure_console_encoding()
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
        if getattr(sys, "frozen", False) or (sys.stdin and sys.stdin.isatty()):
            return run_interactive_menu(parser)
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
            rules_dir=_resolve_rules_dir(args.rules),
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
            rules_dir=_resolve_rules_dir(args.rules),
            min_severity="INFO",
            output_format=args.format,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
