"""
Live Forensic Triage Collector for AnubisTrace.
Designed for rapid live response from a USB drive on suspect machines (Windows & Linux).
Maintains forensic chain of custody with SHA-256 evidence hashing and metadata manifests.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def calculate_sha256(filepath: Path) -> str:
    """Calculates SHA-256 hash of a file for forensic verification."""
    sha256 = hashlib.sha256()
    try:
        with filepath.open("rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.debug(f"Unable to hash {filepath}: {e}")
        return "ERROR_HASHING_FILE"


class LiveCollector:
    """
    Executes non-destructive, rapid artifact collection from a running endpoint.
    Extracts volatile state (network, processes) and on-disk forensic artifacts.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir.resolve()
        self.artifacts_dir = self.output_dir / "artifacts"
        self.volatile_dir = self.output_dir / "volatile"
        self.manifest_file = self.output_dir / "evidence_manifest.json"

    def run_triage(self) -> Path:
        """Executes full live collection and produces an evidence package."""
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.volatile_dir.mkdir(parents=True, exist_ok=True)

        start_time = datetime.now(timezone.utc)
        print(f"[*] Starting AnubisTrace live triage at: {start_time.isoformat()}")
        print(f"[*] Destination: {self.output_dir}")

        collected_files: List[Dict[str, Any]] = []

        # 1. Collect Volatile System State
        self._collect_volatile_data()

        # 2. Collect OS Specific Artifacts
        current_os = platform.system().lower()
        if current_os == "windows":
            self._collect_windows_artifacts(collected_files)
        else:
            self._collect_linux_artifacts(collected_files)

        # 3. Hash all collected files for Chain of Custody
        for root, _, files in os.walk(self.output_dir):
            for file_name in files:
                p = Path(root) / file_name
                if p == self.manifest_file:
                    continue
                file_hash = calculate_sha256(p)
                rel_path = str(p.relative_to(self.output_dir))
                collected_files.append({
                    "relative_path": rel_path,
                    "sha256": file_hash,
                    "size_bytes": p.stat().st_size,
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                })

        # 4. Generate Forensic Manifest
        end_time = datetime.now(timezone.utc)
        manifest_data = {
            "case_info": {
                "tool": "AnubisTrace Live Collector",
                "collector_version": "0.1.0",
                "triage_start_utc": start_time.isoformat(),
                "triage_end_utc": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds(),
            },
            "system_profile": {
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "os_release": platform.release(),
                "os_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
            },
            "evidence_manifest": collected_files,
        }

        self.manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        print(f"[✓] Live triage finished. {len(collected_files)} artifact(s) hashed into evidence manifest.")
        return self.output_dir

    def _collect_volatile_data(self) -> None:
        """Collects network sockets, process tree, and session info via OS commands."""
        commands: List[Tuple[str, str]] = []

        if platform.system().lower() == "windows":
            commands = [
                ("netstat_ano.txt", "netstat -ano"),
                ("tasklist_verbose.txt", "tasklist /v /fo csv"),
                ("ipconfig_dns.txt", "ipconfig /displaydns"),
                ("systeminfo.txt", "systeminfo"),
                ("active_users.txt", "query user"),
            ]
        else:
            commands = [
                ("ss_sockets.txt", "ss -tulpn"),
                ("ps_forest.txt", "ps aux --forest"),
                ("who_sessions.txt", "w"),
                ("uptime.txt", "uptime"),
                ("ip_routes.txt", "ip route show"),
            ]

        for filename, cmd in commands:
            out_file = self.volatile_dir / filename
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                output = result.stdout or result.stderr
                out_file.write_text(output, encoding="utf-8", errors="replace")
            except Exception as e:
                logger.debug(f"Volatile command failed '{cmd}': {e}")

    def _collect_windows_artifacts(self, registry: List[Dict[str, Any]]) -> None:
        """Copies critical Windows artifacts (Event Logs and Prefetch)."""
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))

        # 1. Event Logs
        evtx_dir = system_root / r"System32\Winevt\Logs"
        critical_logs = [
            "Security.evtx",
            "System.evtx",
            "Microsoft-Windows-PowerShell%4Operational.evtx",
            "Microsoft-Windows-TaskScheduler%4Operational.evtx",
        ]

        dest_evtx = self.artifacts_dir / "evtx"
        dest_evtx.mkdir(exist_ok=True)

        for log_name in critical_logs:
            src = evtx_dir / log_name
            if src.exists():
                dest = dest_evtx / log_name
                try:
                    shutil.copy2(src, dest)
                except PermissionError:
                    # In use by OS, ignore or attempt shadow copy
                    logger.debug(f"Direct copy locked for {src}")

        # 2. Prefetch Files (*.pf)
        prefetch_dir = system_root / "Prefetch"
        if prefetch_dir.exists():
            dest_pf = self.artifacts_dir / "prefetch"
            dest_pf.mkdir(exist_ok=True)
            try:
                # Copy the most recently modified 100 prefetch files
                pf_files = sorted(prefetch_dir.glob("*.pf"), key=lambda p: p.stat().st_mtime, reverse=True)[:100]
                for pf in pf_files:
                    try:
                        shutil.copy2(pf, dest_pf / pf.name)
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Error copying prefetch files: {e}")

    def _collect_linux_artifacts(self, registry: List[Dict[str, Any]]) -> None:
        """Copies critical Linux log files and shell histories."""
        log_files = [
            Path("/var/log/auth.log"),
            Path("/var/log/secure"),
            Path("/var/log/syslog"),
            Path("/var/log/audit/audit.log"),
        ]

        dest_logs = self.artifacts_dir / "logs"
        dest_logs.mkdir(exist_ok=True)

        for log_path in log_files:
            if log_path.exists():
                try:
                    shutil.copy2(log_path, dest_logs / log_path.name)
                except Exception as e:
                    logger.debug(f"Error copying {log_path}: {e}")

        # Shell histories from /home and /root
        dest_history = self.artifacts_dir / "histories"
        dest_history.mkdir(exist_ok=True)

        home_dir = Path("/home")
        history_targets = [Path("/root/.bash_history")]
        if home_dir.exists():
            history_targets.extend(home_dir.glob("*/.bash_history"))

        for hist in history_targets:
            if hist.exists():
                user_label = hist.parent.name
                dest = dest_history / f"{user_label}_bash_history"
                try:
                    shutil.copy2(hist, dest)
                except Exception as e:
                    logger.debug(f"Error copying history {hist}: {e}")
