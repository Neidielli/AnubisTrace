"""
Linux Artifact Parser for AnubisTrace.
Parses /var/log/auth.log, syslog, and bash_history.
Extracts brute force attempts, sudo privilege escalation, and suspicious shell commands.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional

from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.mitre import MitreEngine
from anubistrace.parsers.base import BaseParser

logger = logging.getLogger(__name__)

# Month name mapping for syslog timestamps
MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_timestamp(raw_time: str, default_year: int) -> datetime:
    """
    Parses standard syslog date format 'Nov  7 04:12:30' or ISO 8601 '2026-11-07T04:12:30'.
    """
    raw_time = raw_time.strip()
    # Check ISO format
    if "T" in raw_time or len(raw_time) >= 19 and raw_time[4] == "-":
        try:
            return datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except ValueError:
            pass

    # Standard syslog format: 'Mmm dd hh:mm:ss'
    parts = raw_time.split()
    if len(parts) >= 3 and parts[0] in MONTH_MAP:
        try:
            month = MONTH_MAP[parts[0]]
            day = int(parts[1])
            time_parts = parts[2].split(":")
            hour, minute, sec = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            return datetime(default_year, month, day, hour, minute, sec, tzinfo=timezone.utc)
        except Exception:
            pass

    return datetime.now(timezone.utc)


class LinuxParser(BaseParser):
    """
    Parses Linux system logs and user histories:
      - /var/log/auth.log / secure: SSH brute force, successful logins, sudo abuse
      - .bash_history: shell command auditing
    """

    # RegEx Patterns for auth.log
    RE_SSH_FAIL = re.compile(
        r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\S+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    RE_SSH_ACCEPT = re.compile(
        r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\S+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(?:publickey|password)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )
    RE_SUDO_EXEC = re.compile(
        r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\S+)\s+\S+\s+sudo:\s+(?P<user>\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<cmd>.+)$",
        re.IGNORECASE,
    )
    RE_USERADD = re.compile(
        r"^(?P<time>[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\S+)\s+\S+\s+useradd\[\d+\]:\s+new\s+user:\s+name=(?P<new_user>\S+)",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "Linux Logs & History Parser"

    @property
    def supported_extensions(self) -> List[str]:
        return [".log", ".txt", "history", "bash_history"]

    def can_parse(self, filepath: Path) -> bool:
        if not filepath.exists() or not filepath.is_file():
            return False
        filename = filepath.name.lower()
        if "auth" in filename or "secure" in filename or "syslog" in filename or "history" in filename:
            return True
        return filepath.suffix.lower() in [ext.lower() for ext in self.supported_extensions]

    def parse(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses Linux auth logs or shell history."""
        filename = filepath.name.lower()

        if "history" in filename:
            yield from self._parse_bash_history(filepath)
        else:
            yield from self._parse_auth_log(filepath)

    def _parse_auth_log(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses auth.log / secure lines."""
        current_year = datetime.now(timezone.utc).year

        try:
            with filepath.open("r", encoding="utf-8", errors="replace") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    event = self._parse_auth_line(line, str(filepath), current_year)
                    if event:
                        yield MitreEngine.enrich(event)
        except Exception as e:
            logger.error(f"Error parsing Linux log {filepath}: {e}")

    def _parse_auth_line(self, line: str, source_file: str, year: int) -> Optional[ForensicEvent]:
        # 1. SSH Failed Password (Brute Force indicator)
        m = self.RE_SSH_FAIL.search(line)
        if m:
            ts = parse_syslog_timestamp(m.group("time"), year)
            user = m.group("user")
            ip = m.group("ip")
            event = ForensicEvent(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                source_file=source_file,
                event_id="LINUX_SSH_FAIL",
                severity=Severity.MEDIUM,
                actor=user,
                action="SSH Failed Password",
                target=f"sshd ({ip})",
                command_line=None,
                details={"SourceIP": ip, "Port": m.group("port"), "Raw": line},
            )
            event.add_mitre("Credential Access", "T1110: Brute Force")
            event.add_ioc(f"IP:{ip}")
            return event

        # 2. SSH Accepted Login
        m = self.RE_SSH_ACCEPT.search(line)
        if m:
            ts = parse_syslog_timestamp(m.group("time"), year)
            user = m.group("user")
            ip = m.group("ip")
            event = ForensicEvent(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                source_file=source_file,
                event_id="LINUX_SSH_ACCEPT",
                severity=Severity.INFO,
                actor=user,
                action="SSH Logon Successful",
                target=f"Host (from {ip})",
                command_line=None,
                details={"SourceIP": ip, "Port": m.group("port"), "Raw": line},
            )
            event.add_mitre("Initial Access", "T1078: Valid Accounts")
            return event

        # 3. Sudo Command Execution (Privilege Escalation)
        m = self.RE_SUDO_EXEC.search(line)
        if m:
            ts = parse_syslog_timestamp(m.group("time"), year)
            user = m.group("user")
            target_user = m.group("target_user")
            cmd = m.group("cmd").strip()
            event = ForensicEvent(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                source_file=source_file,
                event_id="LINUX_SUDO_EXEC",
                severity=Severity.HIGH,
                actor=user,
                action=f"Sudo Execution (as {target_user})",
                target=target_user,
                command_line=cmd,
                details={"InvokingUser": user, "TargetUser": target_user, "Raw": line},
            )
            event.add_mitre("Privilege Escalation", "T1548.003: Sudo and Sudo Caching")
            return event

        # 4. User Account Created
        m = self.RE_USERADD.search(line)
        if m:
            ts = parse_syslog_timestamp(m.group("time"), year)
            new_user = m.group("new_user")
            event = ForensicEvent(
                timestamp=ts,
                source_type=SourceType.LINUX_AUTH,
                source_file=source_file,
                event_id="LINUX_USERADD",
                severity=Severity.HIGH,
                actor="root",
                action="Linux User Created",
                target=new_user,
                command_line=None,
                details={"NewUser": new_user, "Raw": line},
            )
            event.add_mitre("Persistence", "T1136.001: Create Account: Local Account")
            return event

        return None

    def _parse_bash_history(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses .bash_history lines, recognizing optional epoch timestamps (#1699999999)."""
        file_mtime = datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc)
        current_ts = file_mtime

        try:
            with filepath.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Timestamp line in bash history (e.g. #1699351200)
                    if line.startswith("#") and line[1:].isdigit() and len(line) >= 10:
                        try:
                            epoch = int(line[1:])
                            current_ts = datetime.fromtimestamp(epoch, tz=timezone.utc)
                            continue
                        except Exception:
                            pass

                    # Command line execution
                    event = ForensicEvent(
                        timestamp=current_ts,
                        source_type=SourceType.LINUX_HISTORY,
                        source_file=str(filepath),
                        event_id="LINUX_BASH_CMD",
                        severity=Severity.LOW,
                        actor=filepath.parent.name or "user",
                        action="Bash Command Executed",
                        target="Shell",
                        command_line=line,
                    )
                    yield MitreEngine.enrich(event)
        except Exception as e:
            logger.error(f"Error parsing bash history {filepath}: {e}")
