"""
MITRE ATT&CK Knowledge & Enrichment Engine.
Maps forensic event IDs, LOLBins, and command-line heuristics to the
MITRE ATT&CK Enterprise Matrix (Tactics & Techniques).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Tuple

from anubistrace.core.event import ForensicEvent, Severity


@dataclass(frozen=True)
class MitreRule:
    """Represents a rule that maps an observed behavior to a MITRE technique."""
    tactic: str
    technique_id: str
    technique_name: str
    default_severity: Severity
    description: str


class MitreEngine:
    """
    Enriches raw forensic events with MITRE ATT&CK context, IoCs,
    and calculates adjusted severity scores.
    """

    # Windows Security / System Event ID direct mappings
    EVENT_ID_MAP: Dict[str, List[MitreRule]] = {
        # Process Creation
        "4688": [
            MitreRule(
                tactic="Execution",
                technique_id="T1059",
                technique_name="Command and Scripting Interpreter",
                default_severity=Severity.INFO,
                description="Process creation observed in security audit logs.",
            )
        ],
        # Failed Logon (Brute Force)
        "4625": [
            MitreRule(
                tactic="Credential Access",
                technique_id="T1110",
                technique_name="Brute Force",
                default_severity=Severity.MEDIUM,
                description="Failed user logon attempt detected.",
            )
        ],
        # Defense Evasion: Log Clearing
        "1102": [
            MitreRule(
                tactic="Defense Evasion",
                technique_id="T1070.001",
                technique_name="Indicator Removal: Clear Windows Event Logs",
                default_severity=Severity.CRITICAL,
                description="Security audit log was manually cleared.",
            )
        ],
        "104": [
            MitreRule(
                tactic="Defense Evasion",
                technique_id="T1070.001",
                technique_name="Indicator Removal: Clear Windows Event Logs",
                default_severity=Severity.CRITICAL,
                description="System log file was manually cleared.",
            )
        ],
        # Persistence: Service Installation
        "7045": [
            MitreRule(
                tactic="Persistence",
                technique_id="T1543.003",
                technique_name="Create or Modify System Process: Windows Service",
                default_severity=Severity.HIGH,
                description="A new system service was registered on the host.",
            )
        ],
        "4697": [
            MitreRule(
                tactic="Persistence",
                technique_id="T1543.003",
                technique_name="Create or Modify System Process: Windows Service",
                default_severity=Severity.HIGH,
                description="Service installation attempt recorded in security log.",
            )
        ],
        # Account Creation
        "4720": [
            MitreRule(
                tactic="Persistence",
                technique_id="T1136.001",
                technique_name="Create Account: Local Account",
                default_severity=Severity.HIGH,
                description="A new local user account was created.",
            )
        ],
        # Account Privilege Escalation
        "4728": [
            MitreRule(
                tactic="Persistence",
                technique_id="T1098",
                technique_name="Account Manipulation",
                default_severity=Severity.HIGH,
                description="User added to security-enabled global group (e.g. Domain Admins).",
            )
        ],
        "4732": [
            MitreRule(
                tactic="Privilege Escalation",
                technique_id="T1078",
                technique_name="Valid Accounts",
                default_severity=Severity.HIGH,
                description="User added to security-enabled local group (e.g. Administrators).",
            )
        ],
        # Audit Policy Tampering
        "4719": [
            MitreRule(
                tactic="Defense Evasion",
                technique_id="T1562.002",
                technique_name="Impair Defenses: Disable Windows Event Logging",
                default_severity=Severity.CRITICAL,
                description="System audit policy was modified.",
            )
        ],
        # PowerShell Script Block Execution
        "4104": [
            MitreRule(
                tactic="Execution",
                technique_id="T1059.001",
                technique_name="Command and Scripting Interpreter: PowerShell",
                default_severity=Severity.LOW,
                description="PowerShell script block executed.",
            )
        ],
    }

    # Known Living Off The Land Binaries (LOLBins)
    LOLBINS: Dict[str, Tuple[str, str, Severity]] = {
        "certutil.exe": ("T1105", "Ingress Tool Transfer / Decode", Severity.HIGH),
        "powershell.exe": ("T1059.001", "PowerShell Execution", Severity.LOW),
        "pwsh.exe": ("T1059.001", "PowerShell Core Execution", Severity.LOW),
        "mshta.exe": ("T1218.005", "Signed Binary Proxy: Mshta", Severity.HIGH),
        "rundll32.exe": ("T1218.011", "Signed Binary Proxy: Rundll32", Severity.MEDIUM),
        "regsvr32.exe": ("T1218.010", "Signed Binary Proxy: Regsvr32", Severity.HIGH),
        "wmic.exe": ("T1047", "Windows Management Instrumentation", Severity.MEDIUM),
        "bitsadmin.exe": ("T1197", "BITS Jobs Abuse", Severity.HIGH),
        "vssadmin.exe": ("T1490", "Inhibit System Recovery", Severity.CRITICAL),
        "schtasks.exe": ("T1053.005", "Scheduled Task Abuse", Severity.MEDIUM),
        "nltest.exe": ("T1482", "Domain Trust Discovery", Severity.MEDIUM),
        "whoami.exe": ("T1033", "System Owner/User Discovery", Severity.LOW),
        "procdump.exe": ("T1003.001", "OS Credential Dumping: LSASS", Severity.CRITICAL),
        "mimikatz.exe": ("T1003", "OS Credential Dumping", Severity.CRITICAL),
    }

    # Heuristic Regex Patterns for Command-line analysis
    COMMAND_PATTERNS: List[Tuple[Pattern[str], MitreRule]] = [
        # Encoded PowerShell Commands
        (
            re.compile(r"powershell.*(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE),
            MitreRule(
                tactic="Defense Evasion",
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                default_severity=Severity.HIGH,
                description="Base64 encoded PowerShell command executed.",
            ),
        ),
        # Shadow Copies Deletion (Ransomware Heuristic)
        (
            re.compile(r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy\s+delete|wbadmin.*delete\s+catalog)", re.IGNORECASE),
            MitreRule(
                tactic="Impact",
                technique_id="T1490",
                technique_name="Inhibit System Recovery",
                default_severity=Severity.CRITICAL,
                description="Volume shadow copy deletion command detected (ransomware behavior).",
            ),
        ),
        # Ingress Web Downloads
        (
            re.compile(r"(downloadstring|invoke-webrequest|iwr\s+|curl\s+|wget\s+|certutil.*-urlcache)", re.IGNORECASE),
            MitreRule(
                tactic="Command and Control",
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                default_severity=Severity.HIGH,
                description="Outbound web download command invoked via CLI/script.",
            ),
        ),
        # Windows Defender Disabling
        (
            re.compile(r"(Set-MpPreference.*-DisableRealtimeMonitoring|sc\s+stop\s+WinDefend|net\s+stop\s+WinDefend)", re.IGNORECASE),
            MitreRule(
                tactic="Defense Evasion",
                technique_id="T1562.001",
                technique_name="Impair Defenses: Disable or Modify Tools",
                default_severity=Severity.CRITICAL,
                description="Attempt to disable Windows Defender antivirus detected.",
            ),
        ),
        # User & Domain Reconnaissance
        (
            re.compile(r"(net\s+user.*\/domain|net\s+group.*\"Domain Admins\"|whoami\s+\/all|nltest\s+\/dclist)", re.IGNORECASE),
            MitreRule(
                tactic="Discovery",
                technique_id="T1087",
                technique_name="Account Discovery",
                default_severity=Severity.MEDIUM,
                description="Active domain or local account enumeration command.",
            ),
        ),
    ]

    @classmethod
    def enrich(cls, event: ForensicEvent) -> ForensicEvent:
        """
        Takes an ingested event and enriches it with:
        - MITRE Tactics and Techniques
        - IoC tags
        - Calculated severity bump if malicious patterns match
        """
        # 1. Enrich by Event ID
        if event.event_id in cls.EVENT_ID_MAP:
            for rule in cls.EVENT_ID_MAP[event.event_id]:
                event.add_mitre(rule.tactic, f"{rule.technique_id}: {rule.technique_name}")
                if rule.default_severity > event.severity:
                    event.severity = rule.default_severity

        # 2. Check for LOLBins in Target or Command Line
        search_target = (event.target or "").lower()
        search_cmd = (event.command_line or "").lower()

        for lolbin, (tech_id, tech_name, sev) in cls.LOLBINS.items():
            if lolbin in search_target or lolbin in search_cmd:
                event.add_mitre("Defense Evasion / Execution", f"{tech_id}: {tech_name}")
                event.add_ioc(f"LOLBIN:{lolbin.upper()}")
                if sev > event.severity:
                    event.severity = sev

        # 3. Check Heuristic Regexes against Command Line
        if event.command_line:
            for pattern, rule in cls.COMMAND_PATTERNS:
                if pattern.search(event.command_line):
                    event.add_mitre(rule.tactic, f"{rule.technique_id}: {rule.technique_name}")
                    event.add_ioc(f"RULE:{rule.technique_id}")
                    if rule.default_severity > event.severity:
                        event.severity = rule.default_severity

        # 4. Check RDP remote logon (Event 4624 LogonType 10)
        if event.event_id == "4624":
            logon_type = str(event.details.get("LogonType", ""))
            if logon_type == "10":
                event.add_mitre("Lateral Movement", "T1021.001: Remote Desktop Protocol")
                event.add_ioc("LOGON:RDP_REMOTE")
                if Severity.LOW > event.severity:
                    event.severity = Severity.LOW
            elif logon_type == "3":
                event.add_mitre("Lateral Movement", "T1021.002: SMB/Windows Admin Shares")
                event.add_ioc("LOGON:NETWORK_SHARE")

        return event
