"""
Temporal Correlation Engine for AnubisTrace.
Correlates multi-source forensic events across sliding time windows
to identify active cyber kill chains and multi-stage attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from anubistrace.core.event import ForensicEvent, Severity, SourceType


@dataclass
class CorrelatedFinding:
    """Represents a multi-event correlated attack sequence."""
    title: str
    description: str
    severity: Severity
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    contributing_events: List[ForensicEvent]
    first_seen: datetime = field(init=False)
    last_seen: datetime = field(init=False)

    def __post_init__(self) -> None:
        if self.contributing_events:
            self.first_seen = min(e.timestamp for e in self.contributing_events)
            self.last_seen = max(e.timestamp for e in self.contributing_events)
        else:
            now = datetime.now()
            self.first_seen = now
            self.last_seen = now

    def to_forensic_event(self) -> ForensicEvent:
        """Converts the correlated finding into a synthetic ForensicEvent for timeline inclusion."""
        return ForensicEvent(
            timestamp=self.last_seen,
            source_type=SourceType.GENERIC,
            source_file="AnubisTrace Correlator",
            event_id="CORRELATED_ATTACK_CHAIN",
            severity=self.severity,
            actor=", ".join(set(e.actor for e in self.contributing_events if e.actor)) or "UNKNOWN",
            action=f"[ATTACK CHAIN] {self.title}",
            target=f"{len(self.contributing_events)} correlated events",
            command_line=self.description,
            mitre_tactics=self.mitre_tactics,
            mitre_techniques=self.mitre_techniques,
            iocs=[f"CHAIN:{self.title.replace(' ', '_').upper()}"],
            details={
                "ContributingEventCount": len(self.contributing_events),
                "DurationSeconds": (self.last_seen - self.first_seen).total_seconds(),
                "EventIDs": [e.event_id for e in self.contributing_events],
            },
        )


class TemporalCorrelationEngine:
    """
    Analyzes an ordered list of ForensicEvents and searches for
    high-confidence attack chains spanning multiple hosts, services, and artifacts.
    """

    def __init__(self, time_window_minutes: int = 30) -> None:
        self.time_window = timedelta(minutes=time_window_minutes)

    def correlate(self, events: List[ForensicEvent]) -> List[CorrelatedFinding]:
        """Runs all correlation rules against the chronological event list."""
        if not events:
            return []

        # Ensure events are sorted
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        findings: List[CorrelatedFinding] = []

        findings.extend(self._correlate_bruteforce_to_success(sorted_events))
        findings.extend(self._correlate_antiforensics_after_suspicious_activity(sorted_events))
        findings.extend(self._correlate_ingress_download_to_execution(sorted_events))
        findings.extend(self._correlate_ransomware_inhibit_recovery(sorted_events))

        return findings

    def _correlate_bruteforce_to_success(self, events: List[ForensicEvent]) -> List[CorrelatedFinding]:
        """
        Detects multiple failed logon attempts followed by a successful logon
        from the same actor or IP within the correlation window.
        """
        findings: List[CorrelatedFinding] = []
        failed_logons: List[ForensicEvent] = []

        for e in events:
            # Check for failed logon (Windows 4625 or Linux SSH fail)
            if e.event_id in ("4625", "LINUX_SSH_FAIL"):
                failed_logons.append(e)

            # Check for successful logon (Windows 4624 or Linux SSH accept)
            elif e.event_id in ("4624", "LINUX_SSH_ACCEPT"):
                if not failed_logons:
                    continue

                # Filter failed logons that occurred within the time window before this success
                relevant_fails = [
                    f for f in failed_logons
                    if (e.timestamp - f.timestamp) <= self.time_window
                    and (f.actor == e.actor or f.details.get("SourceIP") == e.details.get("IpAddress"))
                ]

                # Threshold: 2 or more failed attempts before success indicates brute-force/guessing
                if len(relevant_fails) >= 2:
                    chain_events = relevant_fails + [e]
                    findings.append(
                        CorrelatedFinding(
                            title="Brute-Force Authentication into Successful Access",
                            description=(
                                f"Observed {len(relevant_fails)} failed authentication attempts for actor '{e.actor}' "
                                f"followed by successful access at {e.timestamp_iso}."
                            ),
                            severity=Severity.CRITICAL,
                            mitre_tactics=["Credential Access", "Initial Access / Lateral Movement"],
                            mitre_techniques=["T1110: Brute Force", "T1078: Valid Accounts"],
                            contributing_events=chain_events,
                        )
                    )
                    # Reset matching fails to prevent duplicate alert storms
                    for f in relevant_fails:
                        failed_logons.remove(f)

        return findings

    def _correlate_antiforensics_after_suspicious_activity(self, events: List[ForensicEvent]) -> List[CorrelatedFinding]:
        """
        Detects evidence destruction (event log cleared or bash history cleared)
        occurring shortly after high-severity activity or privilege escalation.
        """
        findings: List[CorrelatedFinding] = []

        for i, e in enumerate(events):
            # Check for log clearing event (Windows 1102/104 or history -c)
            is_log_clear = e.event_id in ("1102", "104") or (e.command_line and "history -c" in e.command_line)
            if not is_log_clear:
                continue

            # Look back in the window for preceding HIGH or CRITICAL suspicious events
            window_start = e.timestamp - self.time_window
            prior_suspicious = [
                prev for prev in events[:i]
                if prev.timestamp >= window_start
                and prev.severity >= Severity.HIGH
                and prev != e
            ]

            if prior_suspicious:
                findings.append(
                    CorrelatedFinding(
                        title="Anti-Forensics: Log Tampering Followed Suspicious Activity",
                        description=(
                            f"Audit log clearing or history destruction was executed at {e.timestamp_iso} by '{e.actor}' "
                            f"after {len(prior_suspicious)} high-severity forensic event(s) were recorded."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_tactics=["Defense Evasion"],
                        mitre_techniques=["T1070.001: Indicator Removal: Clear Windows Event Logs"],
                        contributing_events=prior_suspicious + [e],
                    )
                )

        return findings

    def _correlate_ingress_download_to_execution(self, events: List[ForensicEvent]) -> List[CorrelatedFinding]:
        """
        Detects outbound download cradle commands (curl, wget, downloadstring)
        followed shortly by execution of suspicious binaries.
        """
        findings: List[CorrelatedFinding] = []

        for i, e in enumerate(events):
            cmd = (e.command_line or "").lower()
            is_download = any(k in cmd for k in ["downloadstring", "invoke-webrequest", "curl ", "wget ", "certutil -urlcache"])
            if not is_download:
                continue

            # Look forward in the window for subsequent executions (process creation or prefetch)
            window_end = e.timestamp + timedelta(minutes=10)
            subsequent_execs = [
                post for post in events[i+1:]
                if post.timestamp <= window_end
                and (post.event_id in ("4688", "PREFETCH_EXEC", "LINUX_BASH_CMD"))
                and post != e
            ]

            if subsequent_execs:
                findings.append(
                    CorrelatedFinding(
                        title="Ingress Tool Transfer Followed by Execution",
                        description=(
                            f"Download cradle executed at {e.timestamp_iso} was followed by "
                            f"{len(subsequent_execs)} execution event(s) within 10 minutes."
                        ),
                        severity=Severity.HIGH,
                        mitre_tactics=["Command and Control", "Execution"],
                        mitre_techniques=["T1105: Ingress Tool Transfer", "T1059: Command and Scripting Interpreter"],
                        contributing_events=[e] + subsequent_execs,
                    )
                )

        return findings

    def _correlate_ransomware_inhibit_recovery(self, events: List[ForensicEvent]) -> List[CorrelatedFinding]:
        """
        Detects ransomware kill-chain signature: shadow copy destruction
        co-occurring with service modification or encoded script execution.
        """
        findings: List[CorrelatedFinding] = []

        for i, e in enumerate(events):
            cmd = (e.command_line or "").lower()
            is_shadow_wipe = "delete shadows" in cmd or "shadowcopy delete" in cmd
            if not is_shadow_wipe:
                continue

            # Check for accompanying persistence or evasion events in window
            window_start = e.timestamp - timedelta(minutes=15)
            window_end = e.timestamp + timedelta(minutes=15)
            adjacent_events = [
                adj for adj in events
                if window_start <= adj.timestamp <= window_end
                and adj != e
                and (adj.event_id in ("7045", "4697", "1102", "104") or "powershell" in (adj.command_line or "").lower())
            ]

            if adjacent_events:
                findings.append(
                    CorrelatedFinding(
                        title="Ransomware Kill-Chain: Shadow Copies Purged with System Modification",
                        description=(
                            f"Volume shadow copies were purged at {e.timestamp_iso} in combination with "
                            f"{len(adjacent_events)} critical service/execution event(s)."
                        ),
                        severity=Severity.CRITICAL,
                        mitre_tactics=["Impact", "Defense Evasion"],
                        mitre_techniques=["T1490: Inhibit System Recovery", "T1070: Indicator Removal"],
                        contributing_events=[e] + adjacent_events,
                    )
                )

        return findings
