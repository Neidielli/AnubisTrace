"""
Forensic Event Data Model
Defines the unified schema for all ingested forensic artifacts.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Event severity levels with comparison support."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        levels = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return levels[self]

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.rank >= other.rank

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.rank > other.rank

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.rank <= other.rank

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            other = Severity(other.upper())
        return self.rank < other.rank


class SourceType(str, Enum):
    """Artifact source origin."""
    EVTX_SECURITY = "EVTX_SECURITY"
    EVTX_SYSTEM = "EVTX_SYSTEM"
    EVTX_APPLICATION = "EVTX_APPLICATION"
    EVTX_POWERSHELL = "EVTX_POWERSHELL"
    PREFETCH = "PREFETCH"
    REGISTRY = "REGISTRY"
    MFT = "MFT"
    LINUX_AUTH = "LINUX_AUTH"
    LINUX_SYSLOG = "LINUX_SYSLOG"
    LINUX_HISTORY = "LINUX_HISTORY"
    GENERIC = "GENERIC"


@dataclass
class ForensicEvent:
    """
    Unified Forensic Event Schema.
    Normalizes artifacts from Windows, Linux, and network logs into a single
    chronological data structure mapped to the MITRE ATT&CK framework.
    """
    timestamp: datetime
    source_type: SourceType
    action: str
    source_file: str = "unknown"
    event_id: str = ""
    severity: Severity = Severity.INFO
    actor: str = "SYSTEM"
    target: str = ""
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Ensure timestamp is timezone-aware (defaulting to UTC if naive)
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        else:
            self.timestamp = self.timestamp.astimezone(timezone.utc)

        # Ensure enums
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
        if isinstance(self.source_type, str):
            self.source_type = SourceType(self.source_type.upper())

    @property
    def timestamp_iso(self) -> str:
        """Returns UTC ISO 8601 formatted timestamp string."""
        return self.timestamp.isoformat()

    def add_mitre(self, tactic: str, technique: str) -> None:
        """Adds a MITRE ATT&CK tactic and technique without duplicates."""
        if tactic and tactic not in self.mitre_tactics:
            self.mitre_tactics.append(tactic)
        if technique and technique not in self.mitre_techniques:
            self.mitre_techniques.append(technique)

    def add_ioc(self, ioc: str) -> None:
        """Adds an Indicator of Compromise tag."""
        if ioc and ioc not in self.iocs:
            self.iocs.append(ioc)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes event to dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp_iso
        data["severity"] = self.severity.value
        data["source_type"] = self.source_type.value
        return data

    def to_json(self) -> str:
        """Serializes event to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForensicEvent:
        """Deserializes event from dictionary."""
        raw = dict(data)
        if isinstance(raw["timestamp"], str):
            raw["timestamp"] = datetime.fromisoformat(raw["timestamp"])
        if isinstance(raw["severity"], str):
            raw["severity"] = Severity(raw["severity"])
        if isinstance(raw["source_type"], str):
            raw["source_type"] = SourceType(raw["source_type"])
        return cls(**raw)

    def to_timeline_row(self) -> Dict[str, str]:
        """
        Formats event for CSV Super Timeline export (Eric Zimmerman / Plaso standard).
        """
        return {
            "Timestamp (UTC)": self.timestamp_iso,
            "Severity": self.severity.value,
            "Source": self.source_type.value,
            "Event ID": self.event_id,
            "Actor": self.actor,
            "Action": self.action,
            "Target": self.target,
            "Command Line": self.command_line or "",
            "Parent Process": self.parent_process or "",
            "MITRE Tactics": ", ".join(self.mitre_tactics),
            "MITRE Techniques": ", ".join(self.mitre_techniques),
            "IoCs": ", ".join(self.iocs),
            "Source File": self.source_file,
        }
