"""
Detection Rule Model for AnubisTrace.
Defines declarative Sigma-style rules for pattern matching against forensic events.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern

from anubistrace.core.event import ForensicEvent, Severity


@dataclass
class DetectionRule:
    """Represents a single detection rule for forensic events."""
    id: str
    title: str
    description: str
    severity: Severity
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    selection: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())

    def matches(self, event: ForensicEvent) -> bool:
        """Evaluates whether the given ForensicEvent matches the selection criteria."""
        if not self.selection:
            return False

        # 1. Match event_id (list or string)
        if "event_id" in self.selection:
            expected_ids = self.selection["event_id"]
            if isinstance(expected_ids, list):
                if event.event_id not in [str(x) for x in expected_ids]:
                    return False
            elif str(expected_ids) != event.event_id:
                return False

        # 2. Match actor (case-insensitive substring or exact)
        if "actor" in self.selection:
            expected_actor = str(self.selection["actor"]).lower()
            if not event.actor or expected_actor not in event.actor.lower():
                return False

        # 3. Match target (case-insensitive substring or exact)
        if "target" in self.selection:
            expected_target = str(self.selection["target"]).lower()
            if not event.target or expected_target not in event.target.lower():
                return False

        # 4. Match command_line_contains (list of strings, ANY must match)
        if "command_line_contains" in self.selection:
            terms = self.selection["command_line_contains"]
            cmd = (event.command_line or "").lower()
            if not any(term.lower() in cmd for term in terms):
                return False

        # 5. Match command_line_regex (regex pattern)
        if "command_line_regex" in self.selection:
            pattern_str = self.selection["command_line_regex"]
            try:
                regex = re.compile(pattern_str, re.IGNORECASE)
                if not event.command_line or not regex.search(event.command_line):
                    return False
            except re.error:
                return False

        return True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionRule:
        """Instantiates a DetectionRule from a dictionary (e.g. from YAML)."""
        mitre_info = data.get("mitre", {})
        return cls(
            id=data.get("id", "UNKNOWN"),
            title=data.get("title", "Untitled Rule"),
            description=data.get("description", ""),
            severity=Severity(data.get("severity", "MEDIUM").upper()),
            mitre_tactic=mitre_info.get("tactic", "Unknown"),
            mitre_technique_id=mitre_info.get("technique_id", "T0000"),
            mitre_technique_name=mitre_info.get("technique_name", "Unknown Technique"),
            selection=data.get("detection", {}).get("selection", {}),
            tags=data.get("tags", []),
        )
