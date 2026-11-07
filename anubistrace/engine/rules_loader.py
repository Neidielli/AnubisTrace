"""
Rules Loader for AnubisTrace.
Discovers and loads YAML detection rules from the rules/ directory.
Includes built-in fallback rules if PyYAML or files are not available.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from anubistrace.core.event import ForensicEvent, Severity
from anubistrace.engine.rule_model import DetectionRule

logger = logging.getLogger(__name__)

# Built-in fallback rules (always active even without external YAML files)
BUILTIN_RULES: List[DetectionRule] = [
    DetectionRule(
        id="BUILTIN-001",
        title="Audit Log Purged / Cleared",
        description="Detects deletion of audit logs (Anti-Forensics)",
        severity=Severity.CRITICAL,
        mitre_tactic="Defense Evasion",
        mitre_technique_id="T1070.001",
        mitre_technique_name="Clear Windows Event Logs",
        selection={"event_id": ["1102", "104"]},
        tags=["defense_evasion"],
    ),
    DetectionRule(
        id="BUILTIN-002",
        title="Volume Shadow Copy Deletion",
        description="Detects ransomware behavior attempting to wipe backups",
        severity=Severity.CRITICAL,
        mitre_tactic="Impact",
        mitre_technique_id="T1490",
        mitre_technique_name="Inhibit System Recovery",
        selection={"command_line_contains": ["delete shadows", "shadowcopy delete"]},
        tags=["ransomware"],
    ),
    DetectionRule(
        id="BUILTIN-003",
        title="Base64 Encoded PowerShell",
        description="Detects obfuscated PowerShell commands",
        severity=Severity.HIGH,
        mitre_tactic="Defense Evasion",
        mitre_technique_id="T1027",
        mitre_technique_name="Obfuscated Files or Information",
        selection={"command_line_regex": r"powershell.*(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{10,}"},
        tags=["obfuscation"],
    ),
]


def load_rules_from_directory(directory: Path) -> List[DetectionRule]:
    """Loads all YAML rules from the specified directory."""
    rules: List[DetectionRule] = list(BUILTIN_RULES)

    if not directory.exists() or not directory.is_dir():
        return rules

    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed. Using built-in rule set.")
        return rules

    for rule_file in directory.glob("*.yaml"):
        try:
            content = rule_file.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "id" in data and "detection" in data:
                rule = DetectionRule.from_dict(data)
                # Avoid duplicates with builtins
                if not any(r.id == rule.id for r in rules):
                    rules.append(rule)
        except Exception as e:
            logger.debug(f"Failed to load rule from {rule_file}: {e}")

    for rule_file in directory.glob("*.yml"):
        try:
            content = rule_file.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            if isinstance(data, dict) and "id" in data and "detection" in data:
                rule = DetectionRule.from_dict(data)
                if not any(r.id == rule.id for r in rules):
                    rules.append(rule)
        except Exception as e:
            logger.debug(f"Failed to load rule from {rule_file}: {e}")

    return rules


def apply_rules(event: ForensicEvent, rules: List[DetectionRule]) -> List[DetectionRule]:
    """Evaluates rules against an event and applies any matched MITRE tags and severities."""
    matched: List[DetectionRule] = []
    for rule in rules:
        if rule.matches(event):
            matched.append(rule)
            event.add_mitre(rule.mitre_tactic, f"{rule.mitre_technique_id}: {rule.mitre_technique_name}")
            event.add_ioc(f"RULE:{rule.id}")
            if rule.severity > event.severity:
                event.severity = rule.severity
    return matched
