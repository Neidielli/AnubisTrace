"""Unit tests for Detection Rules and Temporal Correlation Engine."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.engine.correlation import TemporalCorrelationEngine
from anubistrace.engine.rule_model import DetectionRule
from anubistrace.engine.rules_loader import apply_rules, load_rules_from_directory

RULES_DIR = Path(__file__).parent.parent / "rules"


def test_yaml_rules_loading():
    rules = load_rules_from_directory(RULES_DIR)
    assert len(rules) >= 4

    rule_ids = [r.id for r in rules]
    assert "anubis-rule-001" in rule_ids or "BUILTIN-001" in rule_ids


def test_rule_matching_and_enrichment():
    rule = DetectionRule(
        id="TEST-001",
        title="Test Shadow Wipe Rule",
        description="Detects shadow copy deletion",
        severity=Severity.CRITICAL,
        mitre_tactic="Impact",
        mitre_technique_id="T1490",
        mitre_technique_name="Inhibit System Recovery",
        selection={"command_line_contains": ["delete shadows"]},
    )

    event = ForensicEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.EVTX_PROCESS,
        action="Process Spawned",
        command_line="vssadmin.exe delete shadows /all /quiet",
    )

    assert rule.matches(event)
    matched = apply_rules(event, [rule])
    assert len(matched) == 1
    assert event.severity == Severity.CRITICAL
    assert any("T1490" in tech for tech in event.mitre_techniques)


def test_temporal_bruteforce_correlation():
    base_time = datetime(2026, 11, 7, 3, 0, 0, tzinfo=timezone.utc)
    engine = TemporalCorrelationEngine(time_window_minutes=15)

    events = [
        ForensicEvent(
            timestamp=base_time,
            source_type=SourceType.EVTX_SECURITY,
            action="Logon Failure",
            event_id="4625",
            actor="Administrator",
            details={"IpAddress": "192.168.1.180"},
        ),
        ForensicEvent(
            timestamp=base_time + timedelta(seconds=30),
            source_type=SourceType.EVTX_SECURITY,
            action="Logon Failure",
            event_id="4625",
            actor="Administrator",
            details={"IpAddress": "192.168.1.180"},
        ),
        ForensicEvent(
            timestamp=base_time + timedelta(minutes=2),
            source_type=SourceType.EVTX_SECURITY,
            action="Successful Logon",
            event_id="4624",
            actor="Administrator",
            details={"IpAddress": "192.168.1.180", "LogonType": "10"},
        ),
    ]

    findings = engine.correlate(events)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "Brute-Force" in finding.title
    assert len(finding.contributing_events) == 3

    # Verify synthetic event creation
    synth_event = finding.to_forensic_event()
    assert synth_event.severity == Severity.CRITICAL
    assert "CORRELATED_ATTACK_CHAIN" in synth_event.event_id


def test_temporal_antiforensics_correlation():
    base_time = datetime(2026, 11, 7, 3, 10, 0, tzinfo=timezone.utc)
    engine = TemporalCorrelationEngine(time_window_minutes=30)

    events = [
        ForensicEvent(
            timestamp=base_time,
            source_type=SourceType.EVTX_PROCESS,
            action="Malicious Command",
            event_id="4688",
            severity=Severity.HIGH,
            actor="attacker",
            command_line="powershell.exe -enc AAAA...",
        ),
        ForensicEvent(
            timestamp=base_time + timedelta(minutes=5),
            source_type=SourceType.EVTX_SECURITY,
            action="Audit Log Cleared",
            event_id="1102",
            severity=Severity.CRITICAL,
            actor="attacker",
        ),
    ]

    findings = engine.correlate(events)
    assert len(findings) >= 1
    assert any("Anti-Forensics" in f.title for f in findings)
