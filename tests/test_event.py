"""Unit tests for ForensicEvent and Severity."""

from datetime import datetime, timezone
from anubistrace.core.event import ForensicEvent, Severity, SourceType


def test_severity_ordering():
    assert Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.HIGH
    assert Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.INFO <= Severity.INFO


def test_forensic_event_creation():
    now = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)
    event = ForensicEvent(
        timestamp=now,
        source_type=SourceType.EVTX_SECURITY,
        action="Logon Failed",
        event_id="4625",
        severity=Severity.MEDIUM,
        actor="CORP\\Attacker",
        target="WORKSTATION-01",
    )

    assert event.timestamp_iso == "2026-11-07T10:00:00+00:00"
    assert event.source_type == SourceType.EVTX_SECURITY
    assert event.severity == Severity.MEDIUM
    assert event.actor == "CORP\\Attacker"

    # Test MITRE addition
    event.add_mitre("Credential Access", "T1110: Brute Force")
    assert len(event.mitre_tactics) == 1
    assert len(event.mitre_techniques) == 1

    # Ensure idempotency (no duplicate MITRE tags)
    event.add_mitre("Credential Access", "T1110: Brute Force")
    assert len(event.mitre_tactics) == 1

    # Test serialization
    data = event.to_dict()
    assert data["severity"] == "MEDIUM"
    assert data["source_type"] == "EVTX_SECURITY"

    # Test deserialization
    recreated = ForensicEvent.from_dict(data)
    assert recreated.actor == event.actor
    assert recreated.timestamp == event.timestamp
    assert recreated.severity == event.severity
