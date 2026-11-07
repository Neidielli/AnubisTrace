"""Unit tests for TimelineEngine."""

from datetime import datetime, timedelta, timezone
from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.timeline import TimelineEngine


def test_timeline_sorting_and_filtering():
    engine = TimelineEngine()
    base_time = datetime(2026, 11, 7, 10, 0, 0, tzinfo=timezone.utc)

    # Insert events out of order
    e3 = ForensicEvent(
        timestamp=base_time + timedelta(minutes=15),
        source_type=SourceType.EVTX_SECURITY,
        action="Log Cleared",
        event_id="1102",
        severity=Severity.CRITICAL,
        actor="Administrator",
    )
    e1 = ForensicEvent(
        timestamp=base_time,
        source_type=SourceType.EVTX_SECURITY,
        action="Logon Attempt",
        event_id="4625",
        severity=Severity.MEDIUM,
        actor="Attacker",
    )
    e2 = ForensicEvent(
        timestamp=base_time + timedelta(minutes=5),
        source_type=SourceType.EVTX_PROCESS,
        action="Process Spawned",
        event_id="4688",
        severity=Severity.LOW,
        actor="Attacker",
        target="powershell.exe",
    )

    engine.add_events([e3, e1, e2])

    # Assert sorted order: e1, e2, e3
    sorted_events = engine.events
    assert len(sorted_events) == 3
    assert sorted_events[0] == e1
    assert sorted_events[1] == e2
    assert sorted_events[2] == e3

    # Test filtering by min_severity >= HIGH (should only return e3)
    high_events = engine.filter(min_severity=Severity.HIGH)
    assert len(high_events) == 1
    assert high_events[0] == e3

    # Test free text search
    ps_events = engine.search_query = engine.filter(search_query="powershell")
    assert len(ps_events) == 1
    assert ps_events[0] == e2

    # Test statistics
    stats = engine.get_statistics()
    assert stats["total_events"] == 3
    assert stats["severity_counts"]["CRITICAL"] == 1
    assert stats["severity_counts"]["MEDIUM"] == 1
    assert stats["severity_counts"]["LOW"] == 1
