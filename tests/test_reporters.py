"""Unit tests for AnubisTrace reporting modules (CSV, JSONL, HTML)."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.timeline import TimelineEngine
from anubistrace.engine.correlation import CorrelatedFinding
from anubistrace.reporters.csv_exporter import export_to_csv
from anubistrace.reporters.html_reporter import generate_html_report
from anubistrace.reporters.json_exporter import export_to_jsonl


def test_reporters_full_cycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_dir = Path(tmpdir)

        now = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)
        event = ForensicEvent(
            timestamp=now,
            source_type=SourceType.EVTX_SECURITY,
            action="Logon Failure",
            event_id="4625",
            severity=Severity.HIGH,
            actor="Attacker",
            target="HOST-01",
            command_line=None,
        )
        event.add_mitre("Credential Access", "T1110: Brute Force")

        timeline = TimelineEngine()
        timeline.add_event(event)

        stats = timeline.get_statistics()
        finding = CorrelatedFinding(
            title="Test Attack Sequence",
            description="Correlation of test events",
            severity=Severity.CRITICAL,
            mitre_tactics=["Credential Access"],
            mitre_techniques=["T1110: Brute Force"],
            contributing_events=[event],
        )

        # 1. Test CSV export
        csv_file = out_dir / "timeline.csv"
        export_to_csv([event], csv_file)
        assert csv_file.exists()
        csv_content = csv_file.read_text(encoding="utf-8-sig")
        assert "Timestamp (UTC)" in csv_content
        assert "4625" in csv_content
        assert "Attacker" in csv_content

        # 2. Test JSONL export
        jsonl_file = out_dir / "timeline.jsonl"
        export_to_jsonl([event], jsonl_file)
        assert jsonl_file.exists()
        jsonl_content = jsonl_file.read_text(encoding="utf-8")
        assert "EVTX_SECURITY" in jsonl_content
        assert "4625" in jsonl_content

        # 3. Test HTML Report Generation
        html_file = out_dir / "report.html"
        generate_html_report([event], stats, [finding], html_file)
        assert html_file.exists()
        html_content = html_file.read_text(encoding="utf-8")
        assert "AnubisTrace Forensic Triage Dashboard" in html_content
        assert "Test Attack Sequence" in html_content
        assert "T1110: Brute Force" in html_content
        assert "HOST-01" in html_content
