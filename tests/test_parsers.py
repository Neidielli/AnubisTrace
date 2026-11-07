"""Unit tests for AnubisTrace artifact parsers (EVTX and Linux)."""

from pathlib import Path

from anubistrace.core.event import Severity, SourceType
from anubistrace.parsers.evtx_parser import EvtxParser
from anubistrace.parsers.linux_parser import LinuxParser

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def test_evtx_xml_parser():
    evtx_file = SAMPLES_DIR / "sample_security.xml"
    assert evtx_file.exists(), "Sample security XML file not found"

    parser = EvtxParser()
    events = list(parser.parse(evtx_file))

    # Expect 6 events from sample_security.xml
    assert len(events) == 6

    # Event 1: 4625 Failed Logon
    e1 = events[0]
    assert e1.event_id == "4625"
    assert e1.severity == Severity.MEDIUM
    assert any("T1110" in tech for tech in e1.mitre_techniques)

    # Event 2: 4624 Successful Logon (Logon Type 10 - RDP)
    e2 = events[1]
    assert e2.event_id == "4624"
    assert any("T1021.001" in tech for tech in e2.mitre_techniques)
    assert any("LOGON:RDP_REMOTE" in ioc for ioc in e2.iocs)

    # Event 3: 4688 Process Creation (Encoded PowerShell)
    e3 = events[2]
    assert e3.event_id == "4688"
    assert e3.severity >= Severity.HIGH
    assert any("T1027" in tech for tech in e3.mitre_techniques)

    # Event 4: 4688 Process Creation (vssadmin delete shadows)
    e4 = events[3]
    assert e4.severity == Severity.CRITICAL
    assert any("T1490" in tech for tech in e4.mitre_techniques)
    assert any("LOLBIN:VSSADMIN.EXE" in ioc for ioc in e4.iocs)

    # Event 5: 1102 Audit Log Cleared
    e5 = events[4]
    assert e5.event_id == "1102"
    assert e5.severity == Severity.CRITICAL
    assert any("T1070.001" in tech for tech in e5.mitre_techniques)

    # Event 6: 7045 Service Installed
    e6 = events[5]
    assert e6.event_id == "7045"
    assert e6.severity == Severity.HIGH
    assert e6.target == "AnubisPersistSvc"
    assert any("T1543.003" in tech for tech in e6.mitre_techniques)


def test_linux_auth_parser():
    auth_file = SAMPLES_DIR / "auth.log"
    assert auth_file.exists(), "Sample auth.log not found"

    parser = LinuxParser()
    events = list(parser.parse(auth_file))

    assert len(events) == 6

    # Failed SSH attempts
    failed_attempts = [e for e in events if e.event_id == "LINUX_SSH_FAIL"]
    assert len(failed_attempts) == 3
    for f in failed_attempts:
        assert f.severity == Severity.MEDIUM
        assert any("T1110" in tech for tech in f.mitre_techniques)

    # Sudo execution
    sudo_event = next(e for e in events if e.event_id == "LINUX_SUDO_EXEC")
    assert sudo_event.actor == "neidi"
    assert sudo_event.target == "root"
    assert sudo_event.command_line == "/bin/bash"
    assert sudo_event.severity == Severity.HIGH
    assert any("T1548.003" in tech for tech in sudo_event.mitre_techniques)

    # User creation
    useradd_event = next(e for e in events if e.event_id == "LINUX_USERADD")
    assert useradd_event.target == "ghost_admin"
    assert useradd_event.severity == Severity.HIGH
    assert any("T1136.001" in tech for tech in useradd_event.mitre_techniques)


def test_linux_bash_history_parser():
    history_file = SAMPLES_DIR / "bash_history"
    assert history_file.exists(), "Sample bash_history not found"

    parser = LinuxParser()
    events = list(parser.parse(history_file))

    assert len(events) >= 4
    # The curl download cradle command should be enriched
    c2_event = next(e for e in events if "curl" in (e.command_line or ""))
    assert c2_event.severity >= Severity.HIGH
    assert any("T1105" in tech for tech in c2_event.mitre_techniques)
