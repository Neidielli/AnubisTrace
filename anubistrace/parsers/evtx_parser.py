"""
Windows Event Log (.evtx) Parser for AnubisTrace.
Extracts security-critical event records and normalizes them into ForensicEvents.
Supports binary .evtx files and exported XML/JSON event streams.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.mitre import MitreEngine
from anubistrace.parsers.base import BaseParser

logger = logging.getLogger(__name__)

# XML Namespaces used in Windows Event Logs
EVTX_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}


class EvtxParser(BaseParser):
    """
    Parses Windows Event Logs (.evtx and .xml exports).
    Specialized in security auditing:
      - 4688: Process Creation (CommandLine, ParentProcess)
      - 4624 / 4625: Logon Success / Failure
      - 1102 / 104: Security / System Log Clearing
      - 7045 / 4697: Service Installations (Persistence)
      - 4720 / 4728: Account creation and group tampering
      - 4104: PowerShell Script Block Execution
    """

    @property
    def name(self) -> str:
        return "Windows Event Log Parser"

    @property
    def supported_extensions(self) -> List[str]:
        return [".evtx", ".xml"]

    def parse(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses an EVTX binary file or XML event export."""
        suffix = filepath.suffix.lower()

        if suffix == ".xml":
            yield from self._parse_xml_file(filepath)
        elif suffix == ".evtx":
            yield from self._parse_binary_evtx(filepath)

    def _parse_binary_evtx(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Attempts to parse binary .evtx using python-evtx library if installed."""
        try:
            import Evtx.Evtx as evtx
        except ImportError:
            logger.warning(
                "python-evtx library not installed. To parse binary .evtx directly, install it via: pip install python-evtx"
            )
            return

        try:
            with evtx.Evtx(str(filepath)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        event = self._parse_event_xml_string(xml_str, str(filepath))
                        if event:
                            yield MitreEngine.enrich(event)
                    except Exception as err:
                        logger.debug(f"Skipping corrupted EVTX record in {filepath}: {err}")
                        continue
        except Exception as e:
            logger.error(f"Failed to read binary EVTX {filepath}: {e}")

    def _parse_xml_file(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses an XML file containing one or more <Event> nodes."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            # If the file contains multiple events without a root tag, wrap them
            if not content.strip().startswith("<Events>"):
                content = f"<Events>{content}</Events>"

            root = ET.fromstring(content)
            for event_elem in root.findall(".//ns:Event", EVTX_NS) or root.findall(".//Event"):
                event = self._parse_event_element(event_elem, str(filepath))
                if event:
                    yield MitreEngine.enrich(event)
        except Exception as e:
            logger.error(f"Error parsing XML event log {filepath}: {e}")

    def _parse_event_xml_string(self, xml_str: str, source_file: str) -> Optional[ForensicEvent]:
        """Parses a single XML event string into a ForensicEvent."""
        try:
            elem = ET.fromstring(xml_str)
            return self._parse_event_element(elem, source_file)
        except Exception:
            return None

    def _parse_event_element(self, elem: ET.Element, source_file: str) -> Optional[ForensicEvent]:
        """Converts an XML Event element into a normalized ForensicEvent."""
        # 1. System Headers
        system = elem.find("ns:System", EVTX_NS)
        if system is None:
            system = elem.find("System")
        if system is None:
            return None

        event_id_elem = system.find("ns:EventID", EVTX_NS) or system.find("EventID")
        event_id = event_id_elem.text.strip() if (event_id_elem is not None and event_id_elem.text) else "0"

        time_elem = system.find("ns:TimeCreated", EVTX_NS) or system.find("TimeCreated")
        time_str = time_elem.get("SystemTime") if time_elem is not None else None

        if time_str:
            try:
                # Handle ISO 8601 UTC timestamp
                timestamp = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        channel_elem = system.find("ns:Channel", EVTX_NS) or system.find("Channel")
        channel = channel_elem.text.strip() if (channel_elem is not None and channel_elem.text) else "Security"

        # Determine source type
        source_type = SourceType.EVTX_SECURITY
        if "System" in channel:
            source_type = SourceType.EVTX_SYSTEM
        elif "PowerShell" in channel:
            source_type = SourceType.EVTX_POWERSHELL

        # 2. Extract EventData attributes
        data_map = self._extract_event_data(elem)

        # 3. Contextual normalization based on Event ID
        action = f"Windows Event {event_id}"
        actor = "SYSTEM"
        target = ""
        cmd_line: Optional[str] = None
        parent_proc: Optional[str] = None
        severity = Severity.INFO

        if event_id == "4688":
            # Process Creation
            action = "Process Creation"
            actor = data_map.get("SubjectUserName") or data_map.get("TargetUserName") or "SYSTEM"
            target = data_map.get("NewProcessName", "")
            cmd_line = data_map.get("CommandLine")
            parent_proc = data_map.get("ParentProcessName")
            severity = Severity.LOW

        elif event_id == "4624":
            # Successful Logon
            action = "Successful Logon"
            actor = data_map.get("TargetUserName") or data_map.get("SubjectUserName") or "UNKNOWN"
            ip = data_map.get("IpAddress", "-")
            logon_type = data_map.get("LogonType", "-")
            target = f"Host (Type {logon_type}, Source IP: {ip})"
            severity = Severity.INFO

        elif event_id == "4625":
            # Failed Logon
            action = "Logon Failure"
            actor = data_map.get("TargetUserName") or "UNKNOWN"
            ip = data_map.get("IpAddress", "-")
            target = f"Host (Source IP: {ip})"
            severity = Severity.MEDIUM

        elif event_id in ("1102", "104"):
            # Audit / System Log Cleared
            action = "Audit Log Cleared"
            actor = data_map.get("SubjectUserName") or "Administrator"
            target = "EventLog Subsystem"
            severity = Severity.CRITICAL

        elif event_id in ("7045", "4697"):
            # New Service Installed
            action = "Service Installed"
            actor = data_map.get("SubjectUserName") or "SYSTEM"
            target = data_map.get("ServiceName", "")
            cmd_line = data_map.get("ImagePath")
            severity = Severity.HIGH

        elif event_id == "4720":
            # User Created
            action = "User Account Created"
            actor = data_map.get("SubjectUserName") or "Administrator"
            target = data_map.get("TargetUserName", "")
            severity = Severity.HIGH

        elif event_id == "4104":
            # PowerShell Script Block
            action = "PowerShell Script Block"
            actor = data_map.get("UserId") or "User"
            target = "PowerShell Engine"
            cmd_line = data_map.get("ScriptBlockText")
            severity = Severity.LOW

        return ForensicEvent(
            timestamp=timestamp,
            source_type=source_type,
            source_file=source_file,
            event_id=event_id,
            severity=severity,
            actor=actor,
            action=action,
            target=target,
            command_line=cmd_line,
            parent_process=parent_proc,
            details=data_map,
        )

    def _extract_event_data(self, elem: ET.Element) -> Dict[str, str]:
        """Extracts key-value pairs from EventData or UserData XML."""
        data_map: Dict[str, str] = {}
        event_data = elem.find("ns:EventData", EVTX_NS) or elem.find("EventData")

        if event_data is not None:
            for item in event_data.findall("ns:Data", EVTX_NS) or event_data.findall("Data"):
                name = item.get("Name")
                text = item.text or ""
                if name:
                    data_map[name] = text.strip()
                elif text:
                    # Anonymous data field
                    data_map[f"Field_{len(data_map)}"] = text.strip()

        return data_map
