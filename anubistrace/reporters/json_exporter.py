"""
JSONL Stream Exporter for AnubisTrace.
Outputs newline-delimited JSON events for easy ingestion into SIEMs (Splunk, ELK, Wazuh).
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from anubistrace.core.event import ForensicEvent


def export_to_jsonl(events: List[ForensicEvent], output_path: Path) -> Path:
    """Exports events to a newline-delimited JSONL file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(event.to_json() + "\n")

    return output_path
