"""
CSV Super Timeline Exporter for AnubisTrace.
Generates CSV files fully compatible with Eric Zimmerman's Timeline Explorer.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import List

from anubistrace.core.event import ForensicEvent


def export_to_csv(events: List[ForensicEvent], output_path: Path) -> Path:
    """Exports events to a Super Timeline CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "Timestamp (UTC)",
        "Severity",
        "Source",
        "Event ID",
        "Actor",
        "Action",
        "Target",
        "Command Line",
        "Parent Process",
        "MITRE Tactics",
        "MITRE Techniques",
        "IoCs",
        "Source File",
    ]

    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            writer.writerow(event.to_timeline_row())

    return output_path
