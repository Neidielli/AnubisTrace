"""
Timeline Engine for AnubisTrace.
Aggregates, sorts, filters, and generates statistical summaries
from multi-source forensic events into a unified Super Timeline.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Dict, Iterator, List, Optional

from anubistrace.core.event import ForensicEvent, Severity, SourceType


class TimelineEngine:
    """
    Manages the chronological collection of ForensicEvents.
    Provides filtering, search, time-windowing, and statistical aggregation.
    """

    def __init__(self) -> None:
        self._events: List[ForensicEvent] = []
        self._is_sorted: bool = True

    def add_event(self, event: ForensicEvent) -> None:
        """Adds a single forensic event to the timeline."""
        self._events.append(event)
        self._is_sorted = False

    def add_events(self, events: List[ForensicEvent]) -> None:
        """Adds a list of forensic events."""
        self._events.extend(events)
        self._is_sorted = False

    def _ensure_sorted(self) -> None:
        """Sorts the events chronologically if dirty."""
        if not self._is_sorted:
            self._events.sort(key=lambda e: e.timestamp)
            self._is_sorted = True

    @property
    def events(self) -> List[ForensicEvent]:
        """Returns all events sorted chronologically."""
        self._ensure_sorted()
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[ForensicEvent]:
        self._ensure_sorted()
        return iter(self._events)

    def filter(
        self,
        min_severity: Optional[Severity] = None,
        source_type: Optional[SourceType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        mitre_tactic: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List[ForensicEvent]:
        """
        Applies multi-criteria filtering over the timeline.
        """
        self._ensure_sorted()
        results: List[ForensicEvent] = []

        query = search_query.lower() if search_query else None
        target_tactic = mitre_tactic.lower() if mitre_tactic else None
        target_tech = mitre_technique.lower() if mitre_technique else None

        for event in self._events:
            # 1. Severity filter
            if min_severity and event.severity < min_severity:
                continue

            # 2. Source filter
            if source_type and event.source_type != source_type:
                continue

            # 3. Time bounds
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue

            # 4. MITRE filters
            if target_tactic and not any(target_tactic in t.lower() for t in event.mitre_tactics):
                continue
            if target_tech and not any(target_tech in tech.lower() for tech in event.mitre_techniques):
                continue

            # 5. Free-text search filter
            if query:
                searchable_text = f"{event.actor} {event.action} {event.target} {event.command_line or ''} {' '.join(event.iocs)}".lower()
                if query not in searchable_text:
                    continue

            results.append(event)

        return results

    def get_statistics(self) -> Dict[str, object]:
        """
        Generates comprehensive metrics for investigative reports and dashboards.
        """
        self._ensure_sorted()

        if not self._events:
            return {
                "total_events": 0,
                "first_event": None,
                "last_event": None,
                "severity_counts": {s.value: 0 for s in Severity},
                "source_counts": {},
                "top_tactics": {},
                "top_techniques": {},
                "top_actors": {},
                "total_iocs": 0,
                "unique_iocs": [],
            }

        severity_counts = Counter(e.severity.value for e in self._events)
        source_counts = Counter(e.source_type.value for e in self._events)
        actor_counts = Counter(e.actor for e in self._events if e.actor)

        # Count tactics and techniques
        tactics_counter: Counter[str] = Counter()
        techniques_counter: Counter[str] = Counter()
        all_iocs: List[str] = []

        for e in self._events:
            for tactic in e.mitre_tactics:
                tactics_counter[tactic] += 1
            for tech in e.mitre_techniques:
                techniques_counter[tech] += 1
            all_iocs.extend(e.iocs)

        unique_iocs = sorted(set(all_iocs))

        return {
            "total_events": len(self._events),
            "first_event": self._events[0].timestamp_iso,
            "last_event": self._events[-1].timestamp_iso,
            "severity_counts": {s.value: severity_counts.get(s.value, 0) for s in Severity},
            "source_counts": dict(source_counts.most_common()),
            "top_tactics": dict(tactics_counter.most_common(10)),
            "top_techniques": dict(techniques_counter.most_common(10)),
            "top_actors": dict(actor_counts.most_common(5)),
            "total_iocs": len(all_iocs),
            "unique_iocs": unique_iocs,
        }
