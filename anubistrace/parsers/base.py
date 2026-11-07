"""
Base Parser Interface for AnubisTrace.
All artifact parsers (EVTX, Prefetch, Registry, Linux) inherit from BaseParser.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, List

from anubistrace.core.event import ForensicEvent


class BaseParser(ABC):
    """Abstract base class for all forensic artifact parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the parser."""
        pass

    @property
    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """List of supported file extensions (e.g. ['.evtx', '.pf'])."""
        pass

    def can_parse(self, filepath: Path) -> bool:
        """Determines if this parser can handle the specified file."""
        if not filepath.exists() or not filepath.is_file():
            return False
        return filepath.suffix.lower() in [ext.lower() for ext in self.supported_extensions]

    @abstractmethod
    def parse(self, filepath: Path) -> Iterator[ForensicEvent]:
        """
        Parses a forensic artifact file and yields standardized ForensicEvent instances.
        Must handle errors gracefully and skip corrupted records without crashing.
        """
        pass
