"""Parsers package for AnubisTrace."""

from typing import List

from anubistrace.parsers.base import BaseParser
from anubistrace.parsers.evtx_parser import EvtxParser
from anubistrace.parsers.prefetch_parser import PrefetchParser
from anubistrace.parsers.linux_parser import LinuxParser

__all__ = [
    "BaseParser",
    "EvtxParser",
    "PrefetchParser",
    "LinuxParser",
    "get_all_parsers",
]


def get_all_parsers() -> List[BaseParser]:
    """Returns a list of all instantiated default parsers."""
    return [
        EvtxParser(),
        PrefetchParser(),
        LinuxParser(),
    ]
