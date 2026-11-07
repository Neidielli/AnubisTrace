"""
Windows Prefetch (.pf) Parser for AnubisTrace.
Extracts execution proof, execution count, and historical timestamps
from Windows Prefetch files (XP, Win7, Win8, Win10/11).
"""

from __future__ import annotations

import ctypes
import logging
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from anubistrace.core.event import ForensicEvent, Severity, SourceType
from anubistrace.core.mitre import MitreEngine
from anubistrace.parsers.base import BaseParser

logger = logging.getLogger(__name__)

# Difference between Windows FILETIME (1601-01-01) and Unix Epoch (1970-01-01) in 100ns units
WINDOWS_TICK = 10000000
SEC_TO_UNIX_EPOCH = 11644473600


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Converts a 64-bit Windows FILETIME into a UTC datetime."""
    if filetime <= 0:
        return None
    try:
        epoch_seconds = (filetime / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH
        if epoch_seconds < 0:
            return None
        return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def decompress_mam(raw_data: bytes) -> Optional[bytes]:
    """
    Decompresses Windows 10/11 MAM-compressed prefetch data
    using ntdll.dll RtlDecompressBufferEx if running on Windows.
    """
    if len(raw_data) < 8 or raw_data[:3] != b"MAM":
        return raw_data

    # Windows Native Decompression via ntdll
    try:
        uncompressed_size = struct.unpack("<I", raw_data[4:8])[0]
        ntdll = ctypes.windll.ntdll
        # COMPRESSION_FORMAT_XPRESS_HUFF = 4
        decompressed = ctypes.create_string_buffer(uncompressed_size)
        final_uncompressed_size = ctypes.c_ulong(0)

        status = ntdll.RtlDecompressBuffer(
            ctypes.c_ushort(4),
            decompressed,
            ctypes.c_ulong(uncompressed_size),
            raw_data[8:],
            ctypes.c_ulong(len(raw_data) - 8),
            ctypes.byref(final_uncompressed_size),
        )

        if status == 0:  # STATUS_SUCCESS
            return bytes(decompressed.raw[: final_uncompressed_size.value])
    except Exception as e:
        logger.debug(f"Native MAM decompression unavailable: {e}")

    return None


class PrefetchParser(BaseParser):
    """
    Parses Windows Prefetch (.pf) files to prove application execution history.
    Extracts run count, primary executable name, and up to 8 historical execution timestamps.
    """

    @property
    def name(self) -> str:
        return "Windows Prefetch Parser"

    @property
    def supported_extensions(self) -> List[str]:
        return [".pf"]

    def parse(self, filepath: Path) -> Iterator[ForensicEvent]:
        """Parses a .pf file and yields execution events."""
        try:
            raw_bytes = filepath.read_bytes()
        except Exception as e:
            logger.error(f"Failed to read prefetch file {filepath}: {e}")
            return

        # Decompress if MAM compressed
        if raw_bytes.startswith(b"MAM"):
            decompressed = decompress_mam(raw_bytes)
            if not decompressed:
                logger.debug(f"Unable to decompress MAM-compressed prefetch: {filepath}")
                return
            data = decompressed
        else:
            data = raw_data = raw_bytes

        if len(data) < 84:
            return

        # Check SCCA signature
        magic = data[4:8]
        if magic != b"SCCA":
            return

        version = struct.unpack("<I", data[0:4])[0]
        # Extract executable name (offset 0x10, 60 bytes / 30 UTF-16LE characters)
        raw_name = data[0x10:0x4C]
        try:
            exe_name = raw_name.decode("utf-16le", errors="ignore").split("\x00")[0].strip()
        except Exception:
            exe_name = filepath.stem

        run_count, timestamps = self._extract_timestamps_and_count(version, data)

        if not timestamps:
            # Fallback to file modification time if prefetch timestamps could not be extracted
            timestamps = [datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc)]

        # Emit an event for each verified execution timestamp (sorted oldest to newest)
        for idx, ts in enumerate(sorted(timestamps)):
            is_latest = (idx == len(timestamps) - 1)
            event = ForensicEvent(
                timestamp=ts,
                source_type=SourceType.PREFETCH,
                source_file=str(filepath),
                event_id="PREFETCH_EXEC",
                severity=Severity.LOW,
                actor="USER/SYSTEM",
                action="Binary Execution (Prefetch)",
                target=exe_name,
                command_line=None,
                details={
                    "RunCount": run_count,
                    "PrefetchVersion": version,
                    "ExecutionInstance": f"{idx + 1} of {len(timestamps)}",
                    "IsMostRecent": is_latest,
                },
            )
            yield MitreEngine.enrich(event)

    def _extract_timestamps_and_count(
        self, version: int, data: bytes
    ) -> Tuple[int, List[datetime]]:
        """Extracts run count and timestamp array based on Windows Prefetch version."""
        run_count = 0
        timestamps: List[datetime] = []

        try:
            if version == 17:  # Windows XP
                if len(data) >= 0x9C:
                    run_count = struct.unpack("<I", data[0x90:0x94])[0]
                    ft = struct.unpack("<Q", data[0x78:0x80])[0]
                    dt = filetime_to_datetime(ft)
                    if dt:
                        timestamps.append(dt)

            elif version == 23:  # Windows 7
                if len(data) >= 0x9C:
                    run_count = struct.unpack("<I", data[0x98:0x9C])[0]
                    ft = struct.unpack("<Q", data[0x80:0x88])[0]
                    dt = filetime_to_datetime(ft)
                    if dt:
                        timestamps.append(dt)

            elif version in (26, 30):  # Windows 8 (26) & Windows 10/11 (30)
                if len(data) >= 0xD4:
                    run_count = struct.unpack("<I", data[0xD0:0xD4])[0]
                    # Up to 8 timestamps stored sequentially at offset 0x80
                    for i in range(8):
                        offset = 0x80 + (i * 8)
                        if len(data) >= offset + 8:
                            ft = struct.unpack("<Q", data[offset : offset + 8])[0]
                            dt = filetime_to_datetime(ft)
                            if dt:
                                timestamps.append(dt)
        except Exception as e:
            logger.debug(f"Error parsing prefetch version {version} headers: {e}")

        return run_count, timestamps
