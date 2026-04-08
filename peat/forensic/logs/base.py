"""
Base classes for ICS/SCADA log parsers.

Provides the LogParser abstract base and ParsedLogEntry data class
that all vendor-specific parsers build upon. Handles common operations
like timestamp normalization and ECS field mapping.

@decision: Uses a flat ParsedLogEntry dataclass rather than PEAT's
Event pydantic model directly. This keeps the forensic parsers
decoupled from the data model — the normalization layer converts
ParsedLogEntry → Event as a separate step. This allows the forensic
module to be used standalone for log analysis without requiring
full PEAT initialization.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from peat import log


@dataclass
class ParsedLogEntry:
    """
    A normalized log entry from any ICS/SCADA source.

    Fields follow the Elastic Common Schema (ECS) naming conventions
    where applicable.
    """

    # Core ECS fields
    timestamp: datetime | None = None  # event.created
    message: str = ""  # event.message
    original: str = ""  # event.original (raw line)

    # Source identification
    source_type: str = ""  # e.g. "sel_ser", "siprotec_csv"
    source_file: str = ""  # Original filename

    # Event classification (ECS)
    action: str = ""  # event.action (e.g. "relay_trip", "config_change")
    category: str = ""  # event.category (e.g. "configuration", "process")
    severity: str = ""  # event.severity (e.g. "info", "warning", "critical")
    outcome: str = ""  # event.outcome (e.g. "success", "failure")

    # Device identification
    device_id: str = ""  # Relay ID, PLC name, etc.
    device_vendor: str = ""  # e.g. "SEL", "Siemens", "GE"
    device_model: str = ""  # e.g. "SEL-751", "SIPROTEC 5"

    # Network context (if applicable)
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0

    # Additional structured data
    extra: dict[str, Any] = field(default_factory=dict)

    def to_ecs_dict(self) -> dict[str, Any]:
        """Convert to ECS-compliant dictionary for Elasticsearch output."""
        result: dict[str, Any] = {
            "event": {
                "created": self.timestamp.isoformat() if self.timestamp else None,
                "message": self.message,
                "original": self.original,
                "action": self.action,
                "category": self.category,
                "severity": self.severity,
                "outcome": self.outcome,
                "module": "peat_forensic",
                "dataset": self.source_type,
            },
            "observer": {
                "vendor": self.device_vendor,
                "product": self.device_model,
                "name": self.device_id,
            },
        }

        if self.source_ip:
            result["source"] = {"ip": self.source_ip}
            if self.source_port:
                result["source"]["port"] = self.source_port
        if self.destination_ip:
            result["destination"] = {"ip": self.destination_ip}
            if self.destination_port:
                result["destination"]["port"] = self.destination_port

        # Hash the original line for integrity
        if self.original:
            result["event"]["hash"] = hashlib.sha256(
                self.original.encode("utf-8", errors="replace")
            ).hexdigest()

        if self.extra:
            result["extra"] = self.extra

        # Remove empty values
        result["event"] = {k: v for k, v in result["event"].items() if v}
        result["observer"] = {k: v for k, v in result["observer"].items() if v}

        return result


class LogParser(ABC):
    """
    Abstract base class for ICS/SCADA log parsers.

    Subclasses implement detect() and parse() for a specific vendor format.
    """

    name: str = "unknown"
    vendor: str = "unknown"
    description: str = ""
    file_patterns: list[str] = []  # Glob patterns this parser handles

    @classmethod
    @abstractmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        """
        Determine if this parser can handle the given file.

        Args:
            path: Path to the log file.
            sample: First ~4KB of the file content for sniffing.

        Returns:
            True if this parser can handle the file.
        """
        ...

    @classmethod
    @abstractmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        """
        Parse a log file and return normalized entries.

        Args:
            path: Path to the log file.

        Returns:
            List of ParsedLogEntry instances.
        """
        ...

    @classmethod
    def _read_text(cls, path: Path) -> str:
        """Read a text file with fallback encoding."""
        for encoding in ("utf-8", "latin-1", "cp1252"):
            try:
                return path.read_text(encoding=encoding)
            except UnicodeDecodeError:
                continue
        return path.read_text(encoding="utf-8", errors="replace")

    @classmethod
    def _read_csv(cls, path: Path) -> list[dict[str, str]]:
        """Read a CSV file and return list of row dicts."""
        text = cls._read_text(path)
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)

    @classmethod
    def _parse_timestamp(cls, ts_str: str, formats: list[str] | None = None) -> datetime | None:
        """
        Parse a timestamp string trying multiple formats.

        Args:
            ts_str: Timestamp string to parse.
            formats: List of strptime format strings to try.

        Returns:
            Parsed datetime or None if no format matched.
        """
        if not ts_str or not ts_str.strip():
            return None

        ts_str = ts_str.strip()

        default_formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%m/%d/%Y %H:%M:%S.%f",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
            "%d-%b-%Y %H:%M:%S",
        ]

        for fmt in (formats or default_formats):
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue

        return None
