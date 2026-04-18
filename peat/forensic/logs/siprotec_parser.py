"""
Siemens SIPROTEC relay diagnostic log parser.

Parses CSV/text diagnostic exports from DIGSI 5 for SIPROTEC 5 relays.
These contain device diagnosis events, fault records, and security audit entries.

CSV format example:
    Timestamp,Event ID,Description,Severity
    2026-03-15 14:23:45,1001,Config download started,Info
    2026-03-15 14:24:12,1002,Config download complete,Info

@decision: Focuses on CSV exports rather than binary SIPROTEC formats.
Binary diagnostic logs require proprietary Siemens decoders. CSV exports
from DIGSI 5 cover the majority of forensic use cases and are parseable
with standard Python CSV tools.
"""
# Copyright 2026 John Jarocki
# Developed with AI assistance from Claude Opus 4.6 (Anthropic)
#
# This file is part of PEAT and is licensed under GPL-3.0.
# See LICENSE for details.


from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from pathlib import Path

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# Column name patterns for auto-detection
_TIMESTAMP_COLS = {"timestamp", "time", "date", "datetime", "date/time", "event time"}
_EVENT_COLS = {"event", "event id", "eventid", "id", "event_id", "code"}
_DESC_COLS = {"description", "desc", "message", "text", "event text", "information"}
_SEVERITY_COLS = {"severity", "level", "priority", "class", "category"}


class SiprotecLogParser(LogParser):
    """Parser for Siemens SIPROTEC CSV diagnostic exports."""

    name = "siprotec_csv"
    vendor = "Siemens"
    description = "Siemens SIPROTEC relay diagnostic CSV parser"
    file_patterns = ["*SIPROTEC*.csv", "*siprotec*.csv", "*DIGSI*.csv", "*digsi*.csv"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        lower = sample.lower()

        # Check for SIPROTEC/DIGSI indicators
        if "siprotec" in lower or "digsi" in lower:
            return True

        # Check for CSV with expected column names
        first_line = sample.split("\n", 1)[0].lower()
        siprotec_indicators = {"event id", "fault record", "device diagnosis", "siemens"}
        return any(indicator in first_line for indicator in siprotec_indicators)

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        # Auto-detect column mappings
        headers = {k.lower().strip(): k for k in rows[0].keys()}
        ts_col = _find_column(headers, _TIMESTAMP_COLS)
        event_col = _find_column(headers, _EVENT_COLS)
        desc_col = _find_column(headers, _DESC_COLS)
        sev_col = _find_column(headers, _SEVERITY_COLS)

        entries: list[ParsedLogEntry] = []
        for row in rows:
            ts_str = row.get(ts_col, "") if ts_col else ""
            timestamp = cls._parse_timestamp(ts_str)

            event_id = row.get(event_col, "") if event_col else ""
            description = row.get(desc_col, "") if desc_col else ""
            severity_raw = row.get(sev_col, "") if sev_col else ""

            severity = _normalize_severity(severity_raw)
            category = _classify_siprotec_event(description, event_id)

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=description or event_id,
                original=str(row),
                source_type="siprotec_csv",
                source_file=path.name,
                action=event_id,
                category=category,
                severity=severity,
                device_vendor="Siemens",
                device_model="SIPROTEC",
                extra={k: v for k, v in row.items() if v},
            ))

        log.info(f"Parsed {len(entries)} events from SIPROTEC log: {path.name}")
        return entries


class GenericCSVLogParser(LogParser):
    """
    Generic CSV log parser for ICS devices.

    Handles any CSV file with timestamp and event/description columns.
    Acts as a fallback when no vendor-specific parser matches.
    """

    name = "generic_csv"
    vendor = "unknown"
    description = "Generic CSV log parser for ICS/SCADA devices"
    file_patterns = ["*.csv"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        # Must look like CSV with a header row containing time-related column
        first_line = sample.split("\n", 1)[0].lower()
        return any(ts in first_line for ts in _TIMESTAMP_COLS) and "," in first_line

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        headers = {k.lower().strip(): k for k in rows[0].keys()}
        ts_col = _find_column(headers, _TIMESTAMP_COLS)
        desc_col = _find_column(headers, _DESC_COLS)
        sev_col = _find_column(headers, _SEVERITY_COLS)

        entries: list[ParsedLogEntry] = []
        for row in rows:
            ts_str = row.get(ts_col, "") if ts_col else ""
            timestamp = cls._parse_timestamp(ts_str)
            description = row.get(desc_col, "") if desc_col else str(row)

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=description,
                original=str(row),
                source_type="generic_csv",
                source_file=path.name,
                severity=_normalize_severity(row.get(sev_col, "")) if sev_col else "info",
                extra={k: v for k, v in row.items() if v},
            ))

        log.info(f"Parsed {len(entries)} entries from CSV: {path.name}")
        return entries


def _find_column(headers: dict[str, str], candidates: set[str]) -> str | None:
    """Find the first matching column name from a set of candidates."""
    for candidate in candidates:
        if candidate in headers:
            return headers[candidate]
    return None


def _normalize_severity(raw: str) -> str:
    """Normalize severity string to standard levels."""
    lower = raw.lower().strip()
    if lower in ("critical", "crit", "fatal", "emergency"):
        return "critical"
    if lower in ("error", "err", "high"):
        return "error"
    if lower in ("warning", "warn", "medium"):
        return "warning"
    if lower in ("info", "information", "notice", "low"):
        return "info"
    if lower in ("debug", "trace", "verbose"):
        return "debug"
    return "info"


def _classify_siprotec_event(description: str, event_id: str) -> str:
    """Classify a SIPROTEC event into an ECS category."""
    lower = (description + " " + event_id).lower()
    if any(kw in lower for kw in ("fault", "trip", "protection", "overcurrent")):
        return "process"
    if any(kw in lower for kw in ("config", "download", "upload", "setting")):
        return "configuration"
    if any(kw in lower for kw in ("login", "logout", "auth", "password", "user")):
        return "authentication"
    if any(kw in lower for kw in ("comm", "network", "ethernet", "port")):
        return "network"
    return "process"
