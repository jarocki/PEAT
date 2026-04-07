"""
SEL (Schweitzer Engineering Laboratories) relay log parser.

Parses SEL Sequential Events Recorder (SER) logs and CSER (Compressed SER)
exports. These are fixed-width ASCII text files produced by SEL protective
relays widely used in the energy sector.

SER format example:
    Date       Time          Event                Loc
    03/15/2026 14:23:45.123  RELAY TRIP            001
    03/15/2026 14:23:45.456  67P1T                 001

@decision: Uses a regex-driven line-by-line parser rather than a full
finite state machine. SEL SER files have a consistent per-line format
that doesn't require cross-line state tracking for basic event extraction.
Multi-line fault reports are grouped by matching consecutive entries with
identical timestamps (within a tolerance window).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# SEL SER line patterns
# Format: DATE TIME EVENT [LOCATION]
_SER_LINE_RE = re.compile(
    r"(\d{2}/\d{2}/\d{4})\s+"  # Date: MM/DD/YYYY
    r"(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"  # Time: HH:MM:SS[.fff]
    r"(.+?)(?:\s{2,}(\S+))?\s*$"  # Event text, optional location
)

# Alternative format with different date order
_SER_LINE_ALT_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})\s+"  # Date: YYYY-MM-DD
    r"(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"  # Time
    r"(.+?)(?:\s{2,}(\S+))?\s*$"  # Event text, optional location
)

# Header detection patterns
_SER_HEADER_PATTERNS = [
    re.compile(r"^\s*Date\s+Time\s+Event", re.IGNORECASE),
    re.compile(r"^\s*SER\s+", re.IGNORECASE),
    re.compile(r"^\s*Sequential Events Recorder", re.IGNORECASE),
    re.compile(r"^\s*FID=", re.IGNORECASE),
    re.compile(r"^\s*BFID=", re.IGNORECASE),
]

# Known SEL event categories for classification
_TRIP_KEYWORDS = {"trip", "tripped", "67p", "67g", "67q", "51p", "51g", "50p", "50g", "87"}
_ALARM_KEYWORDS = {"alarm", "alm", "warning", "warn"}
_CONFIG_KEYWORDS = {"set", "setting", "config", "enable", "disable", "password"}
_COMMS_KEYWORDS = {"comm", "communication", "port", "serial", "ethernet", "login", "logout"}


class SELLogParser(LogParser):
    """Parser for SEL relay SER/CSER log files."""

    name = "sel_ser"
    vendor = "SEL"
    description = "SEL Sequential Events Recorder (SER) log parser"
    file_patterns = ["*SER.TXT", "*SER.txt", "*ser.txt", "*CSER.TXT", "*cser.txt"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        # Check for SER header patterns
        for pattern in _SER_HEADER_PATTERNS:
            if pattern.search(sample):
                return True

        # Check for date/event lines
        lines_with_events = 0
        for line in sample.splitlines()[:50]:
            if _SER_LINE_RE.match(line.strip()) or _SER_LINE_ALT_RE.match(line.strip()):
                lines_with_events += 1

        return lines_with_events >= 3

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        text = cls._read_text(path)
        entries: list[ParsedLogEntry] = []
        device_id = ""
        device_model = ""

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Extract device identification from header
            if stripped.startswith("FID=") or stripped.startswith("BFID="):
                device_id = _extract_fid(stripped)
                continue

            if "SEL-" in stripped.upper():
                model_match = re.search(r"(SEL-\d+\w*)", stripped, re.IGNORECASE)
                if model_match:
                    device_model = model_match.group(1).upper()
                continue

            # Try to parse as an event line
            entry = _parse_ser_line(stripped, path.name, device_id, device_model)
            if entry:
                entries.append(entry)

        log.info(f"Parsed {len(entries)} events from SEL SER log: {path.name}")
        return entries


def _extract_fid(line: str) -> str:
    """Extract relay FID (Firmware ID) from header line."""
    match = re.search(r"(?:B?FID)=(\S+)", line)
    return match.group(1) if match else ""


def _parse_ser_line(
    line: str, source_file: str, device_id: str, device_model: str
) -> ParsedLogEntry | None:
    """Parse a single SER event line."""
    match = _SER_LINE_RE.match(line)
    date_fmt = "%m/%d/%Y"

    if not match:
        match = _SER_LINE_ALT_RE.match(line)
        date_fmt = "%Y-%m-%d"

    if not match:
        return None

    date_str, time_str, event_text, location = match.groups()
    event_text = event_text.strip()

    # Parse timestamp
    ts_str = f"{date_str} {time_str}"
    if "." in time_str:
        ts_fmt = f"{date_fmt} %H:%M:%S.%f"
    else:
        ts_fmt = f"{date_fmt} %H:%M:%S"

    try:
        timestamp = datetime.strptime(ts_str, ts_fmt)
    except ValueError:
        timestamp = None

    # Classify the event
    action, category, severity = _classify_sel_event(event_text)

    extra: dict = {}
    if location:
        extra["location"] = location

    return ParsedLogEntry(
        timestamp=timestamp,
        message=event_text,
        original=line,
        source_type="sel_ser",
        source_file=source_file,
        action=action,
        category=category,
        severity=severity,
        device_id=device_id,
        device_vendor="SEL",
        device_model=device_model,
        extra=extra,
    )


def _classify_sel_event(event_text: str) -> tuple[str, str, str]:
    """Classify a SEL event into action, category, and severity."""
    lower = event_text.lower()

    if any(kw in lower for kw in _TRIP_KEYWORDS):
        return "relay_trip", "process", "critical"
    if any(kw in lower for kw in _ALARM_KEYWORDS):
        return "alarm", "process", "warning"
    if any(kw in lower for kw in _CONFIG_KEYWORDS):
        return "config_change", "configuration", "info"
    if any(kw in lower for kw in _COMMS_KEYWORDS):
        return "communication", "network", "info"

    return "event", "process", "info"
