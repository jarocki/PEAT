"""
Schneider Electric ClearSCADA / Geo SCADA Expert comms log parser.

Parses Comms and I/O log files from ClearSCADA / Geo SCADA Expert systems.
These logs contain TX (transmitted) and RX (received) SCADA communication
entries with timestamps, status codes, and channel information.

Log format example:
    2026-03-15 14:23:45.123 TX 01 03 00 00 00 0A C5 CD
    2026-03-15 14:23:45.456 RX ACCEPTED 01 03 14 00 64 ...

Also handles Schneider Modicon PLC CSV logs from SD card/flash exports.

@decision: TX/RX delimiter-based parsing rather than fixed-width, because
ClearSCADA log line widths vary based on payload length. The TX/RX keyword
is the reliable anchor point for splitting direction from payload data.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# ClearSCADA comms log patterns
_COMMS_LINE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"  # Timestamp
    r"(TX|RX)\s+"  # Direction
    r"(ACCEPTED|REJECTED|TIMEOUT|ERROR)?\s*"  # Optional status
    r"(.*)"  # Payload (hex bytes or message)
)

# Modicon CSV log patterns (FAT16 format from SD/flash)
_MODICON_HEADER_INDICATORS = {"timestamp", "tag", "value", "quality", "log_data"}


class SchneiderCommsParser(LogParser):
    """Parser for Schneider ClearSCADA/Geo SCADA comms logs."""

    name = "schneider_comms"
    vendor = "Schneider Electric"
    description = "Schneider ClearSCADA/Geo SCADA comms log parser"
    file_patterns = ["*comms*.log", "*comms*.txt", "*clearscada*.log", "*geoscada*.log"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        # Look for TX/RX patterns characteristic of SCADA comms logs
        tx_rx_count = len(re.findall(r"\b(TX|RX)\s+(ACCEPTED|REJECTED|TIMEOUT|ERROR|\d)", sample))
        return tx_rx_count >= 3

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        text = cls._read_text(path)
        entries: list[ParsedLogEntry] = []
        channel_info = ""

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # Extract channel information from header
            if "channel" in stripped.lower() and ":" in stripped:
                channel_info = stripped
                continue

            match = _COMMS_LINE_RE.match(stripped)
            if not match:
                continue

            ts_str, direction, status, payload = match.groups()
            timestamp = cls._parse_timestamp(ts_str)
            status = (status or "").strip()
            payload = payload.strip()

            # Determine severity from status
            if status == "REJECTED":
                severity = "warning"
                outcome = "failure"
            elif status == "TIMEOUT":
                severity = "warning"
                outcome = "failure"
            elif status == "ERROR":
                severity = "error"
                outcome = "failure"
            elif status == "ACCEPTED":
                severity = "info"
                outcome = "success"
            else:
                severity = "info"
                outcome = ""

            extra: dict = {"direction": direction, "payload": payload}
            if status:
                extra["status"] = status
            if channel_info:
                extra["channel"] = channel_info

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=f"{direction} {status} {payload}".strip(),
                original=stripped,
                source_type="schneider_comms",
                source_file=path.name,
                action=f"scada_{direction.lower()}",
                category="network",
                severity=severity,
                outcome=outcome,
                device_vendor="Schneider Electric",
                device_model="ClearSCADA",
                extra=extra,
            ))

        log.info(f"Parsed {len(entries)} comms entries from Schneider log: {path.name}")
        return entries


class SchneiderModiconCSVParser(LogParser):
    """Parser for Schneider Modicon PLC CSV logs from flash/SD card."""

    name = "schneider_modicon_csv"
    vendor = "Schneider Electric"
    description = "Schneider Modicon PLC CSV log parser (SD/flash exports)"
    file_patterns = ["LOG_*.CSV", "log_*.csv", "LOG_DATA.CSV"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        # Check for 8.3 filename pattern and CSV content
        name_match = re.match(r"LOG_?\w*\.CSV", path.name, re.IGNORECASE)
        if not name_match:
            return False

        # Should have CSV-like content with timestamps
        return "," in sample and re.search(r"\d{4}[-/]\d{2}[-/]\d{2}", sample) is not None

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        entries: list[ParsedLogEntry] = []
        for row in rows:
            # Try to find timestamp in any column
            timestamp = None
            for val in row.values():
                timestamp = cls._parse_timestamp(val)
                if timestamp:
                    break

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=str(row),
                original=str(row),
                source_type="schneider_modicon_csv",
                source_file=path.name,
                category="process",
                severity="info",
                device_vendor="Schneider Electric",
                device_model="Modicon",
                extra={k: v for k, v in row.items() if v},
            ))

        log.info(f"Parsed {len(entries)} entries from Modicon CSV: {path.name}")
        return entries
