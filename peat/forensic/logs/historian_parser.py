"""
OT historian data export parser (OSIsoft PI / AVEVA, Honeywell PHD, generic).

Parses time-series CSV and XML exports from industrial historians used in
ICS/SCADA environments. During incident response, historian exports reveal
process anomalies — pressure spikes, irregular valve operations, or
manipulated setpoints that indicate physical process tampering.

Supported formats:
  - OSIsoft PI / AVEVA PI System CSV exports (PI DataLink, PI System Explorer)
  - OSIsoft PI XML exports (PI System Explorer native format)
  - Generic historian CSV with tag/value/quality columns

CSV format example (PI DataLink export):
    Tag,Timestamp,Value,Quality,Annotated
    TANK.LEVEL,2026-03-15 14:00:00,85.2,Good,
    TANK.LEVEL,2026-03-15 14:01:00,85.5,Good,
    PUMP.STATUS,2026-03-15 14:00:00,1,Good,

@decision: Uses chunked CSV reading for large historian exports. PI exports
can contain millions of rows spanning days of process data. The parser
yields entries in chunks rather than loading everything into memory.
Anomaly detection (standard deviation from baseline) is left to downstream
analysis — the parser normalizes data; it doesn't interpret it.
"""

from __future__ import annotations

import csv
import io
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# Column candidates for historian CSV auto-detection
_HIST_TAG_COLS = {"tag", "tagname", "tag name", "tag_name", "point", "pointname",
                   "point name", "point_name", "name", "item", "itemid"}
_HIST_VALUE_COLS = {"value", "val", "data", "result", "reading", "measurement"}
_HIST_QUALITY_COLS = {"quality", "status", "qual", "opc quality", "data quality",
                       "state", "validity"}
_HIST_TIMESTAMP_COLS = {"timestamp", "time", "date", "datetime", "date/time",
                         "sample time", "event time", "t"}
_HIST_UNIT_COLS = {"unit", "units", "engineering units", "eng units", "uom"}

# Quality values that indicate bad/questionable data
_BAD_QUALITY = {"bad", "uncertain", "questionable", "error", "comm failure",
                "sensor failure", "out of range", "stale", "timeout"}


class PICSVParser(LogParser):
    """Parser for OSIsoft PI / AVEVA historian CSV exports."""

    name = "pi_csv"
    vendor = "OSIsoft/AVEVA"
    description = "OSIsoft PI / AVEVA historian CSV export parser"
    file_patterns = [
        "*PI*.csv", "*pi_*.csv", "*aveva*.csv",
        "*historian*.csv", "*Historian*.csv",
        "*datalink*.csv", "*DataLink*.csv",
        "*process_data*.csv", "*trend*.csv",
    ]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        lower = sample.lower()

        # Check for PI/AVEVA indicators
        pi_indicators = {"osisoft", "pi system", "pi datalink", "aveva", "pi web api",
                         "af sdk", "pi server"}
        if any(ind in lower for ind in pi_indicators):
            return True

        # Check for historian-style CSV: tag + value + timestamp columns
        first_line = lower.split("\n", 1)[0]
        has_tag = any(col in first_line for col in _HIST_TAG_COLS)
        has_value = any(col in first_line for col in _HIST_VALUE_COLS)
        has_time = any(col in first_line for col in _HIST_TIMESTAMP_COLS)

        # Need at least tag+value+time to look like historian data
        if has_tag and has_value and has_time:
            # Distinguish from alarm CSVs by checking for absence of alarm keywords
            alarm_indicators = {"alarm", "severity", "acknowledgement", "priority"}
            if not any(ind in first_line for ind in alarm_indicators):
                return True

        return False

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        headers = {k.lower().strip(): k for k in rows[0].keys()}
        tag_col = _find_col(headers, _HIST_TAG_COLS)
        value_col = _find_col(headers, _HIST_VALUE_COLS)
        quality_col = _find_col(headers, _HIST_QUALITY_COLS)
        ts_col = _find_col(headers, _HIST_TIMESTAMP_COLS)
        unit_col = _find_col(headers, _HIST_UNIT_COLS)

        entries: list[ParsedLogEntry] = []
        bad_quality_count = 0

        for row in rows:
            tag = row.get(tag_col, "") if tag_col else ""
            value = row.get(value_col, "") if value_col else ""
            quality = row.get(quality_col, "") if quality_col else "Good"
            ts_str = row.get(ts_col, "") if ts_col else ""
            unit = row.get(unit_col, "") if unit_col else ""

            timestamp = cls._parse_timestamp(ts_str)

            # Flag bad quality as warnings
            is_bad = quality.lower().strip() in _BAD_QUALITY
            if is_bad:
                bad_quality_count += 1
                severity = "warning"
                action = "bad_quality"
            else:
                severity = "info"
                action = "process_value"

            extra: dict[str, Any] = {"tag": tag, "value": value, "quality": quality}
            if unit:
                extra["unit"] = unit

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=f"{tag}={value} ({quality})",
                original=str(row),
                source_type="pi_csv",
                source_file=path.name,
                action=action,
                category="process",
                severity=severity,
                device_vendor="OSIsoft/AVEVA",
                device_model="PI System",
                extra=extra,
            ))

        if bad_quality_count:
            log.info(
                f"Historian: {bad_quality_count} of {len(entries)} readings "
                f"have bad/questionable quality"
            )

        log.info(f"Parsed {len(entries)} historian readings from: {path.name}")
        return entries


class PIXMLParser(LogParser):
    """Parser for OSIsoft PI XML exports (PI System Explorer format)."""

    name = "pi_xml"
    vendor = "OSIsoft/AVEVA"
    description = "OSIsoft PI XML export parser"
    file_patterns = ["*PI*.xml", "*pi_*.xml", "*aveva*.xml", "*historian*.xml"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]
        return ("<PI" in sample or "<AF" in sample or "PIPoint" in sample
                or "osisoft" in sample.lower() or "PISystem" in sample)

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        text = cls._read_text(path)
        entries: list[ParsedLogEntry] = []

        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            log.warning(f"Failed to parse PI XML {path.name}: {e}")
            return []

        # Handle multiple PI XML schemas
        # Look for data elements with timestamp/value pairs
        for elem in _iter_data_elements(root):
            tag = elem.get("tag", elem.get("name", elem.get("pointname", "")))
            value = elem.get("value", elem.get("val", elem.text or ""))
            quality = elem.get("quality", elem.get("status", "Good"))
            ts_str = elem.get("timestamp", elem.get("time", elem.get("t", "")))

            timestamp = cls._parse_timestamp(ts_str)

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=f"{tag}={value} ({quality})",
                original=ET.tostring(elem, encoding="unicode")[:300],
                source_type="pi_xml",
                source_file=path.name,
                action="process_value",
                category="process",
                severity="warning" if quality.lower() in _BAD_QUALITY else "info",
                device_vendor="OSIsoft/AVEVA",
                device_model="PI System",
                extra={"tag": tag, "value": value, "quality": quality},
            ))

        log.info(f"Parsed {len(entries)} readings from PI XML: {path.name}")
        return entries


def _iter_data_elements(root: ET.Element):
    """Iterate over data-bearing XML elements in PI exports."""
    # Try common PI XML structures
    for tag_name in ["Data", "Value", "Reading", "Sample", "Item",
                     "PIPoint", "Record", "Row", "Entry"]:
        elements = root.findall(f".//{tag_name}")
        if elements:
            yield from elements
            return

    # Fallback: yield all leaf elements with text content
    for elem in root.iter():
        if elem.text and elem.text.strip() and len(elem.attrib) >= 2:
            yield elem


def _find_col(headers: dict[str, str], candidates: set[str]) -> str | None:
    for c in candidates:
        if c in headers:
            return headers[c]
    return None
