"""
Rockwell Automation FactoryTalk Alarms and Events (FTAE) log parser.

Parses CSV exports from FactoryTalk Alarms and Events, FactoryTalk
Diagnostics, and Connected Components Workbench (CCW) event logs.

FTAE CSV format example:
    Alarm Name,Severity,Event Time,Message,Acknowledgement Status
    Tank_Level_High,High,2026-03-15 14:23:45,Tank level exceeded 95%,Unacknowledged
    Pump_1_Fault,Critical,2026-03-15 14:24:00,Motor overload detected,Unacknowledged

@decision: Focuses on CSV/text exports rather than live CIP communication.
pylogix requires a live EtherNet/IP connection to a controller and cannot
parse offline exports. CSV exports from FactoryTalk View, FTAE, or CCW
are the standard offline artifact available to forensic analysts.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# Column name candidates for Rockwell FTAE CSVs
_RW_TIMESTAMP_COLS = {"event time", "timestamp", "time", "date/time", "date_time",
                       "alarm time", "occurrence time"}
_RW_ALARM_COLS = {"alarm name", "alarm", "tag", "tag name", "point name", "name"}
_RW_MESSAGE_COLS = {"message", "description", "alarm message", "event message",
                     "alarm description", "text"}
_RW_SEVERITY_COLS = {"severity", "priority", "level", "alarm severity",
                      "alarm priority", "criticality"}
_RW_STATUS_COLS = {"status", "acknowledgement status", "ack status", "state",
                    "alarm state", "condition"}

# Rockwell-specific classification
_RW_CRITICAL_KW = {"fault", "critical", "emergency", "e-stop", "estop", "shutdown",
                    "overload", "overcurrent", "safety"}
_RW_WARNING_KW = {"high", "low", "warning", "caution", "deviation", "exceeded",
                   "approaching", "limit"}
_RW_CONFIG_KW = {"download", "upload", "program", "firmware", "mode change",
                  "run", "remote", "online", "offline"}


class RockwellFTAEParser(LogParser):
    """Parser for Rockwell FactoryTalk Alarms and Events CSV exports."""

    name = "rockwell_ftae"
    vendor = "Rockwell Automation"
    description = "Rockwell FactoryTalk Alarms and Events CSV parser"
    file_patterns = [
        "*FactoryTalk*.csv", "*factorytalk*.csv",
        "*FTAE*.csv", "*ftae*.csv",
        "*alarm*.csv", "*Alarm*.csv",
        "*CCW*.csv", "*ccw*.csv",
    ]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        lower = sample.lower()

        # Check for Rockwell/FactoryTalk indicators
        rw_indicators = {"factorytalk", "allen-bradley", "rockwell", "ftae",
                         "rslogix", "studio 5000", "controllogix", "compactlogix",
                         "connected components"}
        if any(ind in lower for ind in rw_indicators):
            return True

        # Check for alarm-specific CSV with Rockwell-style headers
        first_line = sample.split("\n", 1)[0].lower()
        alarm_headers = {"alarm name", "alarm severity", "alarm message",
                         "alarm time", "ack status"}
        return sum(1 for h in alarm_headers if h in first_line) >= 2

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        headers = {k.lower().strip(): k for k in rows[0].keys()}
        ts_col = _find_col(headers, _RW_TIMESTAMP_COLS)
        alarm_col = _find_col(headers, _RW_ALARM_COLS)
        msg_col = _find_col(headers, _RW_MESSAGE_COLS)
        sev_col = _find_col(headers, _RW_SEVERITY_COLS)
        status_col = _find_col(headers, _RW_STATUS_COLS)

        entries: list[ParsedLogEntry] = []
        for row in rows:
            ts_str = row.get(ts_col, "") if ts_col else ""
            timestamp = cls._parse_timestamp(ts_str)
            alarm_name = row.get(alarm_col, "") if alarm_col else ""
            message = row.get(msg_col, "") if msg_col else ""
            severity_raw = row.get(sev_col, "") if sev_col else ""
            status = row.get(status_col, "") if status_col else ""

            action, category, severity = _classify_rockwell_event(
                alarm_name, message, severity_raw
            )

            # Determine outcome from acknowledgement status
            outcome = ""
            if status:
                lower_status = status.lower()
                if "unack" in lower_status:
                    outcome = "pending"
                elif "ack" in lower_status:
                    outcome = "acknowledged"
                elif "return" in lower_status or "clear" in lower_status:
                    outcome = "resolved"

            extra: dict = {k: v for k, v in row.items() if v}
            if alarm_name:
                extra["alarm_name"] = alarm_name

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=message or alarm_name,
                original=str(row),
                source_type="rockwell_ftae",
                source_file=path.name,
                action=action,
                category=category,
                severity=severity,
                outcome=outcome,
                device_vendor="Rockwell Automation",
                device_model="ControlLogix",
                extra=extra,
            ))

        log.info(f"Parsed {len(entries)} alarms from Rockwell FTAE: {path.name}")
        return entries


def _find_col(headers: dict[str, str], candidates: set[str]) -> str | None:
    for c in candidates:
        if c in headers:
            return headers[c]
    return None


def _classify_rockwell_event(
    alarm_name: str, message: str, severity_raw: str
) -> tuple[str, str, str]:
    combined = (alarm_name + " " + message + " " + severity_raw).lower()

    if any(kw in combined for kw in _RW_CRITICAL_KW):
        return "alarm_critical", "process", "critical"
    if any(kw in combined for kw in _RW_WARNING_KW):
        return "alarm_warning", "process", "warning"
    if any(kw in combined for kw in _RW_CONFIG_KW):
        return "config_change", "configuration", "info"

    # Fall back to severity_raw
    sev_lower = severity_raw.lower().strip()
    if sev_lower in ("critical", "urgent", "1"):
        return "alarm", "process", "critical"
    if sev_lower in ("high", "2"):
        return "alarm", "process", "error"
    if sev_lower in ("medium", "3"):
        return "alarm", "process", "warning"

    return "alarm", "process", "info"
