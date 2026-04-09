"""
GE Universal Relay (UR) log parser.

Parses GE Multilin UR relay Security Audit Logs, Event Logs, and
IEC 61850 Substation Configuration Language (SCL) XML exports.

GE UR relays produce structured logs with timestamps, user actions,
and fault data. The Security Audit Log is stored in protected memory
and records all user commands — invaluable for incident response.

SCL XML format (IEC 61850) contains relay data model and GOOSE message
configurations which can be parsed with standard XML tools.

@decision: Supports both CSV event exports and IEC 61850 SCL XML.
CSV is the common export format from EnerVista (GE's relay management
software). SCL XML provides deeper device model information but requires
XML parsing. Both are handled by the same parser class with format
auto-detection.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from peat import log
from peat.forensic.logs.base import LogParser, ParsedLogEntry

# GE UR CSV column patterns
_GE_TIMESTAMP_COLS = {"timestamp", "time", "date/time", "event time", "date"}
_GE_EVENT_COLS = {"event", "event type", "event id", "type", "event description"}
_GE_USER_COLS = {"user", "username", "user id", "operator"}
_GE_SOURCE_COLS = {"source", "origin", "interface", "port"}

# GE UR event classification keywords
_GE_PROTECTION_KW = {"trip", "pickup", "dropout", "overcurrent", "overvoltage",
                      "undervoltage", "underfrequency", "overfrequency", "fault",
                      "50", "51", "67", "87", "21", "59", "27", "81"}
_GE_AUTH_KW = {"login", "logout", "password", "access", "user", "lockout", "session"}
_GE_CONFIG_KW = {"setting", "config", "download", "upload", "program", "firmware", "update"}


class GEURLogParser(LogParser):
    """Parser for GE Multilin Universal Relay CSV event/audit logs."""

    name = "ge_ur_csv"
    vendor = "GE"
    description = "GE Multilin UR relay event and security audit log parser"
    file_patterns = [
        "*GE*.csv", "*ge*.csv",
        "*UR*.csv", "*ur*.csv",
        "*EnerVista*.csv", "*enervista*.csv",
        "*audit*.csv", "*event*.csv",
    ]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]

        lower = sample.lower()

        # Check for GE/UR/EnerVista indicators in content
        ge_indicators = {"ge multilin", "enervista", "universal relay", "ge ur",
                         "security audit", "multilin"}
        if any(ind in lower for ind in ge_indicators):
            return True

        # Check filename patterns
        name_lower = path.name.lower()
        if any(kw in name_lower for kw in ("ge", "ur_", "enervista", "multilin")):
            return "," in sample  # Must also look like CSV

        return False

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        rows = cls._read_csv(path)
        if not rows:
            return []

        headers = {k.lower().strip(): k for k in rows[0].keys()}
        ts_col = _find_col(headers, _GE_TIMESTAMP_COLS)
        event_col = _find_col(headers, _GE_EVENT_COLS)
        user_col = _find_col(headers, _GE_USER_COLS)
        source_col = _find_col(headers, _GE_SOURCE_COLS)

        entries: list[ParsedLogEntry] = []
        for row in rows:
            ts_str = row.get(ts_col, "") if ts_col else ""
            timestamp = cls._parse_timestamp(ts_str)
            event_text = row.get(event_col, "") if event_col else ""
            user = row.get(user_col, "") if user_col else ""
            source = row.get(source_col, "") if source_col else ""

            action, category, severity = _classify_ge_event(event_text)

            extra: dict = {k: v for k, v in row.items() if v}
            if user:
                extra["user"] = user
            if source:
                extra["source_interface"] = source

            entries.append(ParsedLogEntry(
                timestamp=timestamp,
                message=event_text or str(row),
                original=str(row),
                source_type="ge_ur_csv",
                source_file=path.name,
                action=action,
                category=category,
                severity=severity,
                device_vendor="GE",
                device_model="Universal Relay",
                extra=extra,
            ))

        log.info(f"Parsed {len(entries)} events from GE UR log: {path.name}")
        return entries


class GESCLParser(LogParser):
    """Parser for GE relay IEC 61850 SCL (Substation Configuration Language) XML exports."""

    name = "ge_scl_xml"
    vendor = "GE"
    description = "GE relay IEC 61850 SCL XML configuration parser"
    file_patterns = ["*.scl", "*.scd", "*.icd", "*.cid", "*.SCL", "*.SCD"]

    @classmethod
    def detect(cls, path: Path, sample: str = "") -> bool:
        if not sample:
            sample = cls._read_text(path)[:4096]
        return "<SCL" in sample or "<scl" in sample or "IEC 61850" in sample

    @classmethod
    def parse(cls, path: Path) -> list[ParsedLogEntry]:
        text = cls._read_text(path)
        entries: list[ParsedLogEntry] = []

        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            log.warning(f"Failed to parse SCL XML {path.name}: {e}")
            return []

        ns = {"scl": "http://www.iec.ch/61850/2003/SCL"}

        # Extract IED (Intelligent Electronic Device) information
        for ied in root.findall(".//scl:IED", ns) or root.findall(".//IED"):
            ied_name = ied.get("name", "unknown")
            manufacturer = ied.get("manufacturer", "")
            ied_type = ied.get("type", "")

            entries.append(ParsedLogEntry(
                message=f"IED: {ied_name} ({manufacturer} {ied_type})",
                original=ET.tostring(ied, encoding="unicode")[:500],
                source_type="ge_scl_xml",
                source_file=path.name,
                action="ied_definition",
                category="configuration",
                severity="info",
                device_vendor=manufacturer or "GE",
                device_model=ied_type,
                device_id=ied_name,
                extra={
                    "ied_name": ied_name,
                    "manufacturer": manufacturer,
                    "type": ied_type,
                },
            ))

            # Extract GOOSE control blocks
            for goose in ied.findall(".//scl:GSEControl", ns) or ied.findall(".//GSEControl"):
                goose_name = goose.get("name", "")
                app_id = goose.get("appID", "")
                entries.append(ParsedLogEntry(
                    message=f"GOOSE: {goose_name} (appID={app_id}) on {ied_name}",
                    original=ET.tostring(goose, encoding="unicode")[:500],
                    source_type="ge_scl_xml",
                    source_file=path.name,
                    action="goose_config",
                    category="configuration",
                    severity="info",
                    device_vendor=manufacturer or "GE",
                    device_id=ied_name,
                    extra={"goose_name": goose_name, "app_id": app_id},
                ))

        log.info(f"Parsed {len(entries)} items from SCL XML: {path.name}")
        return entries


def _find_col(headers: dict[str, str], candidates: set[str]) -> str | None:
    for c in candidates:
        if c in headers:
            return headers[c]
    return None


def _classify_ge_event(event_text: str) -> tuple[str, str, str]:
    lower = event_text.lower()
    if any(kw in lower for kw in _GE_PROTECTION_KW):
        return "protection_event", "process", "critical"
    if any(kw in lower for kw in _GE_AUTH_KW):
        return "authentication", "authentication", "info"
    if any(kw in lower for kw in _GE_CONFIG_KW):
        return "config_change", "configuration", "info"
    return "event", "process", "info"
