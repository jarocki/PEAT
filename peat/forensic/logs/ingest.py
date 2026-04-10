"""
Unified ICS/SCADA log ingestion framework.

Auto-detects log format and dispatches to the appropriate vendor parser.
Handles single files, directories of logs, and mixed-format collections.

@decision: Parser registration uses a simple list rather than a plugin
system. The number of ICS log parsers is small and well-defined — the
overhead of a full plugin registry isn't justified. New parsers are added
by importing them here and appending to PARSERS.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from peat import config, log
from peat.forensic.logs.base import LogParser, ParsedLogEntry
from peat.forensic.logs.ge_parser import GESCLParser, GEURLogParser
from peat.forensic.logs.rockwell_parser import RockwellFTAEParser
from peat.forensic.logs.schneider_parser import SchneiderCommsParser, SchneiderModiconCSVParser
from peat.forensic.logs.sel_parser import SELLogParser
from peat.forensic.logs.siprotec_parser import GenericCSVLogParser, SiprotecLogParser

# Ordered list of parsers — vendor-specific first, generic last
PARSERS: list[type[LogParser]] = [
    SELLogParser,
    SiprotecLogParser,
    GEURLogParser,
    GESCLParser,
    RockwellFTAEParser,
    SchneiderCommsParser,
    SchneiderModiconCSVParser,
    GenericCSVLogParser,  # Fallback — must be last
]


def ingest_logs(
    path: Path,
    output_dir: Path | None = None,
) -> list[ParsedLogEntry]:
    """
    Ingest log files from a path (file or directory).

    Auto-detects the log format and dispatches to the appropriate parser.
    Results are normalized to ParsedLogEntry and optionally written as
    ECS-compliant JSON.

    Args:
        path: Path to a log file or directory of log files.
        output_dir: Directory to write parsed results. If None, uses
                    config.RUN_DIR / "forensic_logs".

    Returns:
        List of all parsed log entries.
    """
    if output_dir is None and config.RUN_DIR:
        output_dir = config.RUN_DIR / "forensic_logs"
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    all_entries: list[ParsedLogEntry] = []

    if path.is_file():
        entries = _ingest_single_file(path)
        all_entries.extend(entries)
    elif path.is_dir():
        log.info(f"Scanning directory for log files: {path}")
        for child in sorted(path.rglob("*")):
            if child.is_file() and not child.name.startswith("."):
                entries = _ingest_single_file(child)
                all_entries.extend(entries)
    else:
        log.error(f"Log path is not a file or directory: {path}")

    log.info(f"Total log entries ingested: {len(all_entries)}")

    # Write results
    if output_dir and all_entries:
        _write_results(all_entries, output_dir)

    return all_entries


def _ingest_single_file(path: Path) -> list[ParsedLogEntry]:
    """Detect format and parse a single log file."""
    # Read sample for detection
    try:
        sample = path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError as e:
        log.warning(f"Cannot read log file {path.name}: {e}")
        return []

    # Try each parser in order
    for parser_cls in PARSERS:
        try:
            if parser_cls.detect(path, sample):
                log.info(f"Detected {parser_cls.name} format: {path.name}")
                entries = parser_cls.parse(path)
                return entries
        except Exception as e:
            log.warning(f"{parser_cls.name} failed on {path.name}: {e}")
            continue

    log.debug(f"No parser matched: {path.name}")
    return []


def _write_results(entries: list[ParsedLogEntry], output_dir: Path) -> None:
    """Write parsed log entries as ECS-compliant JSON."""
    # Summary file
    summary = {
        "log_ingestion": {
            "total_entries": len(entries),
            "sources": _count_by_field(entries, "source_type"),
            "vendors": _count_by_field(entries, "device_vendor"),
            "severities": _count_by_field(entries, "severity"),
            "categories": _count_by_field(entries, "category"),
        }
    }

    summary_path = output_dir / "log-ingestion-summary.json"
    try:
        summary_path.write_text(json.dumps(summary, indent=4))
        log.debug(f"Summary written to: {summary_path}")
    except OSError as e:
        log.warning(f"Failed to write summary: {e}")

    # Full entries as NDJSON (newline-delimited JSON) for Elasticsearch bulk import
    entries_path = output_dir / "parsed-log-entries.ndjson"
    try:
        with open(entries_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry.to_ecs_dict(), default=str) + "\n")
        log.debug(f"Entries written to: {entries_path} ({len(entries)} lines)")
    except OSError as e:
        log.warning(f"Failed to write entries: {e}")


def _count_by_field(entries: list[ParsedLogEntry], field: str) -> dict[str, int]:
    """Count entries by a specific field value."""
    counts: dict[str, int] = {}
    for entry in entries:
        val = getattr(entry, field, "") or "unknown"
        counts[val] = counts.get(val, 0) + 1
    return counts
