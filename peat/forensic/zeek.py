"""
Zeek/ICSNPP integration for advanced ICS protocol analysis.

Wraps a local Zeek installation (with CISA ICSNPP plugins) to process
PCAP files and parse the resulting log files for ICS protocol events.
This provides deeper protocol analysis than the built-in dpkt/scapy
pipeline, including MITRE ICS ATT&CK technique mapping via ACID.

Zeek is an optional dependency — the forensic PCAP pipeline works without
it using dpkt/scapy. When Zeek + ICSNPP are available, this module adds:
  - Detailed Modbus register-level logging (modbus_detailed.log)
  - DNP3 object-level logging (dnp3_objects.log, dnp3_control.log)
  - BACnet, EtherCAT, ENIP, S7comm protocol parsing
  - MITRE ATT&CK mapping via ACID scripts (if installed)

@decision: Runs Zeek as a subprocess rather than embedding it. Zeek is a
C++ application with no Python bindings — subprocess is the only option.
JSON log output is enabled via LogAscii::use_json=T for easy parsing.
The module gracefully degrades when Zeek/ICSNPP/ACID are not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from peat import config, log


@dataclass
class ZeekAnalysisResult:
    """Results from Zeek/ICSNPP analysis of a PCAP file."""

    zeek_available: bool = False
    icsnpp_available: bool = False
    acid_available: bool = False
    log_dir: str = ""
    logs_parsed: dict[str, int] = field(default_factory=dict)  # log_name → entry count
    ics_events: list[dict[str, Any]] = field(default_factory=list)
    mitre_techniques: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "zeek_analysis": {
                "zeek_available": self.zeek_available,
                "icsnpp_available": self.icsnpp_available,
                "acid_available": self.acid_available,
                "log_dir": self.log_dir,
                "logs_parsed": self.logs_parsed,
                "ics_events_count": len(self.ics_events),
                "mitre_techniques_count": len(self.mitre_techniques),
                "errors": self.errors,
            }
        }


def find_zeek() -> str | None:
    """Find the Zeek binary on the system."""
    zeek_path = shutil.which("zeek")
    if zeek_path:
        return zeek_path

    # Common install locations
    for candidate in [
        "/opt/zeek/bin/zeek",
        "/usr/local/zeek/bin/zeek",
        "/usr/bin/zeek",
        "/usr/local/bin/zeek",
    ]:
        if Path(candidate).is_file():
            return candidate

    return None


def check_icsnpp(zeek_bin: str) -> bool:
    """Check if ICSNPP plugins are installed in Zeek."""
    try:
        result = subprocess.run(
            [zeek_bin, "-N"],
            capture_output=True, text=True, timeout=10,
        )
        return "ICSNPP" in result.stdout or "icsnpp" in result.stdout.lower()
    except (subprocess.TimeoutExpired, OSError):
        return False


def check_acid(zeek_bin: str) -> bool:
    """Check if MITRE ACID scripts are available."""
    try:
        result = subprocess.run(
            [zeek_bin, "-N"],
            capture_output=True, text=True, timeout=10,
        )
        return "ACID" in result.stdout or "acid" in result.stdout.lower()
    except (subprocess.TimeoutExpired, OSError):
        return False


def analyze_with_zeek(
    pcap_path: Path,
    output_dir: Path | None = None,
) -> ZeekAnalysisResult:
    """
    Run Zeek with ICSNPP plugins on a PCAP file and parse the results.

    Args:
        pcap_path: Path to the PCAP/PCAPNG file.
        output_dir: Directory for Zeek log output. Defaults to
                    config.RUN_DIR / "zeek_logs".

    Returns:
        ZeekAnalysisResult with parsed ICS events and MITRE mappings.
    """
    result = ZeekAnalysisResult()

    # Find Zeek
    zeek_bin = find_zeek()
    if not zeek_bin:
        log.info("Zeek not found — skipping Zeek/ICSNPP analysis")
        return result

    result.zeek_available = True
    log.info(f"Found Zeek at: {zeek_bin}")

    # Check for ICSNPP and ACID
    result.icsnpp_available = check_icsnpp(zeek_bin)
    result.acid_available = check_acid(zeek_bin)

    if result.icsnpp_available:
        log.info("ICSNPP plugins detected")
    else:
        log.info("ICSNPP plugins not detected — basic Zeek analysis only")

    if result.acid_available:
        log.info("MITRE ACID scripts detected")

    # Set up output directory
    if output_dir is None and config.RUN_DIR:
        output_dir = config.RUN_DIR / "zeek_logs"
    if output_dir is None:
        output_dir = Path("zeek_logs")
    output_dir.mkdir(parents=True, exist_ok=True)
    result.log_dir = str(output_dir)

    # Run Zeek
    success = _run_zeek(zeek_bin, pcap_path, output_dir, result)
    if not success:
        return result

    # Parse Zeek log files
    _parse_zeek_logs(output_dir, result)

    log.info(
        f"Zeek analysis complete: {sum(result.logs_parsed.values())} entries "
        f"from {len(result.logs_parsed)} log files, "
        f"{len(result.ics_events)} ICS events"
    )

    # Write results summary
    summary_path = output_dir / "zeek-analysis-summary.json"
    try:
        summary_path.write_text(json.dumps(result.to_dict(), indent=4))
    except OSError as e:
        log.warning(f"Failed to write Zeek summary: {e}")

    return result


def _run_zeek(
    zeek_bin: str,
    pcap_path: Path,
    output_dir: Path,
    result: ZeekAnalysisResult,
) -> bool:
    """Execute Zeek against a PCAP file."""
    cmd = [
        zeek_bin,
        "-C",  # Ignore checksum errors (common in forensic captures)
        "-r", str(pcap_path),
        f"LogAscii::use_json=T",  # JSON output for easy parsing
    ]

    log.info(f"Running Zeek on: {pcap_path.name}")
    log.debug(f"Zeek command: {' '.join(cmd)}")

    try:
        zeek_result = subprocess.run(
            cmd,
            cwd=str(output_dir),
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout for large PCAPs
        )

        if zeek_result.returncode != 0:
            error_msg = f"Zeek exited with code {zeek_result.returncode}"
            if zeek_result.stderr:
                error_msg += f": {zeek_result.stderr[:500]}"
            log.warning(error_msg)
            result.errors.append(error_msg)
            # Continue anyway — partial logs may still be useful
            return True

        log.info("Zeek completed successfully")
        return True

    except subprocess.TimeoutExpired:
        error_msg = "Zeek timed out after 10 minutes"
        log.error(error_msg)
        result.errors.append(error_msg)
        return False
    except OSError as e:
        error_msg = f"Failed to run Zeek: {e}"
        log.error(error_msg)
        result.errors.append(error_msg)
        return False


# Zeek log files relevant to ICS analysis, in priority order
_ICS_LOG_FILES = [
    # ICSNPP logs (if available)
    "modbus.log",
    "modbus_detailed.log",
    "modbus_mask_write_register.log",
    "modbus_read_write_multiple_registers.log",
    "dnp3.log",
    "dnp3_objects.log",
    "dnp3_control.log",
    "bacnet.log",
    "enip.log",
    "cip.log",
    "s7comm.log",
    "ethercat.log",
    "profinet.log",
    # Standard Zeek logs
    "conn.log",
    "dns.log",
    "http.log",
    "ssl.log",
    "notice.log",
    "weird.log",
]


def _parse_zeek_logs(log_dir: Path, result: ZeekAnalysisResult) -> None:
    """Parse Zeek JSON log files from the output directory."""
    for log_name in _ICS_LOG_FILES:
        log_path = log_dir / log_name
        if not log_path.exists():
            continue

        entries = _parse_single_zeek_log(log_path, log_name)
        if entries:
            result.logs_parsed[log_name] = len(entries)

            # ICS-specific logs get added to the events list
            if log_name not in ("conn.log", "dns.log", "http.log", "ssl.log"):
                result.ics_events.extend(entries)

    # Check for ACID/MITRE ATT&CK notices
    notice_path = log_dir / "notice.log"
    if notice_path.exists():
        _extract_mitre_notices(notice_path, result)


def _parse_single_zeek_log(log_path: Path, log_name: str) -> list[dict[str, Any]]:
    """Parse a single Zeek JSON log file."""
    entries: list[dict[str, Any]] = []

    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = json.loads(line)
                    entry["_zeek_log"] = log_name
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        log.warning(f"Failed to read Zeek log {log_name}: {e}")

    if entries:
        log.debug(f"Parsed {len(entries)} entries from {log_name}")

    return entries


def _extract_mitre_notices(notice_path: Path, result: ZeekAnalysisResult) -> None:
    """Extract MITRE ATT&CK technique references from Zeek notice.log."""
    try:
        with open(notice_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # ACID notices contain ATT&CK references in the msg or note fields
                msg = entry.get("msg", "")
                note = entry.get("note", "")

                if "ATT&CK" in msg or "ATT&CK" in note or "MITRE" in msg:
                    result.mitre_techniques.append({
                        "note": note,
                        "message": msg,
                        "source_ip": entry.get("src", ""),
                        "destination_ip": entry.get("dst", ""),
                        "timestamp": entry.get("ts", ""),
                        "sub_message": entry.get("sub", ""),
                    })
    except OSError as e:
        log.warning(f"Failed to read notice.log for MITRE extraction: {e}")
