"""
Tests for ICS/SCADA log file parsers.

@decision: Tests use inline fixture strings that represent realistic but
synthetic ICS log data. This avoids shipping vendor-proprietary log files
in the test suite while ensuring parsers handle real-world formatting
patterns (variable whitespace, mixed case, optional fields).
"""

from pathlib import Path

import pytest

from peat.forensic.logs.base import ParsedLogEntry, LogParser
from peat.forensic.logs.sel_parser import SELLogParser
from peat.forensic.logs.siprotec_parser import SiprotecLogParser, GenericCSVLogParser
from peat.forensic.logs.schneider_parser import SchneiderCommsParser
from peat.forensic.logs.ingest import ingest_logs, PARSERS


# -- SEL SER log fixtures --

SEL_SER_LOG = """\
FID=SEL-751-R107-V0-Z003003-D20260101

Date       Time           Event                   Loc
03/15/2026 14:23:45.123   RELAY TRIP               001
03/15/2026 14:23:45.456   67P1T                    001
03/15/2026 14:24:00.000   ALARM CLR                001
03/15/2026 14:30:12.789   PORT 1 COMM FAIL         001
03/15/2026 15:00:00.000   SET S01 CHANGED           002
"""

# -- Siemens SIPROTEC CSV fixture --

SIPROTEC_CSV = """\
Timestamp,Event ID,Description,Severity,Source
2026-03-15 14:23:45,1001,Config download started,Info,DIGSI 5
2026-03-15 14:24:12,1002,Config download complete,Info,DIGSI 5
2026-03-15 14:25:00,2001,Overcurrent trip Phase A,Critical,Protection
2026-03-15 14:30:00,3001,User admin login,Info,Security
"""

# -- Schneider ClearSCADA comms log fixture --

SCHNEIDER_COMMS_LOG = """\
Channel: Modbus RTU Port 1
2026-03-15 14:23:45.123 TX 01 03 00 00 00 0A C5 CD
2026-03-15 14:23:45.456 RX ACCEPTED 01 03 14 00 64 00 65
2026-03-15 14:23:46.100 TX 01 06 00 01 00 0A D9 CA
2026-03-15 14:23:46.500 RX REJECTED 01 86 02
2026-03-15 14:23:47.000 TX 01 03 00 10 00 01 85 CF
2026-03-15 14:23:48.000 RX TIMEOUT
"""

# -- Generic CSV fixture --

GENERIC_CSV = """\
Timestamp,Tag,Value,Quality
2026-03-15 14:00:00,TANK_LEVEL,85.2,Good
2026-03-15 14:01:00,TANK_LEVEL,85.5,Good
2026-03-15 14:02:00,PUMP_STATUS,1,Good
"""


class TestSELLogParser:
    """Tests for SEL SER log parser."""

    def test_detect_ser_log(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        assert SELLogParser.detect(f) is True

    def test_detect_non_ser(self, tmp_path: Path) -> None:
        f = tmp_path / "random.txt"
        f.write_text("This is just a regular text file with no SER data.")
        assert SELLogParser.detect(f) is False

    def test_parse_event_count(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        assert len(entries) == 5

    def test_parse_timestamps(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        assert entries[0].timestamp is not None
        assert entries[0].timestamp.month == 3
        assert entries[0].timestamp.day == 15

    def test_parse_trip_event(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        trip = entries[0]
        assert "RELAY TRIP" in trip.message
        assert trip.severity == "critical"
        assert trip.action == "relay_trip"

    def test_parse_comm_fail(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        comm = entries[3]
        assert "COMM" in comm.message
        assert comm.category == "network"

    def test_parse_config_change(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        cfg = entries[4]
        assert "SET" in cfg.message
        assert cfg.action == "config_change"
        assert cfg.category == "configuration"

    def test_device_id_extraction(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        assert entries[0].device_id == "SEL-751-R107-V0-Z003003-D20260101"

    def test_vendor_set(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = SELLogParser.parse(f)
        for e in entries:
            assert e.device_vendor == "SEL"


class TestSiprotecLogParser:
    """Tests for Siemens SIPROTEC CSV parser."""

    def test_detect_siprotec(self, tmp_path: Path) -> None:
        f = tmp_path / "siprotec_diag.csv"
        f.write_text(SIPROTEC_CSV)
        # Detection relies on "DIGSI" in content
        assert SiprotecLogParser.detect(f) is True

    def test_parse_event_count(self, tmp_path: Path) -> None:
        f = tmp_path / "siprotec_diag.csv"
        f.write_text(SIPROTEC_CSV)
        entries = SiprotecLogParser.parse(f)
        assert len(entries) == 4

    def test_parse_critical_event(self, tmp_path: Path) -> None:
        f = tmp_path / "siprotec_diag.csv"
        f.write_text(SIPROTEC_CSV)
        entries = SiprotecLogParser.parse(f)
        trip = entries[2]
        assert "Overcurrent" in trip.message
        assert trip.severity == "critical"

    def test_vendor_set(self, tmp_path: Path) -> None:
        f = tmp_path / "siprotec_diag.csv"
        f.write_text(SIPROTEC_CSV)
        entries = SiprotecLogParser.parse(f)
        for e in entries:
            assert e.device_vendor == "Siemens"


class TestSchneiderCommsParser:
    """Tests for Schneider ClearSCADA comms log parser."""

    def test_detect_comms_log(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        assert SchneiderCommsParser.detect(f) is True

    def test_parse_event_count(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        entries = SchneiderCommsParser.parse(f)
        assert len(entries) == 6

    def test_parse_tx_rx_direction(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        entries = SchneiderCommsParser.parse(f)
        assert entries[0].extra["direction"] == "TX"
        assert entries[1].extra["direction"] == "RX"

    def test_parse_rejected_status(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        entries = SchneiderCommsParser.parse(f)
        rejected = entries[3]
        assert rejected.outcome == "failure"
        assert rejected.severity == "warning"
        assert rejected.extra["status"] == "REJECTED"

    def test_parse_timeout(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        entries = SchneiderCommsParser.parse(f)
        timeout = entries[5]
        assert timeout.outcome == "failure"

    def test_channel_info_captured(self, tmp_path: Path) -> None:
        f = tmp_path / "comms.log"
        f.write_text(SCHNEIDER_COMMS_LOG)
        entries = SchneiderCommsParser.parse(f)
        assert entries[0].extra.get("channel") == "Channel: Modbus RTU Port 1"


class TestGenericCSVParser:
    """Tests for generic CSV fallback parser."""

    def test_detect_generic_csv(self, tmp_path: Path) -> None:
        f = tmp_path / "historian_export.csv"
        f.write_text(GENERIC_CSV)
        assert GenericCSVLogParser.detect(f) is True

    def test_parse_entries(self, tmp_path: Path) -> None:
        f = tmp_path / "historian_export.csv"
        f.write_text(GENERIC_CSV)
        entries = GenericCSVLogParser.parse(f)
        assert len(entries) == 3

    def test_timestamps_parsed(self, tmp_path: Path) -> None:
        f = tmp_path / "historian_export.csv"
        f.write_text(GENERIC_CSV)
        entries = GenericCSVLogParser.parse(f)
        assert entries[0].timestamp is not None


class TestECSOutput:
    """Tests for ECS-compliant output format."""

    def test_to_ecs_dict_structure(self) -> None:
        entry = ParsedLogEntry(
            message="RELAY TRIP",
            original="03/15/2026 14:23:45.123 RELAY TRIP 001",
            source_type="sel_ser",
            action="relay_trip",
            category="process",
            severity="critical",
            device_vendor="SEL",
            device_model="SEL-751",
            device_id="RELAY_001",
        )
        d = entry.to_ecs_dict()

        assert "event" in d
        assert d["event"]["action"] == "relay_trip"
        assert d["event"]["severity"] == "critical"
        assert d["event"]["dataset"] == "sel_ser"
        assert "hash" in d["event"]  # SHA-256 of original line

    def test_to_ecs_dict_with_network(self) -> None:
        entry = ParsedLogEntry(
            source_ip="192.168.1.100",
            destination_ip="192.168.1.1",
            source_port=502,
        )
        d = entry.to_ecs_dict()

        assert d["source"]["ip"] == "192.168.1.100"
        assert d["source"]["port"] == 502
        assert d["destination"]["ip"] == "192.168.1.1"


class TestLogIngestion:
    """Tests for the unified log ingestion framework."""

    def test_ingest_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        entries = ingest_logs(f, output_dir=tmp_path / "out")
        assert len(entries) == 5

    def test_ingest_directory(self, tmp_path: Path) -> None:
        (tmp_path / "SER.TXT").write_text(SEL_SER_LOG)
        (tmp_path / "siprotec.csv").write_text(SIPROTEC_CSV)
        entries = ingest_logs(tmp_path, output_dir=tmp_path / "out")
        assert len(entries) == 9  # 5 SEL + 4 SIPROTEC

    def test_output_files_written(self, tmp_path: Path) -> None:
        f = tmp_path / "SER.TXT"
        f.write_text(SEL_SER_LOG)
        out = tmp_path / "out"
        ingest_logs(f, output_dir=out)
        assert (out / "log-ingestion-summary.json").exists()
        assert (out / "parsed-log-entries.ndjson").exists()

    def test_parsers_registered(self) -> None:
        """All expected parsers should be in the registry."""
        parser_names = {p.name for p in PARSERS}
        assert "sel_ser" in parser_names
        assert "siprotec_csv" in parser_names
        assert "schneider_comms" in parser_names
        assert "generic_csv" in parser_names

    def test_empty_directory(self, tmp_path: Path) -> None:
        entries = ingest_logs(tmp_path, output_dir=tmp_path / "out")
        assert len(entries) == 0
