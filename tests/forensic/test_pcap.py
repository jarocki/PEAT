"""
Tests for PCAP analysis pipeline.

@decision: Tests create synthetic PCAP files using dpkt to write real
Ethernet/IP/TCP frames with embedded ICS protocol payloads. This avoids
shipping real network captures (which may contain sensitive data) while
testing the full pipeline end-to-end: dpkt triage -> ICS identification
-> protocol dissection -> asset inventory generation.
"""

import struct
import time
from pathlib import Path

import dpkt
import pytest

from peat.forensic.pcap import (
    ICSEvent,
    NetworkFlow,
    PcapAnalysisResult,
    analyze_pcap,
    _dissect_modbus,
    _dissect_dnp3,
    _dissect_enip,
    _identify_ics_protocol,
    _flow_key,
    ICS_PORTS,
)
from datetime import datetime, timezone


def _build_pcap(tmp_path: Path, packets: list[tuple[bytes, bytes, int, int, bytes]]) -> Path:
    """
    Build a PCAP file from a list of (src_ip, dst_ip, src_port, dst_port, payload) tuples.

    IPs should be 4-byte packed format. Returns path to the PCAP file.
    """
    pcap_path = tmp_path / "test.pcap"
    writer = dpkt.pcap.Writer(open(pcap_path, "wb"))

    for i, (src_ip, dst_ip, src_port, dst_port, payload) in enumerate(packets):
        tcp = dpkt.tcp.TCP(
            sport=src_port, dport=dst_port,
            seq=1000 + i, ack=0, off=5, flags=dpkt.tcp.TH_ACK,
            data=payload,
        )
        ip = dpkt.ip.IP(
            src=src_ip, dst=dst_ip,
            p=dpkt.ip.IP_PROTO_TCP,
            data=tcp, len=20 + len(tcp),
        )
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
        writer.writepkt(bytes(eth), ts=time.time() + i * 0.001)

    writer.close()
    return pcap_path


def _ip(a: int, b: int, c: int, d: int) -> bytes:
    return bytes([a, b, c, d])


def _modbus_read_request(unit_id: int, fc: int, start_addr: int, quantity: int) -> bytes:
    """Build a Modbus TCP read request payload (MBAP + PDU)."""
    pdu = struct.pack(">BHH", fc, start_addr, quantity)
    mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


class TestICSProtocolIdentification:
    """Tests for port-based ICS protocol identification."""

    def test_modbus_port(self) -> None:
        assert _identify_ics_protocol(12345, 502) == "modbus_tcp"
        assert _identify_ics_protocol(502, 12345) == "modbus_tcp"

    def test_enip_port(self) -> None:
        assert _identify_ics_protocol(12345, 44818) == "enip"

    def test_dnp3_port(self) -> None:
        assert _identify_ics_protocol(12345, 20000) == "dnp3"

    def test_s7comm_port(self) -> None:
        assert _identify_ics_protocol(12345, 102) == "s7comm"

    def test_bacnet_port(self) -> None:
        assert _identify_ics_protocol(12345, 47808) == "bacnet"

    def test_non_ics_port(self) -> None:
        assert _identify_ics_protocol(12345, 8080) == ""

    def test_known_ports_populated(self) -> None:
        assert 502 in ICS_PORTS
        assert 44818 in ICS_PORTS
        assert 20000 in ICS_PORTS


class TestModbusDissector:
    """Tests for Modbus TCP protocol dissection."""

    def test_read_holding_registers(self) -> None:
        payload = _modbus_read_request(unit_id=1, fc=3, start_addr=100, quantity=10)
        ts = datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc)

        events = _dissect_modbus(payload, ts, "192.168.1.100", "192.168.1.1", 5000, 502)

        assert len(events) == 1
        e = events[0]
        assert e.function_code == 3
        assert e.function_name == "Read Holding Registers"
        assert e.unit_id == 1
        assert e.is_request is True
        assert e.extra["start_address"] == 100
        assert e.extra["quantity"] == 10

    def test_write_single_register(self) -> None:
        payload = _modbus_read_request(unit_id=2, fc=6, start_addr=40, quantity=500)
        ts = datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc)

        events = _dissect_modbus(payload, ts, "192.168.1.100", "192.168.1.1", 5000, 502)

        assert len(events) == 1
        assert events[0].function_name == "Write Single Register"

    def test_exception_response(self) -> None:
        # Modbus exception: FC 0x83 (Read Holding Registers exception) + exception code 2
        pdu = struct.pack(">BB", 0x83, 0x02)
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
        payload = mbap + pdu
        ts = datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc)

        events = _dissect_modbus(payload, ts, "192.168.1.1", "192.168.1.100", 502, 5000)

        assert len(events) == 1
        assert "Exception" in events[0].description
        assert events[0].is_request is False

    def test_too_short_payload(self) -> None:
        events = _dissect_modbus(
            b"\x00\x01", datetime.now(timezone.utc),
            "1.2.3.4", "5.6.7.8", 1000, 502,
        )
        assert len(events) == 0

    def test_non_modbus_protocol_id(self) -> None:
        # Protocol ID != 0 means not Modbus
        payload = struct.pack(">HHHBB", 1, 99, 2, 1, 3)
        events = _dissect_modbus(
            payload, datetime.now(timezone.utc),
            "1.2.3.4", "5.6.7.8", 1000, 502,
        )
        assert len(events) == 0


class TestDNP3Dissector:
    """Tests for DNP3 protocol dissection."""

    def test_dnp3_read_request(self) -> None:
        # DNP3 start: 0x0564, length, control, dst_addr, src_addr
        # Then transport header + app control + function code
        payload = b"\x05\x64"  # Start bytes
        payload += struct.pack("<B", 20)  # Length
        payload += struct.pack("<B", 0xC0)  # Control
        payload += struct.pack("<H", 10)  # Destination address
        payload += struct.pack("<H", 1)  # Source address
        payload += b"\x00\x00"  # CRC placeholder
        payload += b"\x00"  # Transport header
        payload += b"\xC0"  # Application control
        payload += b"\x01"  # Function code: Read

        ts = datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc)
        events = _dissect_dnp3(payload, ts, "192.168.1.1", "192.168.1.10", 5000, 20000)

        assert len(events) == 1
        assert events[0].function_name == "Read"
        assert events[0].ics_protocol == "dnp3"
        assert events[0].extra["dst_address"] == 10

    def test_too_short(self) -> None:
        events = _dissect_dnp3(
            b"\x05\x64\x0a", datetime.now(timezone.utc),
            "1.2.3.4", "5.6.7.8", 1000, 20000,
        )
        assert len(events) == 0

    def test_wrong_start_bytes(self) -> None:
        payload = b"\x00\x00" + b"\x00" * 20
        events = _dissect_dnp3(
            payload, datetime.now(timezone.utc),
            "1.2.3.4", "5.6.7.8", 1000, 20000,
        )
        assert len(events) == 0


class TestENIPDissector:
    """Tests for EtherNet/IP dissection."""

    def test_list_identity(self) -> None:
        # ENIP header: command(2) + length(2) + session(4) + status(4) + context(8) + options(4)
        payload = struct.pack("<HHI", 0x0063, 0, 0)  # ListIdentity
        payload += b"\x00" * 16  # rest of header

        ts = datetime(2026, 3, 15, 14, 0, 0, tzinfo=timezone.utc)
        events = _dissect_enip(payload, ts, "192.168.1.100", "192.168.1.1", 5000, 44818)

        assert len(events) == 1
        assert events[0].function_name == "ListIdentity"
        assert events[0].is_request is True

    def test_too_short(self) -> None:
        events = _dissect_enip(
            b"\x00" * 10, datetime.now(timezone.utc),
            "1.2.3.4", "5.6.7.8", 1000, 44818,
        )
        assert len(events) == 0


class TestFullPipeline:
    """End-to-end tests for the PCAP analysis pipeline."""

    def test_analyze_modbus_pcap(self, tmp_path: Path) -> None:
        """Full pipeline: create PCAP with Modbus traffic, analyze it."""
        packets = [
            # Modbus Read Holding Registers request
            (_ip(192, 168, 1, 100), _ip(192, 168, 1, 1), 5000, 502,
             _modbus_read_request(1, 3, 0, 10)),
            # Another Modbus request
            (_ip(192, 168, 1, 100), _ip(192, 168, 1, 1), 5000, 502,
             _modbus_read_request(1, 4, 100, 5)),
            # Non-ICS traffic (HTTP)
            (_ip(192, 168, 1, 100), _ip(10, 0, 0, 1), 5000, 80,
             b"GET / HTTP/1.1\r\n\r\n"),
        ]
        pcap_path = _build_pcap(tmp_path, packets)

        result = analyze_pcap(pcap_path, output_dir=tmp_path / "out")

        assert result.total_packets == 3
        assert result.protocol_summary.get("modbus_tcp", 0) >= 1
        assert len(result.ics_events) >= 2
        assert result.ics_events[0].ics_protocol == "modbus_tcp"

    def test_asset_inventory(self, tmp_path: Path) -> None:
        """Pipeline should build asset inventory from flows."""
        packets = [
            (_ip(192, 168, 1, 100), _ip(192, 168, 1, 1), 5000, 502,
             _modbus_read_request(1, 3, 0, 10)),
        ]
        pcap_path = _build_pcap(tmp_path, packets)

        result = analyze_pcap(pcap_path, output_dir=tmp_path / "out")

        assert len(result.assets) >= 2
        ips = {a.ip for a in result.assets}
        assert "192.168.1.100" in ips
        assert "192.168.1.1" in ips

    def test_output_files_written(self, tmp_path: Path) -> None:
        packets = [
            (_ip(192, 168, 1, 100), _ip(192, 168, 1, 1), 5000, 502,
             _modbus_read_request(1, 3, 0, 10)),
        ]
        pcap_path = _build_pcap(tmp_path, packets)
        out = tmp_path / "out"

        analyze_pcap(pcap_path, output_dir=out)

        assert (out / "pcap-analysis-summary.json").exists()
        assert (out / "ics-events.ndjson").exists()
        assert (out / "asset-inventory.json").exists()

    def test_empty_pcap(self, tmp_path: Path) -> None:
        """Empty PCAP should produce empty results without errors."""
        pcap_path = tmp_path / "empty.pcap"
        writer = dpkt.pcap.Writer(open(pcap_path, "wb"))
        writer.close()

        result = analyze_pcap(pcap_path, output_dir=tmp_path / "out")

        assert result.total_packets == 0
        assert len(result.ics_events) == 0


class TestFlowKey:
    """Tests for bidirectional flow key generation."""

    def test_bidirectional(self) -> None:
        k1 = _flow_key("1.2.3.4", "5.6.7.8", 1000, 502, "tcp")
        k2 = _flow_key("5.6.7.8", "1.2.3.4", 502, 1000, "tcp")
        assert k1 == k2

    def test_different_protocols(self) -> None:
        k1 = _flow_key("1.2.3.4", "5.6.7.8", 1000, 502, "tcp")
        k2 = _flow_key("1.2.3.4", "5.6.7.8", 1000, 502, "udp")
        assert k1 != k2


class TestPcapAnalysisResult:
    """Tests for result serialization."""

    def test_to_dict(self) -> None:
        result = PcapAnalysisResult(
            pcap_path="test.pcap",
            total_packets=1000,
            total_bytes=500000,
            duration_seconds=60.123456,
        )
        d = result.to_dict()

        assert d["pcap_analysis"]["total_packets"] == 1000
        assert d["pcap_analysis"]["duration_seconds"] == 60.123
