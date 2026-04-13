"""
Tests for passive device fingerprinting.

@decision: Tests use hand-crafted byte sequences for TCP headers and
ICS payloads rather than dpkt-constructed packets for fingerprint unit
tests. This tests the raw byte parsing logic directly. Integration
tests use dpkt to construct full PCAP files for end-to-end validation.
"""

import struct
from pathlib import Path

import dpkt
import time
import pytest

from peat.forensic.fingerprint import (
    DeviceFingerprint,
    _detect_ics_protocol,
    _extract_tcp_fingerprint,
    _guess_os,
    _compute_confidence,
    _format_mac,
    _is_tls_client_hello,
    _parse_tcp_options,
    _ICS_PAYLOAD_SIGNATURES,
    fingerprint_from_dpkt_pcap,
)


def _build_syn_frame(
    ttl: int = 64,
    window: int = 29200,
    mss: int = 1460,
    src_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
) -> bytes:
    """Build a minimal Ethernet/IP/TCP SYN frame with specified fingerprint values."""
    # Ethernet header (14 bytes)
    eth = b"\x66\x77\x88\x99\xaa\xbb" + src_mac + b"\x08\x00"

    # IP header (20 bytes, IHL=5)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 60,           # version/IHL, DSCP, total length
        0, 0,                   # identification, flags/fragment
        ttl, 6, 0,             # TTL, protocol=TCP, checksum
        b"\xc0\xa8\x01\x64",  # src IP 192.168.1.100
        b"\xc0\xa8\x01\x01",  # dst IP 192.168.1.1
    )

    # TCP header (20 bytes base + MSS option 4 bytes = 24, data_offset=6)
    tcp_flags = 0x02  # SYN
    data_offset = 6  # 6 * 4 = 24 bytes
    tcp = struct.pack("!HHIIBBHHH",
        5000, 502,              # src_port, dst_port
        1000, 0,                # seq, ack
        (data_offset << 4), tcp_flags,  # data_offset + flags
        window, 0, 0,          # window, checksum, urgent
    )
    # MSS option: kind=2, length=4, value
    tcp += struct.pack("!BBH", 2, 4, mss)

    return eth + ip + tcp


class TestTCPFingerprint:
    """Tests for TCP stack fingerprinting."""

    def test_extract_ttl(self) -> None:
        frame = _build_syn_frame(ttl=128)
        fp = DeviceFingerprint(ip="192.168.1.100")
        _extract_tcp_fingerprint(frame, fp)
        assert fp.ttl == 128

    def test_extract_window_size(self) -> None:
        frame = _build_syn_frame(window=16384)
        fp = DeviceFingerprint(ip="192.168.1.100")
        _extract_tcp_fingerprint(frame, fp)
        assert fp.tcp_window_size == 16384

    def test_extract_mss(self) -> None:
        frame = _build_syn_frame(mss=1460)
        fp = DeviceFingerprint(ip="192.168.1.100")
        _extract_tcp_fingerprint(frame, fp)
        assert fp.tcp_mss == 1460

    def test_frame_too_short(self) -> None:
        fp = DeviceFingerprint(ip="1.2.3.4")
        _extract_tcp_fingerprint(b"\x00" * 20, fp)
        assert fp.ttl == 0  # Not modified


class TestOSGuessing:
    """Tests for TCP-based OS identification."""

    def test_guess_windows(self) -> None:
        assert _guess_os(128, 65535, 1460) == "Windows"

    def test_guess_linux(self) -> None:
        assert _guess_os(64, 29200, 1460) == "Embedded Linux"

    def test_guess_vxworks(self) -> None:
        assert _guess_os(64, 4096, 1460) == "VxWorks"

    def test_guess_qnx(self) -> None:
        assert _guess_os(255, 32768, 1460) == "QNX"

    def test_guess_unknown_ttl(self) -> None:
        assert _guess_os(200, 1000, 0) == "Unknown"

    def test_ttl_fallback_linux(self) -> None:
        assert _guess_os(64, 1, 0) == "Linux/Unix"

    def test_ttl_fallback_windows(self) -> None:
        assert _guess_os(128, 1, 0) == "Windows"


class TestICSProtocolDetection:
    """Tests for port-agnostic ICS protocol detection from payloads."""

    def test_detect_modbus_from_payload(self) -> None:
        # MBAP header: transaction(2) + protocol_id=0(2) + length(2) + unit_id(1) + fc(1)
        payload = struct.pack(">HHHBB", 1, 0, 2, 1, 3)
        fp = DeviceFingerprint(ip="1.2.3.4")
        _detect_ics_protocol(payload, 5000, 9999, fp)  # Non-standard port
        assert "modbus_tcp" in fp.ics_protocols

    def test_detect_dnp3_from_payload(self) -> None:
        payload = b"\x05\x64" + b"\x00" * 20
        fp = DeviceFingerprint(ip="1.2.3.4")
        _detect_ics_protocol(payload, 5000, 9999, fp)
        assert "dnp3" in fp.ics_protocols

    def test_detect_s7comm_from_payload(self) -> None:
        # TPKT header: version=3, reserved=0, length
        payload = b"\x03\x00" + b"\x00" * 20
        fp = DeviceFingerprint(ip="1.2.3.4")
        _detect_ics_protocol(payload, 5000, 9999, fp)
        assert "s7comm" in fp.ics_protocols

    def test_no_detection_for_random_payload(self) -> None:
        payload = b"\xde\xad\xbe\xef" * 5
        fp = DeviceFingerprint(ip="1.2.3.4")
        _detect_ics_protocol(payload, 5000, 9999, fp)
        assert len(fp.ics_protocols) == 0

    def test_empty_payload(self) -> None:
        fp = DeviceFingerprint(ip="1.2.3.4")
        _detect_ics_protocol(b"", 5000, 502, fp)
        assert len(fp.ics_protocols) == 0


class TestTLSFingerprinting:
    """Tests for JA3 TLS fingerprint detection."""

    def test_detect_tls_client_hello(self) -> None:
        # Minimal TLS record: ContentType=0x16, version, length, HandshakeType=0x01
        payload = b"\x16\x03\x01\x00\x05\x01" + b"\x00" * 50
        assert _is_tls_client_hello(payload) is True

    def test_reject_non_tls(self) -> None:
        assert _is_tls_client_hello(b"\x00\x01\x02\x03\x04\x05") is False

    def test_reject_short_payload(self) -> None:
        assert _is_tls_client_hello(b"\x16\x03") is False


class TestConfidence:
    """Tests for fingerprint confidence scoring."""

    def test_empty_fingerprint_low_confidence(self) -> None:
        fp = DeviceFingerprint(ip="1.2.3.4")
        _compute_confidence(fp)
        assert fp.confidence == 0.0

    def test_full_fingerprint_high_confidence(self) -> None:
        fp = DeviceFingerprint(
            ip="1.2.3.4", ttl=64, tcp_window_size=29200, tcp_mss=1460,
            tcp_options="2,3,4,8", os_guess="Embedded Linux",
            ics_protocols={"modbus_tcp"}, ja3="abc123",
        )
        _compute_confidence(fp)
        assert fp.confidence >= 0.9

    def test_partial_fingerprint(self) -> None:
        fp = DeviceFingerprint(ip="1.2.3.4", ttl=128, os_guess="Windows")
        _compute_confidence(fp)
        assert 0.2 < fp.confidence < 0.6


class TestUtilities:
    """Tests for utility functions."""

    def test_format_mac(self) -> None:
        assert _format_mac(b"\x00\x11\x22\x33\x44\x55") == "00:11:22:33:44:55"
        assert _format_mac(b"\xff\xff\xff\xff\xff\xff") == "ff:ff:ff:ff:ff:ff"


class TestDeviceFingerprint:
    """Tests for fingerprint serialization."""

    def test_to_dict(self) -> None:
        fp = DeviceFingerprint(
            ip="192.168.1.100", mac="00:11:22:33:44:55",
            ttl=64, tcp_window_size=29200, os_guess="Embedded Linux",
            ics_protocols={"modbus_tcp"}, confidence=0.85, method="passive_tcp+ics_payload",
        )
        d = fp.to_dict()

        assert d["ip"] == "192.168.1.100"
        assert d["tcp_fingerprint"]["ttl"] == 64
        assert d["tcp_fingerprint"]["os_guess"] == "Embedded Linux"
        assert "modbus_tcp" in d["ics_identity"]["protocols"]
        assert d["confidence"] == 0.85


class TestPCAPIntegration:
    """End-to-end fingerprinting from a PCAP file."""

    def test_fingerprint_modbus_pcap(self, tmp_path: Path) -> None:
        """Fingerprint devices from a PCAP with Modbus traffic."""
        # Build PCAP with a SYN + Modbus data
        pcap_path = tmp_path / "test.pcap"
        writer = dpkt.pcap.Writer(open(pcap_path, "wb"))

        # SYN packet from 192.168.1.100 with TTL=64, window=29200
        syn_frame = _build_syn_frame(ttl=64, window=29200, mss=1460)
        writer.writepkt(syn_frame, ts=time.time())

        # Modbus data packet
        modbus_payload = struct.pack(">HHHBB", 1, 0, 2, 1, 3)
        tcp_data = dpkt.tcp.TCP(sport=5000, dport=502, seq=1000, off=5,
                                flags=dpkt.tcp.TH_ACK, data=modbus_payload)
        ip_data = dpkt.ip.IP(src=b"\xc0\xa8\x01\x64", dst=b"\xc0\xa8\x01\x01",
                             p=6, data=tcp_data, len=20+len(tcp_data))
        eth_data = dpkt.ethernet.Ethernet(src=b"\x00\x11\x22\x33\x44\x55",
                                          dst=b"\x66\x77\x88\x99\xaa\xbb",
                                          type=0x0800, data=ip_data)
        writer.writepkt(bytes(eth_data), ts=time.time() + 0.001)
        writer.close()

        fingerprints = fingerprint_from_dpkt_pcap(pcap_path)

        assert "192.168.1.100" in fingerprints
        fp = fingerprints["192.168.1.100"]
        assert fp.ttl == 64
        assert "modbus_tcp" in fp.ics_protocols
        assert fp.confidence > 0.0
