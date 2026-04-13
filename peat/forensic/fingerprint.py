"""
Passive device fingerprinting from network traffic.

Identifies OT/ICS devices without sending any packets by analyzing:
  - TCP stack behavior (window size, TTL, options) — p0f-style OS detection
  - Protocol-specific payload signatures for port-agnostic ICS identification
  - TLS client/server fingerprints (JA3/JA3S) for tool identification
  - Banner and response patterns from observed traffic

@decision: Implements lightweight fingerprinting in pure Python rather than
wrapping p0f or similar tools. The fingerprint database is intentionally
small and ICS-focused — we're identifying PLCs, RTUs, relays, and HMIs,
not general-purpose operating systems. The TCP stack signatures target
common ICS RTOS platforms (VxWorks, QNX, embedded Linux) that have
distinctive network stack implementations.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

from peat import log


@dataclass
class DeviceFingerprint:
    """A passive fingerprint for a network device."""

    ip: str
    mac: str = ""

    # TCP stack fingerprint
    ttl: int = 0
    tcp_window_size: int = 0
    tcp_options: str = ""  # Ordered option kinds as string, e.g. "2,3,4,8"
    tcp_mss: int = 0
    os_guess: str = ""

    # TLS fingerprint
    ja3: str = ""  # Client TLS fingerprint
    ja3s: str = ""  # Server TLS fingerprint
    tls_version: str = ""

    # ICS protocol fingerprint
    ics_protocols: set[str] = field(default_factory=set)
    ics_vendor: str = ""
    ics_product: str = ""
    ics_firmware: str = ""

    # Identification metadata
    banners: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0.0 to 1.0
    method: str = ""  # How the fingerprint was derived

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "tcp_fingerprint": {
                "ttl": self.ttl,
                "window_size": self.tcp_window_size,
                "mss": self.tcp_mss,
                "options": self.tcp_options,
                "os_guess": self.os_guess,
            },
            "tls_fingerprint": {
                "ja3": self.ja3,
                "ja3s": self.ja3s,
                "tls_version": self.tls_version,
            },
            "ics_identity": {
                "protocols": sorted(self.ics_protocols),
                "vendor": self.ics_vendor,
                "product": self.ics_product,
                "firmware": self.ics_firmware,
            },
            "banners": self.banners,
            "confidence": round(self.confidence, 2),
            "method": self.method,
        }


# -- TCP Stack OS Fingerprint Database --
# Format: (ttl_range, window_size_range, mss) → OS guess
# Based on common ICS device network stacks

_TCP_SIGNATURES: list[tuple[str, dict[str, Any]]] = [
    # VxWorks (common in PLCs, RTUs) — TTL 64, small windows, MSS 1460
    ("VxWorks", {"ttl_min": 60, "ttl_max": 64, "win_min": 4096, "win_max": 16384, "mss": 1460}),
    # QNX (common in safety systems) — TTL 255, moderate windows
    ("QNX", {"ttl_min": 250, "ttl_max": 255, "win_min": 16384, "win_max": 65535, "mss": 1460}),
    # Embedded Linux (gateways, modern PLCs) — TTL 64, larger windows
    ("Embedded Linux", {"ttl_min": 60, "ttl_max": 64, "win_min": 29200, "win_max": 65535, "mss": 1460}),
    # Windows (HMIs, engineering workstations) — TTL 128, large windows
    ("Windows", {"ttl_min": 120, "ttl_max": 128, "win_min": 8192, "win_max": 65535, "mss": 1460}),
    # Windows (older) — TTL 128, specific window sizes
    ("Windows (legacy)", {"ttl_min": 120, "ttl_max": 128, "win_min": 16384, "win_max": 16384, "mss": 1460}),
    # Cisco IOS (managed switches in OT) — TTL 255
    ("Cisco IOS", {"ttl_min": 250, "ttl_max": 255, "win_min": 4128, "win_max": 4128, "mss": 536}),
]


# -- ICS Protocol Payload Signatures --
# Port-agnostic detection via application-layer magic bytes

_ICS_PAYLOAD_SIGNATURES: list[tuple[str, bytes, int, str]] = [
    # (protocol_name, signature_bytes, offset, description)
    ("modbus_tcp", b"\x00\x00", 2, "Modbus TCP protocol ID"),  # Bytes 2-3 of MBAP = 0x0000
    ("dnp3", b"\x05\x64", 0, "DNP3 start bytes"),
    ("enip", b"\x00\x04", 0, "ENIP ListServices command"),
    ("enip", b"\x00\x63", 0, "ENIP ListIdentity command"),
    ("enip", b"\x00\x65", 0, "ENIP RegisterSession command"),
    ("enip", b"\x00\x6f", 0, "ENIP SendRRData command"),
    ("enip", b"\x00\x70", 0, "ENIP SendUnitData command"),
    ("s7comm", b"\x03\x00", 0, "TPKT header (S7comm/COTP)"),
    ("iec104", b"\x68", 0, "IEC 104 start byte"),
    ("bacnet", b"\x81", 0, "BACnet/IP BVLC type"),
]

# Modbus function codes that indicate specific device roles
_MODBUS_SERVER_FCS = {1, 2, 3, 4}  # Read operations → device is responding as server
_MODBUS_WRITE_FCS = {5, 6, 15, 16, 22, 23}  # Write operations → potential manipulation


def fingerprint_from_packets(
    packets: list[tuple[float, bytes, str, str, int, int, bytes]],
) -> dict[str, DeviceFingerprint]:
    """
    Build device fingerprints from raw packet data.

    Args:
        packets: List of (timestamp, raw_frame, src_ip, dst_ip, src_port, dst_port, tcp_payload).
                 raw_frame is the full Ethernet frame for TCP header analysis.

    Returns:
        Dict mapping IP address → DeviceFingerprint.
    """
    fingerprints: dict[str, DeviceFingerprint] = {}

    for ts, raw_frame, src_ip, dst_ip, src_port, dst_port, payload in packets:
        # Ensure fingerprint exists for source
        if src_ip not in fingerprints:
            fingerprints[src_ip] = DeviceFingerprint(ip=src_ip)

        fp = fingerprints[src_ip]

        # Extract TCP stack fingerprint from SYN packets
        _extract_tcp_fingerprint(raw_frame, fp)

        # Extract MAC address
        if not fp.mac and len(raw_frame) >= 14:
            fp.mac = _format_mac(raw_frame[6:12])

        # Port-agnostic ICS protocol detection from payload
        if payload:
            _detect_ics_protocol(payload, src_port, dst_port, fp)

        # JA3 TLS fingerprint from ClientHello
        if payload and _is_tls_client_hello(payload):
            fp.ja3 = _compute_ja3(payload)
            fp.tls_version = _extract_tls_version(payload)

    # Assign OS guesses based on TCP signatures
    for fp in fingerprints.values():
        if fp.ttl > 0:
            fp.os_guess = _guess_os(fp.ttl, fp.tcp_window_size, fp.tcp_mss)
        _compute_confidence(fp)

    return fingerprints


def fingerprint_from_dpkt_pcap(pcap_path) -> dict[str, DeviceFingerprint]:
    """
    Build device fingerprints by reading a PCAP file with dpkt.

    Convenience wrapper that extracts packet tuples from a PCAP and
    calls fingerprint_from_packets.
    """
    import dpkt

    packets = []

    try:
        with open(pcap_path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)

            for ts, buf in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.NeedData, dpkt.UnpackError):
                    continue

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                src_ip = ".".join(str(b) for b in ip.src[:4])
                dst_ip = ".".join(str(b) for b in ip.dst[:4])

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    packets.append((
                        ts, buf, src_ip, dst_ip,
                        tcp.sport, tcp.dport, bytes(tcp.data),
                    ))
    except Exception as e:
        log.warning(f"Fingerprint PCAP read error: {e}")

    result = fingerprint_from_packets(packets)
    log.info(f"Fingerprinted {len(result)} devices from PCAP")
    return result


def _extract_tcp_fingerprint(raw_frame: bytes, fp: DeviceFingerprint) -> None:
    """Extract TCP stack properties from a raw Ethernet frame."""
    if len(raw_frame) < 54:  # Minimum: 14 (eth) + 20 (IP) + 20 (TCP)
        return

    # IP header starts at offset 14
    ip_start = 14
    ip_version_ihl = raw_frame[ip_start]
    if (ip_version_ihl >> 4) != 4:
        return

    ihl = (ip_version_ihl & 0x0F) * 4
    ttl = raw_frame[ip_start + 8]

    # Only update TTL from first packet seen (initial TTL is most informative)
    if fp.ttl == 0:
        fp.ttl = ttl

    # TCP header
    tcp_start = ip_start + ihl
    if tcp_start + 20 > len(raw_frame):
        return

    # TCP flags — focus on SYN packets for fingerprinting
    flags = raw_frame[tcp_start + 13]
    is_syn = (flags & 0x02) != 0 and (flags & 0x10) == 0  # SYN without ACK

    if is_syn:
        window = struct.unpack("!H", raw_frame[tcp_start + 14:tcp_start + 16])[0]
        fp.tcp_window_size = window

        # Parse TCP options
        data_offset = (raw_frame[tcp_start + 12] >> 4) * 4
        options_end = tcp_start + data_offset
        _parse_tcp_options(raw_frame[tcp_start + 20:options_end], fp)


def _parse_tcp_options(options_bytes: bytes, fp: DeviceFingerprint) -> None:
    """Parse TCP options from SYN packet to extract MSS and option order."""
    kinds = []
    i = 0
    while i < len(options_bytes):
        kind = options_bytes[i]
        if kind == 0:  # EOL
            break
        if kind == 1:  # NOP
            kinds.append("1")
            i += 1
            continue
        if i + 1 >= len(options_bytes):
            break
        length = options_bytes[i + 1]
        if length < 2:
            break

        kinds.append(str(kind))

        # Extract MSS (kind 2, length 4)
        if kind == 2 and length == 4 and i + 3 < len(options_bytes):
            fp.tcp_mss = struct.unpack("!H", options_bytes[i + 2:i + 4])[0]

        i += length

    fp.tcp_options = ",".join(kinds)


def _detect_ics_protocol(
    payload: bytes, src_port: int, dst_port: int, fp: DeviceFingerprint
) -> None:
    """Detect ICS protocols from payload bytes (port-agnostic)."""
    if len(payload) < 2:
        return

    for proto_name, sig_bytes, offset, desc in _ICS_PAYLOAD_SIGNATURES:
        if offset + len(sig_bytes) <= len(payload):
            if payload[offset:offset + len(sig_bytes)] == sig_bytes:
                fp.ics_protocols.add(proto_name)

    # Modbus-specific: check protocol ID field (bytes 2-3 must be 0x0000)
    if len(payload) >= 8:
        proto_id = struct.unpack("!H", payload[2:4])[0]
        if proto_id == 0:
            fc = payload[7]
            if 1 <= fc <= 127:
                fp.ics_protocols.add("modbus_tcp")


def _is_tls_client_hello(payload: bytes) -> bool:
    """Check if payload starts with a TLS ClientHello."""
    if len(payload) < 6:
        return False
    # ContentType=Handshake(0x16), then version, then HandshakeType=ClientHello(0x01)
    return payload[0] == 0x16 and payload[5] == 0x01


def _compute_ja3(payload: bytes) -> str:
    """
    Compute JA3 fingerprint from a TLS ClientHello.

    JA3 = MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    Simplified implementation — extracts version and cipher suites.
    """
    if len(payload) < 44:
        return ""

    try:
        # TLS record: type(1) + version(2) + length(2) + handshake
        # Handshake: type(1) + length(3) + client_version(2) + random(32) + ...
        hs_start = 5
        client_version = struct.unpack("!H", payload[hs_start + 4:hs_start + 6])[0]

        # Session ID
        sid_offset = hs_start + 38
        if sid_offset >= len(payload):
            return ""
        sid_len = payload[sid_offset]

        # Cipher suites
        cs_offset = sid_offset + 1 + sid_len
        if cs_offset + 2 > len(payload):
            return ""
        cs_len = struct.unpack("!H", payload[cs_offset:cs_offset + 2])[0]

        ciphers = []
        for i in range(0, cs_len, 2):
            if cs_offset + 2 + i + 2 <= len(payload):
                cs = struct.unpack("!H", payload[cs_offset + 2 + i:cs_offset + 2 + i + 2])[0]
                # Skip GREASE values
                if (cs & 0x0F0F) != 0x0A0A:
                    ciphers.append(str(cs))

        ja3_str = f"{client_version},{'-'.join(ciphers)},,,"
        return hashlib.md5(ja3_str.encode()).hexdigest()  # noqa: S324

    except (struct.error, IndexError):
        return ""


def _extract_tls_version(payload: bytes) -> str:
    """Extract TLS version string from ClientHello."""
    if len(payload) < 10:
        return ""
    hs_start = 5
    try:
        ver = struct.unpack("!H", payload[hs_start + 4:hs_start + 6])[0]
        versions = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
        return versions.get(ver, f"0x{ver:04x}")
    except (struct.error, IndexError):
        return ""


def _format_mac(mac_bytes: bytes) -> str:
    """Format 6 bytes as a MAC address string."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _guess_os(ttl: int, window_size: int, mss: int) -> str:
    """Guess the OS/platform from TCP stack signature."""
    for os_name, sig in _TCP_SIGNATURES:
        if sig["ttl_min"] <= ttl <= sig["ttl_max"]:
            if sig["win_min"] <= window_size <= sig["win_max"]:
                return os_name

    # Fallback heuristics based on TTL alone
    if 60 <= ttl <= 64:
        return "Linux/Unix"
    if 120 <= ttl <= 128:
        return "Windows"
    if 250 <= ttl <= 255:
        return "Network Device"

    return "Unknown"


def _compute_confidence(fp: DeviceFingerprint) -> None:
    """Compute a confidence score for the fingerprint."""
    score = 0.0

    if fp.ttl > 0:
        score += 0.2
    if fp.tcp_window_size > 0:
        score += 0.15
    if fp.tcp_mss > 0:
        score += 0.1
    if fp.tcp_options:
        score += 0.1
    if fp.os_guess and fp.os_guess != "Unknown":
        score += 0.15
    if fp.ics_protocols:
        score += 0.2
    if fp.ja3:
        score += 0.1

    fp.confidence = min(score, 1.0)
    fp.method = "passive_tcp" + ("+ja3" if fp.ja3 else "") + ("+ics_payload" if fp.ics_protocols else "")
