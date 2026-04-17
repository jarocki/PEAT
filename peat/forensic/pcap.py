"""
Network packet capture analysis pipeline for ICS/SCADA protocols.

Implements a tiered PCAP processing pipeline:
  Stage 1 (Triage): dpkt for high-speed flow extraction and port identification
  Stage 2 (Deep dissection): scapy for ICS protocol parsing on identified flows

Supports: Modbus TCP, DNP3, EtherNet/IP (CIP), S7comm, BACnet, and
generic TCP/UDP flow analysis.

@decision: Uses dpkt for Stage 1 triage (250K+ pkts/sec) and scapy for
Stage 2 deep dissection. dpkt is ~50x faster than scapy for bulk packet
iteration but lacks ICS protocol awareness. scapy has contrib modules for
Modbus and EtherNet/IP but is too slow for full-capture processing. The
tiered approach gives us speed for triage and depth for ICS analysis.
pyshark (TShark wrapper) was considered for S7comm/BACnet/GOOSE but adds
a heavy external dependency; we use port-based identification instead and
defer deep dissection of those protocols to optional Zeek integration.
"""
# Copyright 2026 John Jarocki
# Developed with AI assistance from Claude Opus 4.6 (Anthropic)
#
# This file is part of PEAT and is licensed under GPL-3.0.
# See LICENSE for details.


from __future__ import annotations

import json
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from peat import config, log


# Well-known ICS protocol ports
ICS_PORTS: dict[int, str] = {
    102: "s7comm",
    502: "modbus_tcp",
    2222: "enip_io",
    4840: "opcua",
    4843: "opcua_tls",
    18245: "ge_srtp",
    20000: "dnp3",
    44818: "enip",
    47808: "bacnet",
}

# Additional ports for passive fingerprinting
SCADA_PORTS: dict[int, str] = {
    23: "telnet",
    80: "http",
    102: "s7comm",
    443: "https",
    502: "modbus_tcp",
    2222: "enip_io",
    2404: "iec104",
    4840: "opcua",
    20000: "dnp3",
    44818: "enip",
    47808: "bacnet",
}


@dataclass
class NetworkFlow:
    """A summarized network flow between two endpoints."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # tcp, udp
    ics_protocol: str = ""  # Detected ICS protocol
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class ICSEvent:
    """An ICS protocol event extracted from packet data."""

    timestamp: datetime | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    ics_protocol: str = ""
    function_code: int = 0
    function_name: str = ""
    unit_id: int = 0
    description: str = ""
    is_request: bool = True
    raw_payload: bytes = b""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ics_event": {
                "protocol": self.ics_protocol,
                "function_code": self.function_code,
                "function_name": self.function_name,
                "description": self.description,
                "is_request": self.is_request,
                "unit_id": self.unit_id,
            },
            "source": {"ip": self.src_ip, "port": self.src_port},
            "destination": {"ip": self.dst_ip, "port": self.dst_port},
        }
        if self.timestamp:
            result["@timestamp"] = self.timestamp.isoformat()
        if self.extra:
            result["extra"] = self.extra
        return result


@dataclass
class AssetRecord:
    """A device discovered via passive traffic analysis."""

    ip: str
    mac: str = ""
    hostname: str = ""
    protocols: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)  # e.g. "master", "slave", "hmi"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    packet_count: int = 0


@dataclass
class PcapAnalysisResult:
    """Results from analyzing a PCAP file."""

    pcap_path: str
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    flows: list[NetworkFlow] = field(default_factory=list)
    ics_events: list[ICSEvent] = field(default_factory=list)
    assets: list[AssetRecord] = field(default_factory=list)
    protocol_summary: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pcap_analysis": {
                "pcap_path": self.pcap_path,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_seconds": round(self.duration_seconds, 3),
                "ics_flows": len([f for f in self.flows if f.ics_protocol]),
                "total_flows": len(self.flows),
                "ics_events": len(self.ics_events),
                "assets_discovered": len(self.assets),
                "protocol_summary": self.protocol_summary,
                "errors": self.errors,
            }
        }


def analyze_pcap(
    pcap_path: Path,
    output_dir: Path | None = None,
    deep_dissect: bool = True,
    use_zeek: bool = True,
) -> PcapAnalysisResult:
    """
    Analyze a PCAP/PCAPNG file for ICS/SCADA traffic.

    Stage 1: Fast triage with dpkt — extract flows, identify ICS ports.
    Stage 2: Deep dissection with scapy — parse ICS protocol payloads.
    Stage 3 (optional): Zeek/ICSNPP for advanced ICS analysis + MITRE ATT&CK.

    Args:
        pcap_path: Path to PCAP or PCAPNG file.
        output_dir: Directory to write results.
        deep_dissect: Enable Stage 2 scapy-based ICS protocol parsing.
        use_zeek: Enable Stage 3 Zeek/ICSNPP analysis (if Zeek is installed).

    Returns:
        PcapAnalysisResult with flows, events, and asset inventory.
    """
    result = PcapAnalysisResult(pcap_path=str(pcap_path))

    if output_dir is None and config.RUN_DIR:
        output_dir = config.RUN_DIR / "forensic_pcap"
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Stage 1: Fast triage with dpkt
    log.info(f"Stage 1: Triaging PCAP with dpkt: {pcap_path.name}")
    flows, ics_packets = _stage1_triage(pcap_path, result)

    log.info(
        f"Triage complete: {result.total_packets:,} packets, "
        f"{len(flows):,} flows, {len(ics_packets):,} ICS packets identified"
    )

    # Stage 2: Deep ICS protocol dissection
    if deep_dissect and ics_packets:
        log.info(f"Stage 2: Deep dissecting {len(ics_packets):,} ICS packets with scapy")
        _stage2_dissect(ics_packets, result)
        log.info(f"Dissection complete: {len(result.ics_events):,} ICS events extracted")

    # Stage 3: Optional Zeek/ICSNPP analysis
    if use_zeek:
        from peat.forensic.zeek import analyze_with_zeek

        zeek_dir = output_dir / "zeek" if output_dir else None
        zeek_result = analyze_with_zeek(pcap_path, output_dir=zeek_dir)

        if zeek_result.zeek_available and zeek_result.ics_events:
            log.info(
                f"Stage 3: Zeek added {len(zeek_result.ics_events)} ICS events"
                f"{f', {len(zeek_result.mitre_techniques)} MITRE techniques' if zeek_result.mitre_techniques else ''}"
            )
            # Merge Zeek ICS events into result
            for zeek_event in zeek_result.ics_events:
                result.ics_events.append(ICSEvent(
                    ics_protocol=zeek_event.get("_zeek_log", "").replace(".log", ""),
                    description=json.dumps(zeek_event, default=str),
                    extra=zeek_event,
                ))

    # Build asset inventory from flows
    _build_asset_inventory(flows, result)
    log.info(f"Asset inventory: {len(result.assets)} devices discovered passively")

    # Passive device fingerprinting
    from peat.forensic.fingerprint import fingerprint_from_dpkt_pcap

    fingerprints = fingerprint_from_dpkt_pcap(pcap_path)
    if fingerprints:
        # Enrich assets with fingerprint data
        for asset in result.assets:
            if asset.ip in fingerprints:
                fp = fingerprints[asset.ip]
                if fp.os_guess:
                    asset.roles.add(f"os:{fp.os_guess}")
                asset.protocols.update(fp.ics_protocols)

    # Write results
    if output_dir:
        _write_results(result, output_dir)
        if fingerprints:
            _write_fingerprints(fingerprints, output_dir)

    return result


def _stage1_triage(
    pcap_path: Path,
    result: PcapAnalysisResult,
) -> tuple[dict[str, NetworkFlow], list[tuple[float, bytes, str, str, int, int]]]:
    """
    Stage 1: Fast packet triage using dpkt.

    Returns:
        Tuple of (flows_dict, ics_packets_list).
        ics_packets_list contains (timestamp, payload, src_ip, dst_ip, src_port, dst_port).
    """
    import dpkt

    flows: dict[str, NetworkFlow] = {}
    ics_packets: list[tuple[float, bytes, str, str, int, int]] = []

    try:
        with open(pcap_path, "rb") as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                reader = dpkt.pcapng.Reader(f)

            first_ts = None
            last_ts = None

            for ts, buf in reader:
                result.total_packets += 1
                result.total_bytes += len(buf)

                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                # Parse Ethernet frame
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.NeedData, dpkt.UnpackError):
                    continue

                if not isinstance(eth.data, dpkt.ip.IP):
                    continue

                ip = eth.data
                src_ip = _inet_ntoa(ip.src)
                dst_ip = _inet_ntoa(ip.dst)

                if isinstance(ip.data, dpkt.tcp.TCP):
                    transport = ip.data
                    proto = "tcp"
                elif isinstance(ip.data, dpkt.udp.UDP):
                    transport = ip.data
                    proto = "udp"
                else:
                    continue

                src_port = transport.sport
                dst_port = transport.dport

                # Build flow key (bidirectional)
                flow_key = _flow_key(src_ip, dst_ip, src_port, dst_port, proto)
                pkt_time = datetime.fromtimestamp(ts, tz=timezone.utc)

                if flow_key not in flows:
                    ics_proto = _identify_ics_protocol(src_port, dst_port)
                    flows[flow_key] = NetworkFlow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        ics_protocol=ics_proto,
                        first_seen=pkt_time,
                    )
                    if ics_proto:
                        result.protocol_summary[ics_proto] = (
                            result.protocol_summary.get(ics_proto, 0) + 1
                        )

                flow = flows[flow_key]
                flow.packet_count += 1
                flow.byte_count += len(buf)
                flow.last_seen = pkt_time

                # Collect ICS packets for Stage 2
                payload = bytes(transport.data)
                if payload and flow.ics_protocol:
                    ics_packets.append((ts, payload, src_ip, dst_ip, src_port, dst_port))

            if first_ts and last_ts:
                result.duration_seconds = last_ts - first_ts

    except Exception as e:
        error_msg = f"dpkt triage failed: {e}"
        log.error(error_msg)
        result.errors.append(error_msg)

    result.flows = list(flows.values())
    return flows, ics_packets


def _stage2_dissect(
    ics_packets: list[tuple[float, bytes, str, str, int, int]],
    result: PcapAnalysisResult,
) -> None:
    """
    Stage 2: Deep ICS protocol dissection using scapy and manual parsing.

    Parses Modbus TCP, DNP3, and EtherNet/IP payloads from collected packets.
    """
    for ts, payload, src_ip, dst_ip, src_port, dst_port in ics_packets:
        timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)
        ics_proto = _identify_ics_protocol(src_port, dst_port)

        events: list[ICSEvent] = []
        if ics_proto == "modbus_tcp":
            events = _dissect_modbus(payload, timestamp, src_ip, dst_ip, src_port, dst_port)
        elif ics_proto == "dnp3":
            events = _dissect_dnp3(payload, timestamp, src_ip, dst_ip, src_port, dst_port)
        elif ics_proto in ("enip", "enip_io"):
            events = _dissect_enip(payload, timestamp, src_ip, dst_ip, src_port, dst_port)
        elif ics_proto:
            # Port-identified but no deep parser — record as generic ICS event
            events = [ICSEvent(
                timestamp=timestamp,
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                ics_protocol=ics_proto,
                description=f"{ics_proto} traffic ({len(payload)} bytes)",
            )]

        result.ics_events.extend(events)


# -- Protocol dissectors --

_MODBUS_FUNCTIONS: dict[int, str] = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}


def _dissect_modbus(
    payload: bytes, timestamp: datetime,
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
) -> list[ICSEvent]:
    """Parse Modbus TCP/IP payload (MBAP header + PDU)."""
    if len(payload) < 8:  # MBAP header is 7 bytes + at least 1 byte PDU
        return []

    # MBAP Header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
    try:
        transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
    except struct.error:
        return []

    if protocol_id != 0:  # Modbus protocol ID is always 0
        return []

    function_code = payload[7] if len(payload) > 7 else 0
    is_exception = function_code >= 0x80
    actual_fc = function_code - 0x80 if is_exception else function_code
    fc_name = _MODBUS_FUNCTIONS.get(actual_fc, f"FC {actual_fc}")
    is_request = dst_port == 502

    desc = f"{'Exception: ' if is_exception else ''}{fc_name}"
    if is_exception and len(payload) > 8:
        desc += f" (exception code: {payload[8]})"

    extra: dict[str, Any] = {"transaction_id": transaction_id}

    # Extract register addresses for read/write functions
    if not is_exception and len(payload) >= 12 and actual_fc in (1, 2, 3, 4, 5, 6, 15, 16):
        start_addr = struct.unpack(">H", payload[8:10])[0]
        quantity = struct.unpack(">H", payload[10:12])[0]
        extra["start_address"] = start_addr
        extra["quantity"] = quantity
        desc += f" addr={start_addr} qty={quantity}"

    return [ICSEvent(
        timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ics_protocol="modbus_tcp",
        function_code=actual_fc,
        function_name=fc_name,
        unit_id=unit_id,
        description=desc,
        is_request=is_request,
        extra=extra,
    )]


_DNP3_FUNCTIONS: dict[int, str] = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate No Ack",
    0x81: "Response",
    0x82: "Unsolicited Response",
}


def _dissect_dnp3(
    payload: bytes, timestamp: datetime,
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
) -> list[ICSEvent]:
    """Parse DNP3 over TCP payload (start bytes + header)."""
    if len(payload) < 10:
        return []

    # DNP3 start bytes: 0x0564
    if payload[0:2] != b"\x05\x64":
        return []

    length = payload[2]
    control = payload[3]
    dst_addr = struct.unpack("<H", payload[4:6])[0]
    src_addr = struct.unpack("<H", payload[6:8])[0]

    # Data link header is 10 bytes: start(2) + len(1) + ctrl(1) + dst(2) + src(2) + crc(2)
    # Transport header at [10], app control at [11], function code at [12]
    if len(payload) < 13:
        return []

    # Transport header is 1 byte, then application control + function code
    function_code = payload[12]
    fc_name = _DNP3_FUNCTIONS.get(function_code, f"FC 0x{function_code:02x}")
    is_request = function_code < 0x80

    return [ICSEvent(
        timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ics_protocol="dnp3",
        function_code=function_code,
        function_name=fc_name,
        unit_id=dst_addr,
        description=f"{fc_name} (src_addr={src_addr}, dst_addr={dst_addr})",
        is_request=is_request,
        extra={"src_address": src_addr, "dst_address": dst_addr, "dnp3_length": length},
    )]


def _dissect_enip(
    payload: bytes, timestamp: datetime,
    src_ip: str, dst_ip: str, src_port: int, dst_port: int,
) -> list[ICSEvent]:
    """Parse EtherNet/IP encapsulation header."""
    if len(payload) < 24:  # ENIP header is 24 bytes
        return []

    _ENIP_COMMANDS: dict[int, str] = {
        0x0001: "ListTargets",
        0x0004: "ListServices",
        0x0063: "ListIdentity",
        0x0064: "ListInterfaces",
        0x0065: "RegisterSession",
        0x0066: "UnregisterSession",
        0x006F: "SendRRData",
        0x0070: "SendUnitData",
    }

    try:
        command = struct.unpack("<H", payload[0:2])[0]
        length = struct.unpack("<H", payload[2:4])[0]
        session_handle = struct.unpack("<I", payload[4:8])[0]
    except struct.error:
        return []

    cmd_name = _ENIP_COMMANDS.get(command, f"Cmd 0x{command:04x}")

    return [ICSEvent(
        timestamp=timestamp,
        src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        ics_protocol="enip",
        function_code=command,
        function_name=cmd_name,
        description=f"{cmd_name} (session=0x{session_handle:08x}, len={length})",
        is_request=dst_port == 44818,
        extra={"session_handle": session_handle, "enip_length": length},
    )]


# -- Utility functions --

def _inet_ntoa(packed: bytes) -> str:
    """Convert packed 4-byte IP to dotted notation."""
    return ".".join(str(b) for b in packed[:4])


def _flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    """Create a bidirectional flow key."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a > b:
        a, b = b, a
    return f"{proto}:{a[0]}:{a[1]}-{b[0]}:{b[1]}"


def _identify_ics_protocol(src_port: int, dst_port: int) -> str:
    """Identify ICS protocol by port number."""
    if dst_port in ICS_PORTS:
        return ICS_PORTS[dst_port]
    if src_port in ICS_PORTS:
        return ICS_PORTS[src_port]
    return ""


def _build_asset_inventory(
    flows: dict[str, NetworkFlow],
    result: PcapAnalysisResult,
) -> None:
    """Build a passive asset inventory from observed network flows."""
    assets: dict[str, AssetRecord] = {}

    for flow in flows.values():
        for ip, port, role in [
            (flow.src_ip, flow.src_port, "client"),
            (flow.dst_ip, flow.dst_port, "server"),
        ]:
            if ip not in assets:
                assets[ip] = AssetRecord(ip=ip, first_seen=flow.first_seen)

            asset = assets[ip]
            asset.ports.add(port)
            asset.packet_count += flow.packet_count
            if flow.ics_protocol:
                asset.protocols.add(flow.ics_protocol)
                asset.roles.add(role)
            if flow.last_seen and (not asset.last_seen or flow.last_seen > asset.last_seen):
                asset.last_seen = flow.last_seen

    result.assets = list(assets.values())


def _write_results(result: PcapAnalysisResult, output_dir: Path) -> None:
    """Write PCAP analysis results to files."""
    # Summary
    summary_path = output_dir / "pcap-analysis-summary.json"
    try:
        summary_path.write_text(json.dumps(result.to_dict(), indent=4))
    except OSError as e:
        log.warning(f"Failed to write summary: {e}")

    # ICS events as NDJSON
    if result.ics_events:
        events_path = output_dir / "ics-events.ndjson"
        try:
            with open(events_path, "w") as f:
                for event in result.ics_events:
                    f.write(json.dumps(event.to_dict(), default=str) + "\n")
            log.debug(f"ICS events: {events_path} ({len(result.ics_events)} events)")
        except OSError as e:
            log.warning(f"Failed to write events: {e}")

    # Asset inventory
    if result.assets:
        assets_path = output_dir / "asset-inventory.json"
        try:
            inventory = [
                {
                    "ip": a.ip,
                    "protocols": sorted(a.protocols),
                    "ports": sorted(a.ports),
                    "roles": sorted(a.roles),
                    "packet_count": a.packet_count,
                    "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None,
                }
                for a in result.assets
            ]
            assets_path.write_text(json.dumps(inventory, indent=4))
            log.debug(f"Asset inventory: {assets_path} ({len(inventory)} devices)")
        except OSError as e:
            log.warning(f"Failed to write inventory: {e}")


def _write_fingerprints(
    fingerprints: dict[str, Any], output_dir: Path
) -> None:
    """Write device fingerprints to a JSON file."""
    fp_path = output_dir / "device-fingerprints.json"
    try:
        data = [fp.to_dict() for fp in fingerprints.values()]
        fp_path.write_text(json.dumps(data, indent=4))
        log.debug(f"Fingerprints: {fp_path} ({len(data)} devices)")
    except OSError as e:
        log.warning(f"Failed to write fingerprints: {e}")
