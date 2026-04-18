"""
PEAT Forensic Module — Passive forensic analysis of OT/ICS artifacts.

Provides three capabilities:
  - Disk image analysis (E01, dd, VMDK, VHD) with embedded filesystem extraction
  - ICS/SCADA log file parsing (vendor-specific formats, historian exports)
  - Network packet capture analysis (PCAP/PCAPNG with ICS protocol dissection)

All operations are read-only and maintain forensic integrity via cryptographic
hashing and chain-of-custody metadata.

@decision: Created as a top-level package under peat/ rather than extending
existing modules (pillage/heat/parse) because: (1) forensic operations have
fundamentally different input sources (files vs live devices), (2) forensic
integrity requirements (hashing, chain of custody) are cross-cutting concerns
that don't fit neatly into any single existing module, (3) keeps active and
passive capabilities cleanly separated for users who need forensic-grade analysis.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from peat import log

log.warning("Forensic module is experimental and AI-assisted. Verify results independently.")


class ForensicInputType(Enum):
    """Types of forensic input that PEAT can process."""

    DISK_IMAGE = "disk_image"
    LOG_FILE = "log_file"
    LOG_DIRECTORY = "log_directory"
    PCAP = "pcap"
    FIRMWARE = "firmware"
    UNKNOWN = "unknown"


# Known file extensions for input type detection
_IMAGE_EXTENSIONS = {".e01", ".dd", ".raw", ".img", ".vmdk", ".vhd", ".vhdx", ".qcow2"}
_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
_LOG_EXTENSIONS = {".log", ".csv", ".txt", ".xml", ".cev", ".evt", ".evtx", ".ser"}
_FIRMWARE_EXTENSIONS = {".bin", ".fw", ".rom", ".spi", ".elf", ".hex"}


def detect_input_type(path: Path) -> ForensicInputType:
    """
    Auto-detect the type of forensic input based on file extension and magic bytes.

    Args:
        path: Path to the input file or directory.

    Returns:
        The detected ForensicInputType.
    """
    if path.is_dir():
        return ForensicInputType.LOG_DIRECTORY

    suffix = path.suffix.lower()

    if suffix in _IMAGE_EXTENSIONS:
        return ForensicInputType.DISK_IMAGE
    if suffix in _PCAP_EXTENSIONS:
        return ForensicInputType.PCAP
    if suffix in _FIRMWARE_EXTENSIONS:
        return ForensicInputType.FIRMWARE
    if suffix in _LOG_EXTENSIONS:
        return ForensicInputType.LOG_FILE

    # Fall back to magic byte detection for ambiguous extensions
    return _detect_by_magic(path)


def _detect_by_magic(path: Path) -> ForensicInputType:
    """
    Detect input type by reading magic bytes from the file header.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except (OSError, PermissionError) as e:
        log.warning(f"Cannot read file header for type detection: {e}")
        return ForensicInputType.UNKNOWN

    if len(header) < 4:
        return ForensicInputType.UNKNOWN

    # E01 (EnCase) magic: "EVF\x09\x0d\x0a\xff\x00"
    if header[:5] == b"EVF\x09\x0d":
        return ForensicInputType.DISK_IMAGE

    # PCAP magic: 0xa1b2c3d4 or 0xd4c3b2a1 (swapped)
    if header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        return ForensicInputType.PCAP

    # PCAPNG magic: 0x0a0d0d0a (Section Header Block)
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        return ForensicInputType.PCAP

    # VxWorks ESTFBINR signature
    if header[:8] == b"ESTFBINR":
        return ForensicInputType.FIRMWARE

    # ELF binary
    if header[:4] == b"\x7fELF":
        return ForensicInputType.FIRMWARE

    # VMDK sparse header: "KDMV"
    if header[:4] == b"KDMV":
        return ForensicInputType.DISK_IMAGE

    return ForensicInputType.UNKNOWN
