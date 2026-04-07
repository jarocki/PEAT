"""
Firmware binary analysis and extraction for ICS/SCADA devices.

Scans firmware blobs for known magic signatures (VxWorks ESTFBINR,
SquashFS, JFFS2, CramFS, ELF) and extracts embedded filesystems
or configuration data.

@decision: Implements magic byte carving in pure Python rather than
shelling out to binwalk. This keeps the dependency footprint small and
avoids binwalk's GPL-3.0 license complications for downstream users.
The carving logic is intentionally simple — it finds known signatures
and extracts/decompresses the payload. For complex firmware with
nested layers, users should use binwalk separately and then feed
the extracted artifacts to `peat forensic` or `peat parse`.
"""

from __future__ import annotations

import io
import json
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from peat import config, log


# Magic byte signatures for embedded filesystems and formats
SIGNATURES: dict[str, bytes] = {
    "vxworks_estfbinr": b"ESTFBINR",
    "squashfs_le": b"hsqs",
    "squashfs_be": b"sqsh",
    "cramfs": b"\x45\x3d\xcd\x28",
    "jffs2_le": b"\x85\x19",
    "jffs2_be": b"\x19\x85",
    "elf": b"\x7fELF",
    "gzip": b"\x1f\x8b",
    "zlib_default": b"\x78\x9c",
    "zlib_best": b"\x78\x01",
    "zlib_no_compression": b"\x78\x01",
    "uimage": b"\x27\x05\x19\x56",  # U-Boot image header
    "cpio_newc": b"070701",
    "cpio_crc": b"070702",
}


@dataclass
class FirmwareRegion:
    """A detected region within a firmware binary."""

    signature_type: str
    offset: int
    size: int  # 0 if unknown
    description: str
    extracted_path: str = ""  # Path where extracted content was saved
    content_preview: str = ""  # First few bytes as hex for identification


@dataclass
class FirmwareAnalysisResult:
    """Results from analyzing a firmware binary."""

    firmware_path: str
    file_size: int
    regions: list[FirmwareRegion] = field(default_factory=list)
    extracted_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "firmware_analysis": {
                "firmware_path": self.firmware_path,
                "file_size": self.file_size,
                "regions_found": len(self.regions),
                "regions": [
                    {
                        "type": r.signature_type,
                        "offset": r.offset,
                        "size": r.size,
                        "description": r.description,
                        "extracted_path": r.extracted_path,
                        "content_preview": r.content_preview,
                    }
                    for r in self.regions
                ],
                "extracted_files": self.extracted_files,
                "errors": self.errors,
            }
        }


def analyze_firmware(
    firmware_path: Path,
    output_dir: Path | None = None,
    extract: bool = True,
) -> FirmwareAnalysisResult:
    """
    Analyze a firmware binary for embedded filesystems and data.

    Scans the binary for known magic signatures and attempts to extract
    embedded content (compressed payloads, filesystems, ELF binaries).

    Args:
        firmware_path: Path to the firmware binary.
        output_dir: Directory to save extracted content.
        extract: Whether to extract found regions to disk.

    Returns:
        FirmwareAnalysisResult with found regions and extraction results.
    """
    result = FirmwareAnalysisResult(
        firmware_path=str(firmware_path),
        file_size=firmware_path.stat().st_size,
    )

    if output_dir is None and config.RUN_DIR:
        output_dir = config.RUN_DIR / "firmware_extracted"
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    log.info(f"Scanning firmware binary: {firmware_path.name} ({result.file_size:,} bytes)")

    try:
        data = firmware_path.read_bytes()
    except OSError as e:
        error_msg = f"Failed to read firmware: {e}"
        log.error(error_msg)
        result.errors.append(error_msg)
        return result

    # Scan for all known signatures
    for sig_name, sig_bytes in SIGNATURES.items():
        offset = 0
        while True:
            idx = data.find(sig_bytes, offset)
            if idx == -1:
                break

            region = FirmwareRegion(
                signature_type=sig_name,
                offset=idx,
                size=0,
                description=_describe_signature(sig_name, data, idx),
                content_preview=data[idx : idx + 16].hex(),
            )

            log.info(f"Found {sig_name} signature at offset 0x{idx:08x}: {region.description}")
            result.regions.append(region)

            # Try to extract this region
            if extract and output_dir:
                _extract_region(data, region, output_dir, result)

            # Advance past this signature to find more
            offset = idx + len(sig_bytes)

    log.info(
        f"Firmware scan complete: found {len(result.regions)} regions, "
        f"extracted {len(result.extracted_files)} files"
    )

    # Write results
    if output_dir:
        results_path = output_dir / "firmware-analysis-results.json"
        try:
            results_path.write_text(json.dumps(result.to_dict(), indent=4))
        except OSError as e:
            log.warning(f"Failed to write results: {e}")

    return result


def _describe_signature(sig_name: str, data: bytes, offset: int) -> str:
    """Generate a human-readable description for a detected signature."""
    descriptions = {
        "vxworks_estfbinr": "VxWorks ESTFBINR firmware container",
        "squashfs_le": "SquashFS filesystem (little-endian)",
        "squashfs_be": "SquashFS filesystem (big-endian)",
        "cramfs": "CramFS compressed ROM filesystem",
        "jffs2_le": "JFFS2 filesystem (little-endian)",
        "jffs2_be": "JFFS2 filesystem (big-endian)",
        "elf": "ELF executable/library",
        "gzip": "gzip compressed data",
        "zlib_default": "zlib compressed data (default compression)",
        "zlib_best": "zlib compressed data (best compression)",
        "zlib_no_compression": "zlib compressed data (no compression)",
        "uimage": "U-Boot firmware image",
        "cpio_newc": "CPIO archive (newc format)",
        "cpio_crc": "CPIO archive (CRC format)",
    }

    desc = descriptions.get(sig_name, f"Unknown signature: {sig_name}")

    # Add ELF details if available
    if sig_name == "elf" and offset + 20 <= len(data):
        ei_class = data[offset + 4]
        ei_data = data[offset + 5]
        bits = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown")
        endian = {1: "little-endian", 2: "big-endian"}.get(ei_data, "unknown")
        desc = f"ELF executable ({bits}, {endian})"

    return desc


def _extract_region(
    data: bytes,
    region: FirmwareRegion,
    output_dir: Path,
    result: FirmwareAnalysisResult,
) -> None:
    """Attempt to extract content from a detected firmware region."""
    offset = region.offset

    try:
        if region.signature_type == "vxworks_estfbinr":
            _extract_vxworks(data, offset, output_dir, region, result)
        elif region.signature_type in ("gzip", "zlib_default", "zlib_best"):
            _extract_compressed(data, offset, region.signature_type, output_dir, region, result)
        elif region.signature_type == "elf":
            _extract_elf(data, offset, output_dir, region, result)
        elif region.signature_type in ("squashfs_le", "squashfs_be"):
            _extract_raw_region(data, offset, output_dir, region, result, "squashfs")
        elif region.signature_type == "cramfs":
            _extract_raw_region(data, offset, output_dir, region, result, "cramfs")
    except Exception as e:
        error_msg = f"Extraction failed for {region.signature_type} at 0x{offset:08x}: {e}"
        log.warning(error_msg)
        result.errors.append(error_msg)


def _extract_vxworks(
    data: bytes,
    offset: int,
    output_dir: Path,
    region: FirmwareRegion,
    result: FirmwareAnalysisResult,
) -> None:
    """
    Extract VxWorks ESTFBINR firmware container.

    ESTFBINR format: 8-byte magic, then typically zlib-compressed payload.
    """
    payload_start = offset + 8  # Skip "ESTFBINR"

    # Try to decompress the payload
    try:
        decompressed = zlib.decompress(data[payload_start:])
        out_path = output_dir / f"vxworks_0x{offset:08x}_decompressed.bin"
        out_path.write_bytes(decompressed)
        region.size = len(decompressed)
        region.extracted_path = str(out_path)
        result.extracted_files.append(str(out_path))
        log.info(f"Extracted VxWorks payload: {len(decompressed):,} bytes → {out_path.name}")
    except zlib.error:
        # Not zlib compressed — save raw payload
        # Estimate size: look for next known signature or use remaining data
        end = _find_next_signature(data, payload_start + 256)
        if end == -1:
            end = len(data)
        raw = data[payload_start:end]
        out_path = output_dir / f"vxworks_0x{offset:08x}_raw.bin"
        out_path.write_bytes(raw)
        region.size = len(raw)
        region.extracted_path = str(out_path)
        result.extracted_files.append(str(out_path))
        log.info(f"Saved raw VxWorks payload: {len(raw):,} bytes → {out_path.name}")


def _extract_compressed(
    data: bytes,
    offset: int,
    sig_type: str,
    output_dir: Path,
    region: FirmwareRegion,
    result: FirmwareAnalysisResult,
) -> None:
    """Extract zlib or gzip compressed data."""
    try:
        if sig_type == "gzip":
            decompressed = zlib.decompress(data[offset:], zlib.MAX_WBITS | 16)
        else:
            decompressed = zlib.decompress(data[offset:])

        out_path = output_dir / f"{sig_type}_0x{offset:08x}_decompressed.bin"
        out_path.write_bytes(decompressed)
        region.size = len(decompressed)
        region.extracted_path = str(out_path)
        result.extracted_files.append(str(out_path))
        log.debug(f"Decompressed {sig_type}: {len(decompressed):,} bytes → {out_path.name}")
    except zlib.error as e:
        log.trace(f"Decompression failed for {sig_type} at 0x{offset:08x}: {e}")


def _extract_elf(
    data: bytes,
    offset: int,
    output_dir: Path,
    region: FirmwareRegion,
    result: FirmwareAnalysisResult,
) -> None:
    """Extract an ELF binary from the firmware."""
    # ELF header contains the file size information
    if offset + 64 > len(data):
        return

    ei_class = data[offset + 4]

    if ei_class == 1:  # 32-bit
        if offset + 52 > len(data):
            return
        # e_shoff (section header offset) + e_shnum * e_shentsize gives approximate end
        e_shoff = struct.unpack_from("<I", data, offset + 32)[0]
        e_shnum = struct.unpack_from("<H", data, offset + 48)[0]
        e_shentsize = struct.unpack_from("<H", data, offset + 46)[0]
        elf_size = e_shoff + (e_shnum * e_shentsize)
    elif ei_class == 2:  # 64-bit
        if offset + 64 > len(data):
            return
        e_shoff = struct.unpack_from("<Q", data, offset + 40)[0]
        e_shnum = struct.unpack_from("<H", data, offset + 60)[0]
        e_shentsize = struct.unpack_from("<H", data, offset + 58)[0]
        elf_size = e_shoff + (e_shnum * e_shentsize)
    else:
        return

    if elf_size <= 0 or elf_size > len(data) - offset:
        elf_size = min(len(data) - offset, 10 * 1024 * 1024)  # Cap at 10MB

    elf_data = data[offset : offset + elf_size]
    out_path = output_dir / f"elf_0x{offset:08x}.bin"
    out_path.write_bytes(elf_data)
    region.size = elf_size
    region.extracted_path = str(out_path)
    result.extracted_files.append(str(out_path))
    log.debug(f"Extracted ELF: {elf_size:,} bytes → {out_path.name}")


def _extract_raw_region(
    data: bytes,
    offset: int,
    output_dir: Path,
    region: FirmwareRegion,
    result: FirmwareAnalysisResult,
    name: str,
) -> None:
    """
    Extract a raw filesystem region (SquashFS, CramFS, etc.).

    Saves from the signature to the next known signature or end of file.
    """
    end = _find_next_signature(data, offset + 256)
    if end == -1:
        end = len(data)

    region_data = data[offset:end]
    out_path = output_dir / f"{name}_0x{offset:08x}.img"
    out_path.write_bytes(region_data)
    region.size = len(region_data)
    region.extracted_path = str(out_path)
    result.extracted_files.append(str(out_path))
    log.debug(f"Extracted {name}: {len(region_data):,} bytes → {out_path.name}")


def _find_next_signature(data: bytes, start: int) -> int:
    """Find the offset of the next known signature after 'start'."""
    next_sig = -1
    for sig_bytes in SIGNATURES.values():
        idx = data.find(sig_bytes, start)
        if idx != -1 and (next_sig == -1 or idx < next_sig):
            next_sig = idx
    return next_sig
