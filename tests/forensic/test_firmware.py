"""
Tests for firmware binary analysis and extraction.

@decision: Tests create synthetic firmware blobs with known signatures
rather than using real device firmware. This avoids licensing issues
with vendor firmware and keeps the test suite fast and self-contained.
"""

import struct
import zlib
from pathlib import Path

import pytest

from peat.forensic.firmware import (
    SIGNATURES,
    FirmwareAnalysisResult,
    FirmwareRegion,
    analyze_firmware,
)


class TestSignatureDetection:
    """Tests for magic byte detection in firmware binaries."""

    def test_detect_vxworks_estfbinr(self, tmp_path: Path) -> None:
        """Detect VxWorks ESTFBINR signature."""
        payload = zlib.compress(b"VxWorks configuration data here")
        data = b"ESTFBINR" + payload
        fw = tmp_path / "firmware.bin"
        fw.write_bytes(data)

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        assert len(result.regions) >= 1
        vxworks_regions = [r for r in result.regions if r.signature_type == "vxworks_estfbinr"]
        assert len(vxworks_regions) == 1
        assert vxworks_regions[0].offset == 0

    def test_detect_elf(self, tmp_path: Path) -> None:
        """Detect ELF binary signature."""
        # Minimal 32-bit ELF header
        elf_header = b"\x7fELF"
        elf_header += b"\x01"  # 32-bit
        elf_header += b"\x01"  # little-endian
        elf_header += b"\x01"  # ELF version
        elf_header += b"\x00" * 9  # padding
        elf_header += b"\x02\x00"  # ET_EXEC
        elf_header += b"\x00" * 14  # rest of header
        elf_header += struct.pack("<I", 52)  # e_shoff
        elf_header += b"\x00" * 8  # flags, ehsize, phentsize
        elf_header += b"\x00\x00"  # phnum
        elf_header += struct.pack("<H", 40)  # e_shentsize
        elf_header += struct.pack("<H", 1)  # e_shnum
        elf_header += b"\x00" * (92 - len(elf_header))  # pad to expected size

        fw = tmp_path / "firmware.elf"
        fw.write_bytes(elf_header)

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        elf_regions = [r for r in result.regions if r.signature_type == "elf"]
        assert len(elf_regions) == 1
        assert "ELF" in elf_regions[0].description

    def test_detect_squashfs(self, tmp_path: Path) -> None:
        """Detect SquashFS signature."""
        # hsqs magic followed by dummy data
        data = b"\x00" * 100 + b"hsqs" + b"\x00" * 100
        fw = tmp_path / "firmware.bin"
        fw.write_bytes(data)

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        squash_regions = [r for r in result.regions if r.signature_type == "squashfs_le"]
        assert len(squash_regions) == 1
        assert squash_regions[0].offset == 100

    def test_detect_multiple_signatures(self, tmp_path: Path) -> None:
        """Detect multiple signatures in a single binary."""
        data = b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 93  # ELF
        data += b"ESTFBINR" + zlib.compress(b"payload")  # VxWorks
        fw = tmp_path / "combo.bin"
        fw.write_bytes(data)

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        types = {r.signature_type for r in result.regions}
        assert "elf" in types
        assert "vxworks_estfbinr" in types

    def test_no_signatures_found(self, tmp_path: Path) -> None:
        """Binary with no known signatures."""
        fw = tmp_path / "random.bin"
        fw.write_bytes(b"\xde\xad\xbe\xef" * 100)

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        assert len(result.regions) == 0


class TestVxWorksExtraction:
    """Tests for VxWorks ESTFBINR extraction."""

    def test_extract_zlib_payload(self, tmp_path: Path) -> None:
        """Extract and decompress zlib payload from ESTFBINR container."""
        original = b"This is VxWorks configuration data for a PLC"
        compressed = zlib.compress(original)
        fw = tmp_path / "vxworks.bin"
        fw.write_bytes(b"ESTFBINR" + compressed)

        out_dir = tmp_path / "extracted"
        result = analyze_firmware(fw, output_dir=out_dir)

        assert len(result.extracted_files) >= 1
        # Read back the extracted file
        extracted_path = Path(result.extracted_files[0])
        assert extracted_path.exists()
        assert extracted_path.read_bytes() == original

    def test_extract_raw_payload(self, tmp_path: Path) -> None:
        """Extract raw (non-compressed) ESTFBINR payload."""
        raw_payload = b"\x00\x01\x02\x03" * 100  # Not valid zlib
        fw = tmp_path / "vxworks_raw.bin"
        fw.write_bytes(b"ESTFBINR" + raw_payload)

        out_dir = tmp_path / "extracted"
        result = analyze_firmware(fw, output_dir=out_dir)

        vxworks_regions = [r for r in result.regions if r.signature_type == "vxworks_estfbinr"]
        assert len(vxworks_regions) == 1
        assert len(result.extracted_files) >= 1


class TestAnalysisResult:
    """Tests for result serialization."""

    def test_result_to_dict(self, tmp_path: Path) -> None:
        fw = tmp_path / "test.bin"
        fw.write_bytes(b"ESTFBINR" + zlib.compress(b"data"))

        result = analyze_firmware(fw, output_dir=tmp_path / "out")
        d = result.to_dict()

        assert "firmware_analysis" in d
        fa = d["firmware_analysis"]
        assert fa["file_size"] > 0
        assert fa["regions_found"] >= 1
        assert isinstance(fa["regions"], list)

    def test_empty_file(self, tmp_path: Path) -> None:
        fw = tmp_path / "empty.bin"
        fw.write_bytes(b"")

        result = analyze_firmware(fw, output_dir=tmp_path / "out")

        assert result.file_size == 0
        assert len(result.regions) == 0
