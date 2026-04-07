"""
Tests for forensic input type detection.

@decision: Tests cover both extension-based and magic-byte-based detection paths.
Magic byte tests use minimal synthetic headers rather than real forensic images
to keep the test suite fast and avoid shipping large binary fixtures.
"""

from pathlib import Path

import pytest

from peat.forensic import ForensicInputType, detect_input_type


class TestDetectInputType:
    """Tests for detect_input_type function."""

    def test_disk_image_by_extension(self, tmp_path: Path) -> None:
        for ext in [".e01", ".dd", ".raw", ".img", ".vmdk", ".vhd", ".vhdx", ".qcow2"]:
            f = tmp_path / f"evidence{ext}"
            f.write_bytes(b"\x00" * 32)
            assert detect_input_type(f) == ForensicInputType.DISK_IMAGE

    def test_pcap_by_extension(self, tmp_path: Path) -> None:
        for ext in [".pcap", ".pcapng", ".cap"]:
            f = tmp_path / f"capture{ext}"
            f.write_bytes(b"\x00" * 32)
            assert detect_input_type(f) == ForensicInputType.PCAP

    def test_log_by_extension(self, tmp_path: Path) -> None:
        for ext in [".log", ".csv", ".txt", ".xml", ".ser"]:
            f = tmp_path / f"events{ext}"
            f.write_bytes(b"\x00" * 32)
            assert detect_input_type(f) == ForensicInputType.LOG_FILE

    def test_firmware_by_extension(self, tmp_path: Path) -> None:
        for ext in [".bin", ".fw", ".rom", ".spi", ".elf", ".hex"]:
            f = tmp_path / f"firmware{ext}"
            f.write_bytes(b"\x00" * 32)
            assert detect_input_type(f) == ForensicInputType.FIRMWARE

    def test_directory_detected(self, tmp_path: Path) -> None:
        assert detect_input_type(tmp_path) == ForensicInputType.LOG_DIRECTORY

    def test_pcap_magic_le(self, tmp_path: Path) -> None:
        """PCAP little-endian magic: 0xd4c3b2a1."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 28)
        assert detect_input_type(f) == ForensicInputType.PCAP

    def test_pcap_magic_be(self, tmp_path: Path) -> None:
        """PCAP big-endian magic: 0xa1b2c3d4."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 28)
        assert detect_input_type(f) == ForensicInputType.PCAP

    def test_pcapng_magic(self, tmp_path: Path) -> None:
        """PCAPNG Section Header Block magic."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 28)
        assert detect_input_type(f) == ForensicInputType.PCAP

    def test_e01_magic(self, tmp_path: Path) -> None:
        """E01 (EnCase) magic bytes."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 24)
        assert detect_input_type(f) == ForensicInputType.DISK_IMAGE

    def test_vxworks_estfbinr_magic(self, tmp_path: Path) -> None:
        """VxWorks ESTFBINR signature."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"ESTFBINR" + b"\x00" * 24)
        assert detect_input_type(f) == ForensicInputType.FIRMWARE

    def test_elf_magic(self, tmp_path: Path) -> None:
        """ELF binary magic."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"\x7fELF" + b"\x00" * 28)
        assert detect_input_type(f) == ForensicInputType.FIRMWARE

    def test_vmdk_magic(self, tmp_path: Path) -> None:
        """VMDK sparse header magic."""
        f = tmp_path / "unknown.dat"
        f.write_bytes(b"KDMV" + b"\x00" * 28)
        assert detect_input_type(f) == ForensicInputType.DISK_IMAGE

    def test_unknown_falls_through(self, tmp_path: Path) -> None:
        """Unknown extension + unknown magic -> UNKNOWN."""
        f = tmp_path / "mystery.xyz"
        f.write_bytes(b"not a known format header!!")
        assert detect_input_type(f) == ForensicInputType.UNKNOWN

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty file with unknown extension -> UNKNOWN."""
        f = tmp_path / "empty.xyz"
        f.write_bytes(b"")
        assert detect_input_type(f) == ForensicInputType.UNKNOWN

    def test_small_file(self, tmp_path: Path) -> None:
        """File too small for magic detection -> UNKNOWN."""
        f = tmp_path / "tiny.xyz"
        f.write_bytes(b"\x00\x01")
        assert detect_input_type(f) == ForensicInputType.UNKNOWN
