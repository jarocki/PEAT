"""
Security-focused tests for forensic analysis code.

Tests cover:
- Path traversal prevention in disk image extraction
- Decompression bomb detection in firmware analysis
- Input validation in Zeek integration

@decision DEC-SEC-003
@title Security regression tests for forensic modules
@status accepted
@rationale These tests verify that security hardening measures remain
    effective. Path traversal, decompression bombs, and input validation
    are attack vectors specific to forensic tooling that processes
    untrusted disk images, firmware blobs, and network captures.
    Tests use real implementations (not mocks) for security-critical paths.
"""
# Copyright 2026 John Jarocki
# Developed with AI assistance from Claude Opus 4.6 (Anthropic)
#
# This file is part of PEAT and is licensed under GPL-3.0.
# See LICENSE for details.

# @mock-exempt: dissect.target filesystem is an external forensic library boundary —
# creating real E01/VMDK disk images in tests requires large binary fixtures and the
# full dissect framework. MagicMock is used only for the fs parameter (external boundary).
from __future__ import annotations

import io
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from peat.forensic.image import ExtractedArtifact, _extract_artifact


def _make_stub_fs(content: bytes = b"stub content") -> MagicMock:
    """Build a stub for dissect's filesystem object (external boundary).

    # @mock-exempt: dissect.target filesystem — external forensic library.
    # Creating real E01/VMDK images in tests requires large binary fixtures
    # and the full dissect framework. The fs object is the external boundary
    # between PEAT's extraction logic and the forensic container library.
    """
    fs = MagicMock()
    entry = MagicMock()
    entry.open.return_value.__enter__ = lambda s: s
    entry.open.return_value.__exit__ = MagicMock(return_value=False)
    entry.open.return_value.read.return_value = content
    fs.path.return_value = entry
    return fs


class TestPathTraversal:
    """Test path traversal prevention in image.py."""

    def test_dotdot_in_virtual_path_is_blocked(self, tmp_path: Path) -> None:
        """Extraction with ../.. in path must not escape output_dir."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        artifact = ExtractedArtifact(
            virtual_path="../../etc/passwd",
            file_name="passwd",
            file_size=0,
            matched_module="test",
            matched_pattern="*",
        )

        # fs is never accessed — function returns early on traversal detection
        stub_fs = _make_stub_fs()
        result = _extract_artifact(stub_fs, "../../etc/passwd", artifact, output_dir)

        # Should NOT have written outside output_dir
        assert not (tmp_path / "etc" / "passwd").exists()
        # output_path should remain empty — extraction was blocked
        assert result.output_path == ""

    def test_dotdot_nested_in_path_is_blocked(self, tmp_path: Path) -> None:
        """Paths like 'foo/../../etc/passwd' must also be blocked."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        artifact = ExtractedArtifact(
            virtual_path="subdir/../../etc/shadow",
            file_name="shadow",
            file_size=0,
            matched_module="test",
            matched_pattern="*",
        )

        stub_fs = _make_stub_fs()
        result = _extract_artifact(stub_fs, "subdir/../../etc/shadow", artifact, output_dir)

        assert not (tmp_path / "etc" / "shadow").exists()
        assert result.output_path == ""

    def test_absolute_path_stays_within_output_dir(self, tmp_path: Path) -> None:
        """Absolute paths should be made relative and stay inside output_dir."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        artifact = ExtractedArtifact(
            virtual_path="/etc/config.txt",
            file_name="config.txt",
            file_size=0,
            matched_module="test",
            matched_pattern="*.txt",
        )

        stub_fs = _make_stub_fs(b"safe content")
        result = _extract_artifact(stub_fs, "/etc/config.txt", artifact, output_dir)

        # If extraction succeeded, file must be within output_dir
        if result.output_path:
            assert Path(result.output_path).resolve().is_relative_to(output_dir.resolve())

    def test_normal_path_extracts_successfully(self, tmp_path: Path) -> None:
        """A normal safe path should extract without issues."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        artifact = ExtractedArtifact(
            virtual_path="/data/config.rdb",
            file_name="config.rdb",
            file_size=0,
            matched_module="test",
            matched_pattern="*.rdb",
        )

        stub_fs = _make_stub_fs(b"rdb file content")
        result = _extract_artifact(stub_fs, "/data/config.rdb", artifact, output_dir)

        assert result.output_path != ""
        extracted = Path(result.output_path)
        assert extracted.exists()
        assert extracted.read_bytes() == b"rdb file content"
        assert extracted.resolve().is_relative_to(output_dir.resolve())


class TestDecompressionBomb:
    """Test decompression bomb detection in firmware.py."""

    def test_safe_decompress_rejects_bomb(self) -> None:
        """A highly compressed payload exceeding limits should return None."""
        from peat.forensic.firmware import _safe_decompress

        # Create a "bomb": compress zeros (extreme ratio)
        bomb_data = zlib.compress(b"\x00" * (10 * 1024 * 1024))

        # With a very low limit, it should reject
        with patch("peat.forensic.firmware._MAX_DECOMPRESS_SIZE", 1024):
            result = _safe_decompress(bomb_data)
            assert result is None

    def test_safe_decompress_allows_normal_data(self) -> None:
        """Normal compressed data should decompress successfully."""
        from peat.forensic.firmware import _safe_decompress

        # Normal data
        original = b"Hello, forensic analysis! " * 100
        compressed = zlib.compress(original)

        result = _safe_decompress(compressed)
        assert result == original

    def test_safe_decompress_handles_gzip(self) -> None:
        """Gzip-wrapped data should also decompress successfully."""
        import gzip

        from peat.forensic.firmware import _safe_decompress

        original = b"Gzip compressed forensic data " * 50
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(original)
        compressed = buf.getvalue()

        result = _safe_decompress(compressed, wbits=zlib.MAX_WBITS | 16)
        assert result == original

    def test_safe_decompress_rejects_high_ratio(self) -> None:
        """A payload with suspiciously high compression ratio should be rejected."""
        from peat.forensic.firmware import _safe_decompress

        # Compress zeros — very high ratio
        bomb_data = zlib.compress(b"\x00" * (1024 * 1024))

        # Set ratio limit very low to trigger
        with patch("peat.forensic.firmware._MAX_DECOMPRESS_RATIO", 2):
            result = _safe_decompress(bomb_data)
            assert result is None

    def test_analyze_firmware_with_bomb_does_not_crash(self, tmp_path: Path) -> None:
        """Full firmware analysis with a decompression bomb should handle it gracefully."""
        from peat.forensic.firmware import analyze_firmware

        # Create a firmware binary with VxWorks header + bomb payload
        bomb_payload = zlib.compress(b"\x00" * (10 * 1024 * 1024))
        data = b"ESTFBINR" + bomb_payload
        fw = tmp_path / "bomb_firmware.bin"
        fw.write_bytes(data)

        # With a low limit, it should not crash but handle gracefully
        with patch("peat.forensic.firmware._MAX_DECOMPRESS_SIZE", 1024):
            result = analyze_firmware(fw, output_dir=tmp_path / "out")

        # Should have found the VxWorks signature
        assert len(result.regions) >= 1
        # Should not have crashed — result is returned
        assert result.firmware_path == str(fw)


class TestSubprocessValidation:
    """Test subprocess input validation in zeek.py."""

    def test_missing_pcap_returns_error(self, tmp_path: Path) -> None:
        """Zeek should not be invoked with non-existent PCAP."""
        from peat.forensic.zeek import ZeekAnalysisResult, _run_zeek

        result = ZeekAnalysisResult()
        output_dir = tmp_path / "zeek_output"
        output_dir.mkdir()

        success = _run_zeek(
            "/usr/bin/zeek",
            tmp_path / "nonexistent.pcap",
            output_dir,
            result,
        )

        assert success is False
        assert any("not found" in e for e in result.errors)

    def test_existing_file_does_not_trigger_validation_error(self, tmp_path: Path) -> None:
        """A file that exists should pass the validation check (even if Zeek fails)."""
        from peat.forensic.zeek import ZeekAnalysisResult, _run_zeek

        result = ZeekAnalysisResult()
        output_dir = tmp_path / "zeek_output"
        output_dir.mkdir()

        # Create a dummy PCAP file (Zeek will fail to parse it, but
        # the validation check should pass)
        pcap = tmp_path / "test.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        _run_zeek(
            "/usr/bin/zeek",
            pcap,
            output_dir,
            result,
        )

        # The validation should pass — errors should NOT contain "not found"
        assert not any("not found" in e for e in result.errors)
