"""
Tests for forensic disk image analysis.

@decision: Tests focus on the pattern matching and artifact collection logic
rather than actual disk image parsing, since creating valid E01/VMDK images
in tests would require large fixtures. The dissect framework's own tests
validate container/filesystem parsing. We test the PEAT-specific logic:
ICS pattern collection, file matching, result serialization, and the
extraction workflow. The fs parameter in _check_and_extract is unused
when extract_artifacts=False, so we pass None instead of mocking.
"""

import pytest

from peat.forensic.image import (
    ExtractedArtifact,
    ImageAnalysisResult,
    _check_and_extract,
    _get_ics_file_patterns,
    _EXTRA_ICS_PATTERNS,
    _EXCLUDED_DIRS,
)


class TestICSFilePatterns:
    """Tests for ICS artifact pattern collection."""

    def test_extra_patterns_exist(self) -> None:
        """Built-in ICS patterns should be populated."""
        assert "ics_project" in _EXTRA_ICS_PATTERNS
        assert "ics_firmware" in _EXTRA_ICS_PATTERNS
        assert "ics_log" in _EXTRA_ICS_PATTERNS
        assert "ics_config" in _EXTRA_ICS_PATTERNS

    def test_extra_patterns_contain_known_extensions(self) -> None:
        """Known ICS file extensions should be in the patterns."""
        all_patterns = []
        for pats in _EXTRA_ICS_PATTERNS.values():
            all_patterns.extend(pats)

        assert "*.l5x" in all_patterns  # Rockwell
        assert "*.apx" in all_patterns  # Schneider M340
        assert "*.rdb" in all_patterns  # SEL
        assert "*.wset" in all_patterns  # Woodward
        assert "*.ser" in all_patterns  # SEL event logs
        assert "*.cev" in all_patterns  # SEL event files

    def test_get_ics_file_patterns_returns_dict(self) -> None:
        """Module patterns function should return a dict."""
        patterns = _get_ics_file_patterns()
        assert isinstance(patterns, dict)

    def test_excluded_dirs(self) -> None:
        """Common non-ICS directories should be excluded."""
        assert "windows" in _EXCLUDED_DIRS
        assert "$recycle.bin" in _EXCLUDED_DIRS
        assert "system volume information" in _EXCLUDED_DIRS


class TestArtifactMatching:
    """Tests for file pattern matching against ICS artifacts.

    _check_and_extract only touches the fs object when extracting files
    or getting file size. With extract_artifacts=False and output_dir=None,
    fs is unused, so we pass None.
    """

    def test_match_l5x_file(self) -> None:
        """L5X files should match Rockwell patterns."""
        patterns = {"ics_project": ["*.l5x", "*.L5X"]}
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/projects/main.l5x", "main.l5x", result, patterns, None, False)

        assert len(result.artifacts) == 1
        assert result.artifacts[0].file_name == "main.l5x"
        assert result.artifacts[0].matched_module == "ics_project"

    def test_match_rdb_file(self) -> None:
        """RDB files should match SEL patterns."""
        patterns = {"ics_project": ["*.rdb", "*.RDB"]}
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/sel/relay.rdb", "relay.rdb", result, patterns, None, False)

        assert len(result.artifacts) == 1
        assert result.artifacts[0].matched_pattern == "*.rdb"

    def test_match_case_insensitive(self) -> None:
        """Pattern matching should be case-insensitive."""
        patterns = {"ics_project": ["*.L5X"]}
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/proj/MAIN.l5x", "MAIN.l5x", result, patterns, None, False)

        assert len(result.artifacts) == 1

    def test_no_match(self) -> None:
        """Non-ICS files should not match."""
        patterns = {"ics_project": ["*.l5x"]}
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/docs/readme.pdf", "readme.pdf", result, patterns, None, False)

        assert len(result.artifacts) == 0

    def test_match_sel_set_pattern(self) -> None:
        """SEL SET_*.TXT files should match."""
        patterns = {"ics_log": ["SET_*.TXT", "set_*.txt"]}
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/sel/SET_1.TXT", "SET_1.TXT", result, patterns, None, False)

        assert len(result.artifacts) == 1

    def test_first_match_wins(self) -> None:
        """Only the first matching pattern should be recorded per file."""
        patterns = {
            "source_a": ["*.bin"],
            "source_b": ["*.bin"],
        }
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")

        _check_and_extract(None, "/fw/plc.bin", "plc.bin", result, patterns, None, False)

        assert len(result.artifacts) == 1  # Not 2


class TestImageAnalysisResult:
    """Tests for result serialization."""

    def test_to_dict_structure(self) -> None:
        result = ImageAnalysisResult(
            image_path="/evidence/disk.e01",
            image_type="e01",
            partitions_found=2,
            filesystem_type="NTFS",
            total_files_scanned=1500,
        )
        result.artifacts.append(
            ExtractedArtifact(
                virtual_path="/projects/main.l5x",
                file_name="main.l5x",
                file_size=45000,
                matched_module="ControlLogix",
                matched_pattern="*.l5x",
            )
        )

        d = result.to_dict()

        assert "image_analysis" in d
        ia = d["image_analysis"]
        assert ia["partitions_found"] == 2
        assert ia["filesystem_type"] == "NTFS"
        assert ia["total_files_scanned"] == 1500
        assert ia["artifacts_found"] == 1
        assert ia["artifacts"][0]["file_name"] == "main.l5x"

    def test_empty_result(self) -> None:
        result = ImageAnalysisResult(image_path="test.dd", image_type="dd")
        d = result.to_dict()

        assert d["image_analysis"]["artifacts_found"] == 0
        assert d["image_analysis"]["total_files_scanned"] == 0
