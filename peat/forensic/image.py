"""
Forensic disk image analysis via the dissect framework.

Opens forensic disk images (E01, dd/raw, VMDK, VHD/VHDX, QCoW2) and
virtual-walks their filesystems to extract ICS/SCADA artifacts without
mounting the image or requiring root privileges.

Uses dissect.target for high-level auto-detection, falling back to
manual container → volume → filesystem layering for edge cases.

@decision: Uses dissect.target.Target.open() as the primary entry point
rather than manually composing EWF + Disk + filesystem objects. Target.open
auto-detects container format, partition scheme, and filesystem type in one
call. Manual composition is available as a fallback for images that
Target.open cannot handle (e.g., bare filesystem images without partition
tables, which are common in embedded ICS device dumps).
"""
# Copyright 2026 John Jarocki
# Developed with AI assistance from Claude Opus 4.6 (Anthropic)
#
# This file is part of PEAT and is licensed under GPL-3.0.
# See LICENSE for details.


from __future__ import annotations

import fnmatch
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from peat import config, log, module_api
from peat.forensic.integrity import ForensicMetadata


@dataclass
class ExtractedArtifact:
    """An artifact extracted from a forensic disk image."""

    virtual_path: str  # Path within the image filesystem
    file_name: str
    file_size: int
    matched_module: str  # PEAT device module that matched
    matched_pattern: str  # Glob pattern that matched
    content: bytes | None = None  # File content (if extracted to memory)
    output_path: str = ""  # Path where artifact was saved (if exported)


@dataclass
class ImageAnalysisResult:
    """Results from analyzing a forensic disk image."""

    image_path: str
    image_type: str  # e01, dd, vmdk, etc.
    partitions_found: int = 0
    filesystem_type: str = ""
    total_files_scanned: int = 0
    artifacts: list[ExtractedArtifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_analysis": {
                "image_path": self.image_path,
                "image_type": self.image_type,
                "partitions_found": self.partitions_found,
                "filesystem_type": self.filesystem_type,
                "total_files_scanned": self.total_files_scanned,
                "artifacts_found": len(self.artifacts),
                "artifacts": [
                    {
                        "virtual_path": a.virtual_path,
                        "file_name": a.file_name,
                        "file_size": a.file_size,
                        "matched_module": a.matched_module,
                        "matched_pattern": a.matched_pattern,
                        "output_path": a.output_path,
                    }
                    for a in self.artifacts
                ],
                "errors": self.errors,
            }
        }


def _get_ics_file_patterns() -> dict[str, list[str]]:
    """
    Collect filename patterns from all registered PEAT device modules.

    Returns:
        Dict mapping module name → list of glob patterns the module can parse.
    """
    patterns: dict[str, list[str]] = {}
    for mod_cls in module_api.classes:
        if hasattr(mod_cls, "filename_patterns") and mod_cls.filename_patterns:
            name = getattr(mod_cls, "name", mod_cls.__name__)
            patterns[name] = list(mod_cls.filename_patterns)
    return patterns


# Common ICS-related file patterns beyond what device modules define
_EXTRA_ICS_PATTERNS: dict[str, list[str]] = {
    "ics_config": [
        "*.cfg",
        "*.conf",
        "*.ini",
        "*.yaml",
        "*.yml",
    ],
    "ics_project": [
        "*.l5x",
        "*.L5X",
        "*.l5k",
        "*.L5K",
        "*.apx",
        "*.rdb",
        "*.RDB",
        "*.wset",
        "*.tc",
    ],
    "ics_firmware": [
        "*.bin",
        "*.fw",
        "*.dmk",
        "*.rom",
        "*.hex",
    ],
    "ics_log": [
        "*.cev",
        "*.ser",
        "SET_*.TXT",
        "set_*.txt",
        "*_events.csv",
        "*_audit.csv",
    ],
}

# Directories commonly excluded during forensic search
_EXCLUDED_DIRS = {
    "windows",
    "system volume information",
    "$recycle.bin",
    "recovery",
    "program files",
    "program files (x86)",
    "programdata",
    "__pycache__",
    ".git",
    "node_modules",
}


def analyze_disk_image(
    image_path: Path,
    metadata: ForensicMetadata | None = None,
    output_dir: Path | None = None,
    extract_artifacts: bool = True,
    include_extra_patterns: bool = True,
) -> ImageAnalysisResult:
    """
    Analyze a forensic disk image for ICS/SCADA artifacts.

    Opens the image using dissect.target, walks the filesystem(s), and
    identifies files matching PEAT device module patterns.

    Args:
        image_path: Path to the disk image file.
        metadata: Forensic metadata from the integrity module.
        output_dir: Directory to save extracted artifacts. If None, uses
                    config.RUN_DIR / "forensic_artifacts".
        extract_artifacts: Whether to extract matching files to disk.
        include_extra_patterns: Include common ICS patterns beyond module patterns.

    Returns:
        ImageAnalysisResult with found artifacts and analysis metadata.
    """
    suffix = image_path.suffix.lower()
    image_type = suffix.lstrip(".")
    result = ImageAnalysisResult(
        image_path=str(image_path),
        image_type=image_type,
    )

    # Collect patterns to search for
    patterns = _get_ics_file_patterns()
    if include_extra_patterns:
        patterns.update(_EXTRA_ICS_PATTERNS)

    total_patterns = sum(len(v) for v in patterns.values())
    log.info(
        f"Searching image for ICS artifacts using {total_patterns} patterns "
        f"from {len(patterns)} sources"
    )

    # Set up output directory
    if output_dir is None and config.RUN_DIR:
        output_dir = config.RUN_DIR / "forensic_artifacts"
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    # Try high-level Target.open first, fall back to manual approach
    try:
        result = _analyze_with_target(image_path, result, patterns, output_dir, extract_artifacts)
    except Exception as e:
        log.warning(f"Target.open failed ({e}), trying manual container analysis...")
        try:
            result = _analyze_manual(image_path, result, patterns, output_dir, extract_artifacts)
        except Exception as e2:
            error_msg = f"Failed to analyze image: {e2}"
            log.error(error_msg)
            result.errors.append(error_msg)

    log.info(
        f"Image analysis complete: scanned {result.total_files_scanned} files, "
        f"found {len(result.artifacts)} ICS artifacts"
    )

    # Write analysis results to output
    if output_dir:
        results_path = output_dir / "image-analysis-results.json"
        try:
            results_path.write_text(json.dumps(result.to_dict(), indent=4))
            log.debug(f"Analysis results written to: {results_path}")
        except OSError as e:
            log.warning(f"Failed to write analysis results: {e}")

    return result


def _analyze_with_target(
    image_path: Path,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> ImageAnalysisResult:
    """Analyze using dissect.target.Target high-level API."""
    from dissect.target import Target

    log.info(f"Opening image with dissect Target: {image_path.name}")
    target = Target.open(image_path)

    # Walk each filesystem the target exposes
    for fs in target.filesystems:
        fs_type = type(fs).__name__
        log.info(f"Walking filesystem: {fs_type}")
        result.filesystem_type = fs_type
        result.partitions_found += 1

        _walk_filesystem(
            fs=fs,
            result=result,
            patterns=patterns,
            output_dir=output_dir,
            extract_artifacts=extract_artifacts,
        )

    return result


def _analyze_manual(
    image_path: Path,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> ImageAnalysisResult:
    """
    Manual analysis for images that Target.open cannot handle.

    Opens the container directly, enumerates partitions, and mounts
    filesystems individually.
    """
    from dissect.volume.disk import Disk

    fh = _open_container(image_path)

    try:
        disk = Disk(fh)
    except Exception:
        # Might be a bare filesystem image — try filesystems directly
        log.debug("No partition table found, trying as bare filesystem")
        fh.seek(0)
        fs = _try_detect_filesystem(fh)
        if fs:
            result.filesystem_type = type(fs).__name__
            result.partitions_found = 1
            _walk_filesystem(fs, result, patterns, output_dir, extract_artifacts)
        else:
            result.errors.append("Could not detect filesystem in image")
        return result

    # Iterate partitions
    for i, partition in enumerate(disk.partitions):
        log.info(f"Analyzing partition {i}")
        result.partitions_found += 1

        try:
            part_fh = partition.open()
            fs = _try_detect_filesystem(part_fh)
            if fs:
                result.filesystem_type = type(fs).__name__
                _walk_filesystem(fs, result, patterns, output_dir, extract_artifacts)
            else:
                log.debug(f"Partition {i}: unknown filesystem, skipping")
        except Exception as e:
            error_msg = f"Partition {i} analysis failed: {e}"
            log.warning(error_msg)
            result.errors.append(error_msg)

    return result


def _open_container(path: Path) -> BinaryIO:
    """
    Open a forensic container file and return a seekable binary stream.

    Handles E01, VMDK, VHD, and raw/dd images.
    """
    suffix = path.suffix.lower()

    if suffix == ".e01":
        from dissect.evidence.ewf import EWF

        log.debug("Opening E01 container")
        return EWF(path)

    if suffix in (".vmdk",):
        from dissect.hypervisor.vmdk import VMDK

        log.debug("Opening VMDK container")
        vmdk = VMDK(path)
        return vmdk.open()

    if suffix in (".vhd", ".vhdx"):
        from dissect.hypervisor.vhd import VHD

        log.debug("Opening VHD/VHDX container")
        vhd = VHD(path)
        return vhd.open()

    if suffix in (".qcow2",):
        from dissect.hypervisor.qcow2 import QCow2

        log.debug("Opening QCoW2 container")
        qcow2 = QCow2(path.open("rb"))
        return qcow2.open()

    # Raw/dd — just open the file directly
    log.debug("Opening raw/dd image")
    return path.open("rb")


def _try_detect_filesystem(fh: BinaryIO) -> Any:
    """
    Try to detect and open a filesystem from a binary stream.

    Attempts each supported filesystem type in order of likelihood
    for ICS environments.
    """
    fs_types = [
        ("NTFS", "dissect.ntfs", "NTFS"),
        ("ExtFS", "dissect.extfs", "ExtFS"),
        ("FAT", "dissect.fat", "FAT"),
        ("QnxFs", "dissect.qnxfs", "QnxFs"),
        ("SquashFS", "dissect.squashfs", "SquashFS"),
        ("JFFS2", "dissect.jffs", "JFFS2"),
        ("CramFS", "dissect.cramfs", "CramFS"),
        ("XFS", "dissect.xfs", "XFS"),
        ("BtrFS", "dissect.btrfs", "BtrFS"),
        ("FFS", "dissect.ffs", "FFS"),
    ]

    for name, module_path, class_name in fs_types:
        try:
            import importlib

            mod = importlib.import_module(module_path)
            fs_class = getattr(mod, class_name)
            fh.seek(0)
            fs = fs_class(fh)
            log.debug(f"Detected filesystem: {name}")
            return fs
        except Exception:
            continue

    return None


def _walk_filesystem(
    fs: Any,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> None:
    """
    Walk a dissect filesystem and search for ICS artifacts.

    Uses the filesystem's walk/iterdir methods to traverse directories
    and match files against known ICS patterns.
    """
    # dissect filesystems expose different APIs depending on the type
    # Target filesystems have .path() and .walk()
    # Raw filesystem objects have .get() and manual iteration

    if hasattr(fs, "path"):
        # dissect.target Filesystem or LayerFilesystem
        _walk_target_fs(fs, result, patterns, output_dir, extract_artifacts)
    elif hasattr(fs, "get"):
        # Raw dissect filesystem (NTFS, ExtFS, etc.)
        _walk_raw_fs(fs, result, patterns, output_dir, extract_artifacts)
    else:
        log.warning(f"Unknown filesystem interface: {type(fs).__name__}")


def _walk_target_fs(
    fs: Any,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> None:
    """Walk a dissect.target Filesystem using its path/walk API."""
    try:
        for dirpath, dirnames, filenames in fs.walk("/"):
            # Skip excluded directories
            dir_name = dirpath.rsplit("/", 1)[-1].lower() if "/" in dirpath else dirpath.lower()
            if dir_name in _EXCLUDED_DIRS:
                continue

            for filename in filenames:
                result.total_files_scanned += 1
                virtual_path = f"{dirpath}/{filename}" if dirpath != "/" else f"/{filename}"

                _check_and_extract(
                    fs, virtual_path, filename, result, patterns,
                    output_dir, extract_artifacts,
                )
    except Exception as e:
        error_msg = f"Filesystem walk error: {e}"
        log.warning(error_msg)
        result.errors.append(error_msg)


def _walk_raw_fs(
    fs: Any,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> None:
    """Walk a raw dissect filesystem using its native get/iterdir API."""
    try:
        root = fs.get("/")
        _walk_raw_entry(root, "/", fs, result, patterns, output_dir, extract_artifacts)
    except Exception as e:
        error_msg = f"Raw filesystem walk error: {e}"
        log.warning(error_msg)
        result.errors.append(error_msg)


def _walk_raw_entry(
    entry: Any,
    current_path: str,
    fs: Any,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> None:
    """Recursively walk a raw filesystem entry."""
    try:
        if hasattr(entry, "is_dir") and entry.is_dir():
            dir_name = current_path.rsplit("/", 1)[-1].lower()
            if dir_name in _EXCLUDED_DIRS:
                return

            if hasattr(entry, "iterdir"):
                for child in entry.iterdir():
                    child_name = getattr(child, "name", str(child))
                    child_path = f"{current_path}/{child_name}".replace("//", "/")
                    _walk_raw_entry(
                        child, child_path, fs, result, patterns,
                        output_dir, extract_artifacts,
                    )
        elif hasattr(entry, "is_file") and entry.is_file():
            result.total_files_scanned += 1
            filename = current_path.rsplit("/", 1)[-1]
            _check_and_extract(
                fs, current_path, filename, result, patterns,
                output_dir, extract_artifacts,
            )
    except Exception as e:
        log.trace(f"Error walking {current_path}: {e}")


def _check_and_extract(
    fs: Any,
    virtual_path: str,
    filename: str,
    result: ImageAnalysisResult,
    patterns: dict[str, list[str]],
    output_dir: Path | None,
    extract_artifacts: bool,
) -> None:
    """Check if a file matches any ICS pattern and optionally extract it."""
    for source_name, pattern_list in patterns.items():
        for pattern in pattern_list:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filename.lower(), pattern.lower()):
                log.info(f"Found ICS artifact: {virtual_path} (matched: {source_name}/{pattern})")

                try:
                    file_size = _get_file_size(fs, virtual_path)
                except Exception:
                    file_size = 0

                artifact = ExtractedArtifact(
                    virtual_path=virtual_path,
                    file_name=filename,
                    file_size=file_size,
                    matched_module=source_name,
                    matched_pattern=pattern,
                )

                # Extract to output directory
                if extract_artifacts and output_dir:
                    artifact = _extract_artifact(fs, virtual_path, artifact, output_dir)

                result.artifacts.append(artifact)
                return  # File matched, no need to check more patterns


def _get_file_size(fs: Any, virtual_path: str) -> int:
    """Get file size from a dissect filesystem."""
    if hasattr(fs, "path"):
        # Target filesystem
        entry = fs.path(virtual_path)
        if hasattr(entry, "stat"):
            return entry.stat().st_size
    elif hasattr(fs, "get"):
        entry = fs.get(virtual_path)
        if hasattr(entry, "size"):
            return entry.size
    return 0


def _extract_artifact(
    fs: Any,
    virtual_path: str,
    artifact: ExtractedArtifact,
    output_dir: Path,
) -> ExtractedArtifact:
    """Extract a file from the forensic image to the output directory."""
    # Sanitize the virtual path for use as a local path
    safe_path = virtual_path.lstrip("/").replace("\\", "/")
    dest = output_dir / safe_path
    dest.parent.mkdir(parents=True, exist_ok=True)

    try:
        if hasattr(fs, "path"):
            # Target filesystem
            entry = fs.path(virtual_path)
            with entry.open("rb") as src:
                content = src.read()
        elif hasattr(fs, "get"):
            entry = fs.get(virtual_path)
            if hasattr(entry, "open"):
                with entry.open("rb") as src:
                    content = src.read()
            else:
                content = entry.read()
        else:
            log.warning(f"Cannot read from filesystem type: {type(fs).__name__}")
            return artifact

        dest.write_bytes(content)
        artifact.output_path = str(dest)
        artifact.file_size = len(content)
        log.debug(f"Extracted: {virtual_path} → {dest} ({len(content):,} bytes)")

    except Exception as e:
        log.warning(f"Failed to extract {virtual_path}: {e}")

    return artifact
