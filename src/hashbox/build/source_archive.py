"""Create a bounded, history-free source archive for the builder."""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path
import stat
import tarfile

EXCLUDED = {
    ".git", ".local", ".azure", ".venv", ".terraform", ".DS_Store",
    ".pytest_cache", "dist", "logs", "tmp", "tests", "__pycache__",
}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_FILES = 256


class SourceError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts[0] == "build":
            continue
        if any(
            part in EXCLUDED or part.startswith(".env") or part.endswith((".egg-info", ".dist-info"))
            for part in relative.parts
        ):
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SourceError(f"source contains a non-regular or linked path: {relative}")
        if metadata.st_size > MAX_FILE_BYTES:
            raise SourceError(f"source file exceeds the size limit: {relative}")
        files.append(relative)
    files.sort(key=lambda item: item.as_posix())
    if not files or len(files) > MAX_FILES:
        raise SourceError("source file count is outside bounds")
    if not (root / "hashbox.toml").is_file() or not (root / "backends/guix/images/azure-gen2.scm").is_file():
        raise SourceError("source is missing the project selector or Azure image")
    return files


def create(root: Path, output: Path) -> tuple[str, int]:
    """Write a no-replace .tar.gz and return its digest and source file count."""
    if output.exists() or output.is_symlink():
        raise SourceError(f"source archive already exists: {output}")
    files = collect(root)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with output.open("xb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", filename="", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|") as archive:
                    for relative in files:
                        path = root / relative
                        content = path.read_bytes()
                        metadata = path.lstat()
                        if len(content) != metadata.st_size or not stat.S_ISREG(metadata.st_mode):
                            raise SourceError(f"source changed while archived: {relative}")
                        entry = tarfile.TarInfo(relative.as_posix())
                        entry.size = len(content)
                        entry.mode = 0o755 if metadata.st_mode & 0o111 else 0o644
                        entry.uid = entry.gid = 0
                        entry.uname = entry.gname = ""
                        entry.mtime = 0
                        archive.addfile(entry, io.BytesIO(content))
        if output.stat().st_size > MAX_ARCHIVE_BYTES:
            raise SourceError("source archive exceeds the size limit")
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    return sha256_file(output), len(files)
