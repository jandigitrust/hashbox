#!/usr/bin/env python3
"""Source-bound, mount-free UKI assembly. Run only inside the pinned Secure Boot manifest.

Inputs are already captured by the artifact pipeline. Never consult the host
Guix store for the guest kernel/initrd, execute GRUB text, or mount a guest fs.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import uuid
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(PROJECT_DIR / "toolchain" / "disk"))
import vhd

MAX_COMPONENT = 48 * 1024 * 1024
MAX_UKI = 64 * 1024 * 1024
STORE = r"/gnu/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+"
LINUX_FS = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
OS_RELEASE = b'ID=hashbox\nNAME=HashBox\nVERSION_ID=1\n'


def boot_spec(config: str) -> tuple[str, str, str]:
    """Accept the single default entry emitted by this Guix image, not GRUB code."""
    if len(config) > 65536 or "\x00" in config:
        raise ValueError("invalid GRUB configuration size/content")
    linux = re.findall(r"^  linux (.+)$", config, re.M)
    initrd = re.findall(r"^  initrd +(.+)$", config, re.M)
    if len(linux) != 1 or len(initrd) != 1 or config.count("set default=0\n") != 1:
        raise ValueError("UKI requires exactly one default Linux/initrd entry")
    kernel, separator, cmdline = linux[0].partition(" ")
    if not separator or not re.fullmatch(STORE + r"/bzImage", kernel):
        raise ValueError("noncanonical kernel store path")
    if not re.fullmatch(STORE + r"/initrd.cpio.gz", initrd[0]):
        raise ValueError("noncanonical initrd store path")
    # Exact, closed boot argument vocabulary: no quoting, substitutions, extra
    # init=, rdinit=, profile selection, shell tokens or implicit root fallback.
    pattern = (r"root=([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}) "
               r"gnu.system=(/gnu/store/[0-9a-z]{32}-system) gnu.load=\2/boot "
               r"console=tty0 console=ttyS0,115200n8 earlyprintk=ttyS0,115200 "
               r"ima_policy=tcb ima_hash=sha256 ima_template=ima-ng rootdelay=10")
    if not re.fullmatch(pattern, cmdline):
        raise ValueError("unsupported or ambiguous kernel command line")
    return kernel, initrd[0], cmdline


def root_partition(artifact: Path) -> tuple[int, int]:
    metadata = vhd.validate(str(artifact))
    with artifact.open("rb") as disk:
        disk.seek(512)
        header = disk.read(512)
        entries_lba, count, size = struct.unpack_from("<QII", header, 72)
        if not count or size < 128 or count * size > 16 * vhd.MIB:
            raise ValueError("invalid partition table bounds")
        disk.seek(entries_lba * 512)
        entries = disk.read(count * size)
    roots = []
    for index in range(count):
        entry = entries[index * size:(index + 1) * size]
        if uuid.UUID(bytes_le=entry[:16]) == LINUX_FS:
            first, last = struct.unpack_from("<QQ", entry, 32)
            if first > last or (last + 1) * 512 > metadata["payloadSizeBytes"]:
                raise ValueError("root partition outside VHD")
            roots.append((first * 512, (last - first + 1) * 512))
    if len(roots) != 1:
        raise ValueError("UKI requires exactly one Linux root partition")
    return roots[0]


def tool(args: list[str]) -> bytes:
    environment = os.environ.copy()
    environment.update(LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="946684800")
    result = subprocess.run(args, env=environment, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300, check=False)
    if result.returncode:
        raise ValueError(f"UKI tool {args[0]} failed: " + result.stderr.decode(errors="replace")[-1000:])
    return result.stdout


def extract(root: Path, guest_path: str, output: Path, maximum: int) -> bytes:
    if output.exists() or output.is_symlink():
        raise ValueError("extraction destination exists")
    # debugfs commands are not passed to a shell, but its own parser also must
    # never receive quotes/metacharacters from guest paths or temp directories.
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", guest_path):
        raise ValueError("unsafe guest extraction path")
    if any(c in str(output) for c in '\"\n\r\\'):
        raise ValueError("unsafe extraction destination")
    stat_text = tool(["debugfs", "-R", "stat " + guest_path, str(root)]).decode("ascii", "strict")
    match = re.search(r"Type: regular\s.*?\bSize:\s+(\d+)", stat_text, re.S)
    if not match or not 0 < int(match[1]) <= maximum:
        raise ValueError("guest component is not a bounded regular file")
    tool(["debugfs", "-R", f'dump {guest_path} "{output}"', str(root)])
    if output.is_symlink() or not output.is_file() or output.stat().st_size != int(match[1]):
        raise ValueError("guest component extraction differs from stat")
    return output.read_bytes()


def assemble(artifact: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("UKI output already exists")
    assembler = shutil.which("hashbox-ukify")
    if assembler is None:
        raise ValueError("pinned hashbox-ukify is unavailable")
    stub = Path(assembler).resolve().parent.parent / "libexec/linuxx64.efi.stub"
    if not stub.is_file():
        raise ValueError("pinned EFI stub is unavailable")
    offset, size = root_partition(artifact)
    with tempfile.TemporaryDirectory(prefix="hashbox-uki-") as temporary:
        work = Path(temporary)
        root = work / "root.ext4"
        with artifact.open("rb") as source, root.open("xb") as target:
            source.seek(offset)
            remaining = size
            while remaining:
                chunk = source.read(min(8 * 1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("truncated root partition")
                target.write(chunk)
                remaining -= len(chunk)
        config = extract(root, "/boot/grub/grub.cfg", work / "grub.cfg", 65536)
        kernel_path, initrd_path, cmdline = boot_spec(config.decode("utf-8", "strict"))
        extract(root, kernel_path, work / "linux", MAX_COMPONENT)
        extract(root, initrd_path, work / "initrd", MAX_COMPONENT)
        (work / "cmdline").write_text(cmdline, encoding="ascii")
        (work / "os-release").write_bytes(OS_RELEASE)
        # Explicit empty configuration prevents host /etc/systemd discovery.
        (work / "ukify.conf").write_bytes(b"")
        tool([assembler, "build", "--config", str(work / "ukify.conf"),
              "--stub", str(stub), "--efi-arch", "x64", "--uname", "hashbox",
              "--linux", str(work / "linux"), "--initrd", str(work / "initrd"),
              "--cmdline", "@" + str(work / "cmdline"),
              "--os-release", "@" + str(work / "os-release"),
              "--output", str(work / "unsigned.efi")])
        payload = (work / "unsigned.efi").read_bytes()
        if not 0 < len(payload) <= MAX_UKI:
            raise ValueError("UKI exceeds supported size")
        # Check that the assembler did not substitute/add payload sections.
        sections = pe_sections(payload)
        for name, data in ((b".linux", (work / "linux").read_bytes()),
                           (b".initrd", (work / "initrd").read_bytes()),
                           (b".cmdline", cmdline.encode("ascii")),
                           (b".osrel", OS_RELEASE)):
            if sections.get(name, b"").rstrip(b"\0") != data.rstrip(b"\0"):
                raise ValueError("assembled UKI component differs: " + name.decode())
        with output.open("xb") as handle:
            handle.write(payload)


def pe_offsets(data: bytes) -> tuple[int, int]:
    if len(data) < 64 or len(data) > MAX_UKI or data[:2] != b"MZ":
        raise ValueError("invalid UKI PE size/signature")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe < 64 or pe + 24 + 152 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid UKI PE header")
    optional = pe + 24
    if (struct.unpack_from("<H", data, pe + 4)[0] != 0x8664
            or struct.unpack_from("<H", data, optional)[0] != 0x20b
            or struct.unpack_from("<H", data, optional + 68)[0] != 10
            or struct.unpack_from("<I", data, optional + 108)[0] < 5):
        raise ValueError("UKI must be AMD64 PE32+ EFI")
    return pe, optional


def pe_sections(data: bytes) -> dict[bytes, bytes]:
    pe, optional = pe_offsets(data)
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    start = optional + optional_size
    if optional_size < 152 or not 1 <= count <= 128 or start + count * 40 > len(data):
        raise ValueError("invalid UKI section table")
    result = {}
    ranges = []
    for index in range(count):
        header = start + index * 40
        name = data[header:header + 8].rstrip(b"\0")
        virtual, _, raw_size, offset = struct.unpack_from("<IIII", data, header + 8)
        if name in result or (virtual > raw_size and raw_size != 0) or offset + raw_size > len(data):
            raise ValueError("invalid/duplicate UKI section")
        if raw_size:
            if offset < start + count * 40 or any(offset < b and a < offset + raw_size for a, b in ranges):
                raise ValueError("overlapping UKI sections")
            ranges.append((offset, offset + raw_size))
        result[name] = data[offset:offset + virtual]
    return result


def verify_signed_payload(unsigned: bytes, signed: bytes) -> None:
    """Signing may alter only checksum, certificate directory and append certs.

    This is not cryptographic signature verification: sbverify is required too.
    All executable bytes/headers and embedded sections must match the freshly
    source-derived unsigned UKI. No attacker-chosen signed stub is admitted.
    """
    _, optional = pe_offsets(unsigned)
    _, signed_optional = pe_offsets(signed)
    if optional != signed_optional:
        raise ValueError("signed UKI changed PE layout")
    if struct.unpack_from("<II", unsigned, optional + 144) != (0, 0):
        raise ValueError("reassembled UKI is already signed")
    offset, size = struct.unpack_from("<II", signed, optional + 144)
    aligned = (len(unsigned) + 7) & ~7
    if offset != aligned or size < 8 or offset + size != len(signed):
        raise ValueError("signed UKI has unexpected certificate placement")
    expected = bytearray(unsigned + b"\0" * (aligned - len(unsigned)))
    observed = bytearray(signed[:offset])
    for value in (expected, observed):
        value[optional + 64:optional + 68] = b"\0" * 4
        value[optional + 144:optional + 152] = b"\0" * 8
    if expected != observed:
        raise ValueError("signed UKI payload differs from source-bound assembly")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-artifact", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assemble(args.source_artifact, args.output)
