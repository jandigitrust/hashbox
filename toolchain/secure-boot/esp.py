"""Locate the one EFI System Partition in a validated fixed VHD."""

from __future__ import annotations

from pathlib import Path
import struct
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "disk"))
import vhd


def locate_single_esp(artifact: Path) -> int:
    metadata = vhd.validate(str(artifact))
    if metadata.get("efiSystemPartitions") != 1:
        raise ValueError("VHD must contain exactly one EFI System Partition")
    with artifact.open("rb") as disk:
        disk.seek(vhd.SECTOR_SIZE)
        header = disk.read(vhd.SECTOR_SIZE)
        if len(header) != vhd.SECTOR_SIZE or header[:8] != vhd.GPT_SIGNATURE:
            raise ValueError("VHD has no primary GPT header")
        entries_lba, count, size = struct.unpack_from("<QII", header, 72)
        if not count or size < 128 or count * size > 16 * vhd.MIB:
            raise ValueError("invalid GPT entry table")
        disk.seek(entries_lba * vhd.SECTOR_SIZE)
        entries = disk.read(count * size)
    if len(entries) != count * size:
        raise ValueError("truncated GPT entry table")
    offsets = []
    for index in range(count):
        entry = entries[index * size:(index + 1) * size]
        if uuid.UUID(bytes_le=entry[:16]) != vhd.EFI_SYSTEM_PARTITION:
            continue
        first, last = struct.unpack_from("<QQ", entry, 32)
        offset = first * vhd.SECTOR_SIZE
        end = (last + 1) * vhd.SECTOR_SIZE
        if first > last or offset < 34 * vhd.SECTOR_SIZE or end > metadata["payloadSizeBytes"]:
            raise ValueError("EFI System Partition is outside the VHD payload")
        offsets.append(offset)
    if len(offsets) != 1:
        raise ValueError("VHD must contain exactly one EFI System Partition")
    return offsets[0]
