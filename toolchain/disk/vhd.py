#!/usr/bin/env python3
"""Create, canonicalize, and validate an Azure-compatible fixed VHD."""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
import uuid
import zlib


FOOTER_SIZE = 512
MIB = 1024 * 1024
COOKIE = b"conectix"
CHECKSUM_OFFSET = 64
TIMESTAMP_OFFSET = 24
UUID_OFFSET = 68
SECTOR_SIZE = 512
GPT_SIGNATURE = b"EFI PART"
EFI_SYSTEM_PARTITION = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")


def gpt_header_checksum(header: bytearray) -> int:
    header_size = struct.unpack_from("<I", header, 12)[0]
    if not 92 <= header_size <= SECTOR_SIZE:
        raise ValueError("invalid GPT header size")
    candidate = bytearray(header[:header_size])
    candidate[16:20] = b"\0" * 4
    return zlib.crc32(candidate) & 0xFFFFFFFF


def relocate_backup_gpt(path: str, payload_size: int) -> None:
    """Move GPT backup metadata after deterministic MiB padding."""
    new_backup_lba = payload_size // SECTOR_SIZE - 1
    with open(path, "r+b") as disk:
        disk.seek(SECTOR_SIZE)
        primary = bytearray(disk.read(SECTOR_SIZE))
        if primary[:8] != GPT_SIGNATURE:
            raise ValueError("raw disk does not contain a primary GPT header")
        if struct.unpack_from("<I", primary, 16)[0] != gpt_header_checksum(primary):
            raise ValueError("raw disk contains an invalid primary GPT header")

        old_backup_lba = struct.unpack_from("<Q", primary, 32)[0]
        entries_lba = struct.unpack_from("<Q", primary, 72)[0]
        entry_count = struct.unpack_from("<I", primary, 80)[0]
        entry_size = struct.unpack_from("<I", primary, 84)[0]
        entries_size = entry_count * entry_size
        if not entry_count or entry_size < 128 or entries_size > 16 * MIB:
            raise ValueError("invalid GPT partition-entry table")

        disk.seek(entries_lba * SECTOR_SIZE)
        entries = disk.read(entries_size)
        if len(entries) != entries_size:
            raise ValueError("truncated GPT partition-entry table")
        entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
        if entries_crc != struct.unpack_from("<I", primary, 88)[0]:
            raise ValueError("invalid GPT partition-entry checksum")

        table_sectors = (entries_size + SECTOR_SIZE - 1) // SECTOR_SIZE
        new_entries_lba = new_backup_lba - table_sectors
        new_last_usable_lba = new_entries_lba - 1
        for offset in range(0, entries_size, entry_size):
            entry = entries[offset : offset + entry_size]
            if entry[:16] != b"\0" * 16:
                partition_last_lba = struct.unpack_from("<Q", entry, 40)[0]
                if partition_last_lba > new_last_usable_lba:
                    raise ValueError("GPT partition overlaps relocated backup table")

        if old_backup_lba != new_backup_lba:
            disk.seek(old_backup_lba * SECTOR_SIZE)
            old_backup = bytearray(disk.read(SECTOR_SIZE))
            if old_backup[:8] != GPT_SIGNATURE:
                raise ValueError("missing GPT backup header")
            if struct.unpack_from("<I", old_backup, 16)[0] != gpt_header_checksum(old_backup):
                raise ValueError("raw disk contains an invalid backup GPT header")
            old_entries_lba = struct.unpack_from("<Q", old_backup, 72)[0]
            if old_entries_lba > old_backup_lba:
                raise ValueError("invalid GPT backup partition-entry location")
            disk.seek(old_entries_lba * SECTOR_SIZE)
            disk.write(b"\0" * ((old_backup_lba - old_entries_lba + 1)
                                 * SECTOR_SIZE))

        struct.pack_into("<Q", primary, 32, new_backup_lba)
        struct.pack_into("<Q", primary, 48, new_last_usable_lba)
        struct.pack_into("<I", primary, 16, 0)
        struct.pack_into("<I", primary, 16, gpt_header_checksum(primary))

        backup = bytearray(primary)
        struct.pack_into("<Q", backup, 24, new_backup_lba)
        struct.pack_into("<Q", backup, 32, 1)
        struct.pack_into("<Q", backup, 72, new_entries_lba)
        struct.pack_into("<I", backup, 16, 0)
        struct.pack_into("<I", backup, 16, gpt_header_checksum(backup))

        disk.seek(SECTOR_SIZE)
        disk.write(primary)
        disk.seek(new_entries_lba * SECTOR_SIZE)
        disk.write(entries)
        disk.write(b"\0" * (table_sectors * SECTOR_SIZE - entries_size))
        disk.seek(new_backup_lba * SECTOR_SIZE)
        disk.write(backup)

        disk.seek(0)
        protective_mbr = bytearray(disk.read(SECTOR_SIZE))
        if protective_mbr[450] == 0xEE:
            struct.pack_into("<I", protective_mbr, 458,
                             min(new_backup_lba, 0xFFFFFFFF))
            disk.seek(0)
            disk.write(protective_mbr)


def check_gpt(path: str, payload_size: int, errors: list[str]) -> dict[str, int]:
    result = {"efiSystemPartitions": 0}
    if payload_size < 2 * MIB or payload_size % SECTOR_SIZE:
        errors.append("GPT payload size is invalid")
        return result
    with open(path, "rb") as disk:
        disk.seek(0)
        protective_mbr = disk.read(SECTOR_SIZE)
        if len(protective_mbr) != SECTOR_SIZE or protective_mbr[510:512] != b"\x55\xaa":
            errors.append("protective MBR signature is missing")
        else:
            first_entry = protective_mbr[446:462]
            if first_entry[4] != 0xEE:
                errors.append("protective MBR does not contain a GPT partition entry")
            if struct.unpack_from("<I", first_entry, 8)[0] != 1:
                errors.append("protective MBR GPT partition does not start at LBA 1")
            expected_sectors = min(payload_size // SECTOR_SIZE - 1, 0xFFFFFFFF)
            if struct.unpack_from("<I", first_entry, 12)[0] != expected_sectors:
                errors.append("protective MBR GPT partition size is invalid")
            if any(protective_mbr[offset : offset + 16] != b"\0" * 16
                   for offset in (462, 478, 494)):
                errors.append("protective MBR contains hybrid partition entries")

        disk.seek(SECTOR_SIZE)
        primary = bytearray(disk.read(SECTOR_SIZE))
        if primary[:8] != GPT_SIGNATURE:
            errors.append("primary GPT header is missing")
            return result

        last_lba = payload_size // SECTOR_SIZE - 1
        if struct.unpack_from("<I", primary, 8)[0] != 0x00010000:
            errors.append("primary GPT revision is invalid")
        if struct.unpack_from("<Q", primary, 24)[0] != 1:
            errors.append("primary GPT header is not at LBA 1")
        if struct.unpack_from("<Q", primary, 32)[0] != last_lba:
            errors.append("GPT backup header is not at the end of the disk")
        if struct.unpack_from("<I", primary, 16)[0] != gpt_header_checksum(primary):
            errors.append("primary GPT header checksum is invalid")

        entries_lba = struct.unpack_from("<Q", primary, 72)[0]
        entry_count = struct.unpack_from("<I", primary, 80)[0]
        entry_size = struct.unpack_from("<I", primary, 84)[0]
        entries_size = entry_count * entry_size
        if not entry_count or entry_size < 128 or entries_size > 16 * MIB:
            errors.append("invalid primary GPT partition-entry table")
            return result
        table_sectors = (entries_size + SECTOR_SIZE - 1) // SECTOR_SIZE
        first_usable = struct.unpack_from("<Q", primary, 40)[0]
        last_usable = struct.unpack_from("<Q", primary, 48)[0]
        if entries_lba < 2 or entries_lba + table_sectors > first_usable:
            errors.append("primary GPT partition-entry location is invalid")
        if not first_usable <= last_usable < last_lba:
            errors.append("primary GPT usable disk range is invalid")
        if primary[56:72] == b"\0" * 16:
            errors.append("GPT disk GUID is zero")

        disk.seek(entries_lba * SECTOR_SIZE)
        entries = disk.read(entries_size)
        if len(entries) != entries_size:
            errors.append("primary GPT partition-entry table is truncated")
            return result
        if zlib.crc32(entries) & 0xFFFFFFFF != struct.unpack_from("<I", primary, 88)[0]:
            errors.append("primary GPT partition-entry checksum is invalid")

        partitions: list[tuple[int, int]] = []
        partition_guids: set[bytes] = set()
        for offset in range(0, entries_size, entry_size):
            entry = entries[offset : offset + entry_size]
            if entry[:16] == b"\0" * 16:
                continue
            partition_first = struct.unpack_from("<Q", entry, 32)[0]
            partition_last = struct.unpack_from("<Q", entry, 40)[0]
            if not first_usable <= partition_first <= partition_last <= last_usable:
                errors.append("GPT partition lies outside the usable disk range")
            for existing_first, existing_last in partitions:
                if partition_first <= existing_last and existing_first <= partition_last:
                    errors.append("GPT partitions overlap")
                    break
            partitions.append((partition_first, partition_last))
            partition_guid = bytes(entry[16:32])
            if partition_guid == b"\0" * 16 or partition_guid in partition_guids:
                errors.append("GPT partition GUID is zero or duplicated")
            partition_guids.add(partition_guid)
            if uuid.UUID(bytes_le=entry[:16]) == EFI_SYSTEM_PARTITION:
                result["efiSystemPartitions"] += 1
        if result["efiSystemPartitions"] == 0:
            errors.append("GPT does not contain an EFI System Partition")

        disk.seek(last_lba * SECTOR_SIZE)
        backup = bytearray(disk.read(SECTOR_SIZE))
        if backup[:8] != GPT_SIGNATURE:
            errors.append("GPT backup header is missing")
            return result
        if struct.unpack_from("<I", backup, 8)[0] != 0x00010000:
            errors.append("backup GPT revision is invalid")
        if struct.unpack_from("<I", backup, 16)[0] != gpt_header_checksum(backup):
            errors.append("backup GPT header checksum is invalid")
        if struct.unpack_from("<Q", backup, 24)[0] != last_lba:
            errors.append("backup GPT current LBA is invalid")
        if struct.unpack_from("<Q", backup, 32)[0] != 1:
            errors.append("backup GPT does not point to the primary header")

        for offset, size, label in (
            (40, 8, "first usable LBA"),
            (48, 8, "last usable LBA"),
            (56, 16, "disk GUID"),
            (80, 4, "partition-entry count"),
            (84, 4, "partition-entry size"),
            (88, 4, "partition-entry checksum"),
        ):
            if backup[offset : offset + size] != primary[offset : offset + size]:
                errors.append(f"primary and backup GPT {label} differ")

        backup_entries_lba = struct.unpack_from("<Q", backup, 72)[0]
        if backup_entries_lba + table_sectors != last_lba:
            errors.append("backup GPT partition-entry location is invalid")
        disk.seek(backup_entries_lba * SECTOR_SIZE)
        backup_entries = disk.read(entries_size)
        if len(backup_entries) != entries_size:
            errors.append("backup GPT partition-entry table is truncated")
        else:
            backup_crc = struct.unpack_from("<I", backup, 88)[0]
            if zlib.crc32(backup_entries) & 0xFFFFFFFF != backup_crc:
                errors.append("backup GPT partition-entry checksum is invalid")
            if backup_entries != entries:
                errors.append("primary and backup GPT partition entries differ")
    return result


def disk_geometry(payload_size: int) -> bytes:
    """Return the legacy CHS geometry required by the VHD footer."""
    total_sectors = payload_size // 512
    maximum_sectors = 65535 * 16 * 255
    total_sectors = min(total_sectors, maximum_sectors)

    if total_sectors >= 65535 * 16 * 63:
        sectors_per_track = 255
        heads = 16
        cylinders = total_sectors // (sectors_per_track * heads)
    else:
        sectors_per_track = 17
        cylinder_times_heads = total_sectors // sectors_per_track
        heads = (cylinder_times_heads + 1023) // 1024
        heads = max(heads, 4)
        if cylinder_times_heads >= heads * 1024 or heads > 16:
            sectors_per_track = 31
            heads = 16
            cylinder_times_heads = total_sectors // sectors_per_track
        if cylinder_times_heads >= heads * 1024:
            sectors_per_track = 63
            heads = 16
            cylinder_times_heads = total_sectors // sectors_per_track
        cylinders = cylinder_times_heads // heads

    return struct.pack(">HBB", cylinders, heads, sectors_per_track)


def build_footer(payload_size: int, digest: bytes) -> bytearray:
    footer = bytearray(FOOTER_SIZE)
    footer[:8] = COOKIE
    struct.pack_into(">I", footer, 8, 2)  # Reserved feature bit.
    struct.pack_into(">I", footer, 12, 0x00010000)  # VHD version 1.0.
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)  # Fixed disk.
    struct.pack_into(">I", footer, TIMESTAMP_OFFSET, 0)
    footer[28:32] = b"hbox"
    struct.pack_into(">I", footer, 32, 0x00010000)
    footer[36:40] = b"Lnx "
    struct.pack_into(">Q", footer, 40, payload_size)
    struct.pack_into(">Q", footer, 48, payload_size)
    footer[56:60] = disk_geometry(payload_size)
    struct.pack_into(">I", footer, 60, 2)  # Fixed hard disk.
    value = bytearray(digest[:16])
    value[6] = (value[6] & 0x0F) | 0x50
    value[8] = (value[8] & 0x3F) | 0x80
    footer[UUID_OFFSET : UUID_OFFSET + 16] = value
    struct.pack_into(">I", footer, CHECKSUM_OFFSET, footer_checksum(footer))
    return footer


def create(raw_path: str, vhd_path: str) -> None:
    raw_size = os.path.getsize(raw_path)
    if raw_size == 0 or raw_size % 512:
        raise ValueError("raw disk size must be a non-zero multiple of 512 bytes")
    payload_size = ((raw_size + MIB - 1) // MIB) * MIB

    zero_block = b"\0" * (8 * MIB)
    with open(raw_path, "rb") as source, open(vhd_path, "xb") as target:
        while True:
            block = source.read(8 * MIB)
            if not block:
                break
            if block == zero_block[: len(block)]:
                target.seek(len(block), os.SEEK_CUR)
            else:
                target.write(block)
        target.truncate(payload_size)

    relocate_backup_gpt(vhd_path, payload_size)
    digest = payload_digest(vhd_path, payload_size)
    with open(vhd_path, "r+b") as target:
        target.seek(payload_size)
        target.write(build_footer(payload_size, digest))

    check(vhd_path)


def payload_digest(path: str, payload_size: int) -> bytes:
    digest = hashlib.sha256()
    remaining = payload_size
    with open(path, "rb") as stream:
        while remaining:
            block = stream.read(min(8 * MIB, remaining))
            if not block:
                raise ValueError("VHD ended before its footer")
            digest.update(block)
            remaining -= len(block)
    return digest.digest()


def content_uuid(path: str, payload_size: int) -> bytes:
    value = bytearray(payload_digest(path, payload_size)[:16])
    value[6] = (value[6] & 0x0F) | 0x50
    value[8] = (value[8] & 0x3F) | 0x80
    return bytes(value)


def footer_checksum(footer: bytes) -> int:
    candidate = bytearray(footer)
    candidate[CHECKSUM_OFFSET : CHECKSUM_OFFSET + 4] = b"\0" * 4
    return (~sum(candidate)) & 0xFFFFFFFF


def read_footer(path: str) -> tuple[int, bytearray]:
    file_size = os.path.getsize(path)
    if file_size < FOOTER_SIZE:
        raise ValueError("file is too small to contain a VHD footer")
    with open(path, "rb") as stream:
        stream.seek(-FOOTER_SIZE, os.SEEK_END)
        footer = bytearray(stream.read(FOOTER_SIZE))
    return file_size, footer


def canonicalize(path: str) -> None:
    file_size, footer = read_footer(path)
    if footer[:8] != COOKIE:
        raise ValueError("missing fixed-VHD 'conectix' footer")

    payload_size = file_size - FOOTER_SIZE
    if payload_size <= 0 or payload_size % MIB:
        raise ValueError("fixed VHD payload must be a positive MiB-aligned size")
    footer = build_footer(payload_size, payload_digest(path, payload_size))

    with open(path, "r+b") as stream:
        stream.seek(-FOOTER_SIZE, os.SEEK_END)
        stream.write(footer)
    check(path)


def validate(path: str) -> dict[str, object]:
    file_size, footer = read_footer(path)
    payload_size = file_size - FOOTER_SIZE
    errors: list[str] = []

    if footer[:8] != COOKIE:
        errors.append("footer cookie is not 'conectix'")
    if struct.unpack_from(">I", footer, 8)[0] != 2:
        errors.append("footer feature flags are not canonical")
    if struct.unpack_from(">I", footer, 12)[0] != 0x00010000:
        errors.append("footer format version is invalid")
    if struct.unpack_from(">Q", footer, 16)[0] != 0xFFFFFFFFFFFFFFFF:
        errors.append("data offset does not identify a fixed VHD")
    if struct.unpack_from(">I", footer, 60)[0] != 2:
        errors.append("disk type is not fixed VHD")
    if footer[28:32] != b"hbox":
        errors.append("footer creator application is not canonical")
    if struct.unpack_from(">I", footer, 32)[0] != 0x00010000:
        errors.append("footer creator version is not canonical")
    if footer[36:40] != b"Lnx ":
        errors.append("footer creator host OS is not canonical")

    original_size = struct.unpack_from(">Q", footer, 40)[0]
    current_size = struct.unpack_from(">Q", footer, 48)[0]
    if original_size != payload_size or current_size != payload_size:
        errors.append("footer size fields do not match the VHD payload")
    if payload_size % MIB:
        errors.append("virtual disk size is not aligned to 1 MiB")
    if payload_size <= 0 or payload_size % SECTOR_SIZE:
        errors.append("virtual disk size is invalid")
    if file_size != current_size + FOOTER_SIZE:
        errors.append("fixed VHD must be payload size plus one 512-byte footer")
    if struct.unpack_from(">I", footer, TIMESTAMP_OFFSET)[0] != 0:
        errors.append("footer timestamp is not canonical")
    if footer[UUID_OFFSET : UUID_OFFSET + 16] != content_uuid(path, payload_size):
        errors.append("footer UUID is not derived from payload content")
    if footer[56:60] != disk_geometry(payload_size):
        errors.append("footer disk geometry is not canonical")
    if footer[84] != 0 or footer[85:] != b"\0" * (FOOTER_SIZE - 85):
        errors.append("footer saved-state or reserved fields are not canonical")

    stored_checksum = struct.unpack_from(">I", footer, CHECKSUM_OFFSET)[0]
    if stored_checksum != footer_checksum(footer):
        errors.append("footer checksum is invalid")

    gpt = check_gpt(path, payload_size, errors)

    if errors:
        raise ValueError("; ".join(errors))

    return {
        "fileSizeBytes": file_size,
        "payloadSizeBytes": payload_size,
        "footer": footer,
        "partitionTable": "GPT",
        "efiSystemPartitions": gpt["efiSystemPartitions"],
    }


def check(path: str) -> None:
    metadata = validate(path)
    payload_size = metadata["payloadSizeBytes"]
    file_size = metadata["fileSizeBytes"]

    print(
        f"valid fixed VHD: payload={payload_size} bytes, "
        f"file={file_size} bytes, sha256={file_sha256(path)}"
    )


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(8 * MIB), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "canonicalize", "check"))
    parser.add_argument("path")
    parser.add_argument("output", nargs="?")
    args = parser.parse_args()

    try:
        if args.command == "create":
            if args.output is None:
                parser.error("create requires INPUT.raw and OUTPUT.vhd")
            create(args.path, args.output)
        elif args.output is not None:
            parser.error(f"{args.command} accepts exactly one path")
        elif args.command == "canonicalize":
            canonicalize(args.path)
        else:
            check(args.path)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
