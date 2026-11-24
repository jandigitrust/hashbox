"""Read and validate one explicit owner-controlled SSH public-key file."""

from __future__ import annotations

import base64
import binascii
import os
import pathlib
import stat
from dataclasses import dataclass


MAX_PUBLIC_KEY_BYTES = 64 * 1024
SUPPORTED_TYPES = frozenset({"ssh-ed25519", "ssh-rsa"})


class PublicKeyError(ValueError):
    pass


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    public_key: str


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_regular_bytes(path: pathlib.Path) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise PublicKeyError("SSH public-key resolution requires O_NOFOLLOW")
    absolute = pathlib.Path(os.path.abspath(os.path.expanduser(path)))
    descriptor = os.open(
        absolute,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.getuid()
            or before.st_size <= 0
            or before.st_size > MAX_PUBLIC_KEY_BYTES
        ):
            raise PublicKeyError(
                f"SSH public key is not a safe owner-controlled regular file: {absolute}"
            )
        payload = bytearray()
        while True:
            block = os.read(descriptor, 8192)
            if not block:
                break
            payload.extend(block)
            if len(payload) > MAX_PUBLIC_KEY_BYTES:
                raise PublicKeyError(f"SSH public key is too large: {absolute}")
        after = os.fstat(descriptor)
        current = os.lstat(absolute)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current):
            raise PublicKeyError(f"SSH public key changed while read: {absolute}")
        return bytes(payload)
    finally:
        os.close(descriptor)


def parse_public_key(line: str) -> PublicKey:
    if "\x00" in line or "\r" in line or "\n" in line:
        raise PublicKeyError("SSH public key must be one text line")
    fields = line.strip().split()
    if len(fields) < 2:
        raise PublicKeyError("SSH public key has too few fields")
    key_type, encoded = fields[0], fields[1]
    if key_type not in SUPPORTED_TYPES:
        raise PublicKeyError(f"unsupported SSH public-key type: {key_type}")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise PublicKeyError("SSH public key has invalid base64") from error
    if len(decoded) < 16 or len(decoded) > 16 * 1024:
        raise PublicKeyError("SSH public-key payload has an invalid size")
    wire_type_size = int.from_bytes(decoded[:4], "big")
    if wire_type_size <= 0 or wire_type_size > len(decoded) - 4:
        raise PublicKeyError("SSH public key has an invalid wire-format type")
    try:
        wire_type = decoded[4 : 4 + wire_type_size].decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicKeyError("SSH public key has a non-ASCII wire-format type") from error
    if wire_type != key_type:
        raise PublicKeyError("SSH public-key text and wire-format types differ")
    # Comments are deliberately dropped so instance data is canonical.
    return PublicKey(key_type, f"{key_type} {encoded}")


def from_file(path: pathlib.Path) -> PublicKey:
    absolute = pathlib.Path(os.path.abspath(os.path.expanduser(path)))
    try:
        text = _stable_regular_bytes(absolute).decode("utf-8")
    except UnicodeDecodeError as error:
        raise PublicKeyError(f"SSH public key is not UTF-8: {absolute}") from error
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise PublicKeyError(f"SSH public-key file must contain exactly one key: {absolute}")
    return parse_public_key(lines[0])
