"""Refuse Azure mutations when the tracked ARM template set has drifted."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re


LOCK_SCHEMA = "hashbox.demo-arm-template-lock/v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def verify(root: Path) -> None:
    try:
        lock = json.loads((root / "ARM_TEMPLATE_LOCK.json").read_text(encoding="utf-8"))
        expected = lock["templates"]
        if lock["schema"] != LOCK_SCHEMA or not isinstance(lock["revision"], int):
            raise ValueError("ARM template lock schema or revision differs")
        if not isinstance(expected, dict) or not expected:
            raise ValueError("ARM template lock has no entries")
        actual = {path.relative_to(root).as_posix() for path in (root / "infra").rglob("*.arm.json")}
        if actual != set(expected):
            raise ValueError("ARM template set differs from the tracked lock")
        for relative, digest in expected.items():
            path = root / relative
            if path.is_symlink() or SHA256.fullmatch(digest) is None:
                raise ValueError(f"invalid ARM template lock entry: {relative}")
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError(f"ARM template changed without lock update: {relative}")
            if not isinstance(json.loads(data), dict):
                raise ValueError(f"ARM template is not a JSON object: {relative}")
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as error:
        raise ValueError(f"cannot verify ARM template lock: {error}") from error
