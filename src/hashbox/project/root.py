"""Resolve the repository data root for checkout and installed controllers."""

from __future__ import annotations

import os
from pathlib import Path


def repository_root(fallback: Path) -> Path:
    configured = os.environ.get("HASHBOX_PROJECT_ROOT")
    root = Path(configured).expanduser().resolve() if configured else fallback.resolve()
    if not (root / "hashbox.toml").is_file() or not (root / "Makefile").is_file():
        raise RuntimeError(f"invalid HashBox project root: {root}")
    return root
