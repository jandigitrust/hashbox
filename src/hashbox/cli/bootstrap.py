#!/usr/bin/env python3
"""Repository-checkout bootstrap for the installable HashBox controller."""

from pathlib import Path
import os
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from hashbox.cli import main


if __name__ == "__main__":
    raise SystemExit(main(project_root=None if os.environ.get("HASHBOX_PROJECT_ROOT") else ROOT))
