#!/usr/bin/env python3
"""Verify that the active Guix command matches the pinned channel commit."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def pinned_commit(channels: Path) -> str:
    commits = re.findall(
        r'\(commit\s+"([0-9a-f]{40})"\)', channels.read_text(encoding="utf-8")
    )
    if len(commits) != 1:
        raise ValueError("channels file must contain exactly one pinned commit")
    return commits[0]


def active_commit(description: str) -> str:
    value = json.loads(description)
    if not isinstance(value, list):
        raise ValueError("guix describe did not return a channel list")
    matches = [item for item in value if item.get("name") == "guix"]
    if len(matches) != 1 or not isinstance(matches[0].get("commit"), str):
        raise ValueError("guix describe did not identify exactly one Guix channel")
    return matches[0]["commit"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channels", type=Path, required=True)
    parser.add_argument("--description-file", type=Path)
    args = parser.parse_args()
    try:
        if args.description_file is None:
            result = subprocess.run(
                ["guix", "describe", "--format=json"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            description = result.stdout
        else:
            description = args.description_file.read_text(encoding="utf-8")
        expected = pinned_commit(args.channels)
        actual = active_commit(description)
        if actual != expected:
            raise ValueError(
                f"active Guix commit {actual} differs from pinned commit {expected}"
            )
        print(actual)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
