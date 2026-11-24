#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
image="$project_dir/dist/HashBox-azure-gen2-x86_64.vhd"

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is required to validate the VHD footer" >&2
  exit 127
fi
if [ ! -f "$image" ]; then
  echo "error: image not found: $image (run 'make image' first)" >&2
  exit 1
fi

python3 -I -B "$project_dir/toolchain/disk/vhd.py" check "$image"
