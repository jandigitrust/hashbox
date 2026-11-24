#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
output_dir=$project_dir/dist
artifact=$output_dir/HashBox-azure-gen2-x86_64.vhd
checksum=$artifact.sha256
[ ! -e "$artifact" ] && [ ! -L "$artifact" ] || {
  echo "error: VHD already exists; retain it and use a fresh output directory" >&2
  exit 1
}
[ ! -e "$checksum" ] && [ ! -L "$checksum" ] || {
  echo "error: VHD checksum already exists; retain it" >&2
  exit 1
}
mkdir -p -m 700 "$output_dir"
raw_image=$("$project_dir/toolchain/release/build-raw.sh")
[ -f "$raw_image" ] || {
  echo "error: Guix did not return a raw image file" >&2
  exit 1
}
"$project_dir/toolchain/disk/raw-to-vhd.sh" "$raw_image" "$artifact"
python3 -I -B "$project_dir/toolchain/disk/vhd.py" check "$artifact"
python3 -I -B - "$artifact" "$checksum" <<'PYCODE'
import hashlib
import os
import sys
from pathlib import Path
artifact = Path(sys.argv[1])
checksum = Path(sys.argv[2])
digest = hashlib.sha256()
with artifact.open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, 'O_NOFOLLOW'):
    flags |= os.O_NOFOLLOW
descriptor = os.open(checksum, flags, 0o600)
with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
    stream.write(f"{digest.hexdigest()}  {artifact.name}\n")
print(f"VHD: {artifact}")
print(f"SHA-256: {digest.hexdigest()}")
PYCODE
