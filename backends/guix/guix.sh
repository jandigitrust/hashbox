#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
channels_file=$project_dir/backends/guix/channels.scm

python3 -I -B "$project_dir/toolchain/release/verify_guix_identity.py" \
  --channels "$channels_file" >/dev/null
exec guix "$@"
