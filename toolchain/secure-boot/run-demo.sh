#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
[ "$#" -eq 3 ] || { echo "usage: $0 BASE.vhd SOURCE_SHA256 OUTPUT_DIRECTORY" >&2; exit 2; }
exec "$project_dir/backends/guix/guix.sh" shell --pure \
  -m "$project_dir/backends/guix/manifests/secure-boot-tools.scm" -- \
  sh "$project_dir/toolchain/secure-boot/build-demo.sh" "$@"
