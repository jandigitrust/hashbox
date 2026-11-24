#!/bin/sh
set -eu

[ "$#" -eq 0 ] || { echo "usage: $0" >&2; exit 2; }
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
command -v guix >/dev/null 2>&1 || {
  echo "error: Guix is required on the Azure builder" >&2
  exit 127
}
"$project_dir/backends/guix/guix.sh" system image --system=x86_64-linux \
  -L "$project_dir/backends/guix/modules" \
  "$project_dir/backends/guix/images/azure-gen2.scm"
