#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 INPUT.raw OUTPUT.vhd" >&2
  exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
input_file=$1
output_file=$2

python3 -I -B "$script_dir/vhd.py" create "$input_file" "$output_file"
