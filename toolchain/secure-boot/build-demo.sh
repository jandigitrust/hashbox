#!/bin/sh
# Derive a Secure Boot VHD from the exact Guix base VHD without a Git release bundle.
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 BASE.vhd SOURCE_ARCHIVE_SHA256 OUTPUT_DIRECTORY" >&2
  exit 2
fi
base=$1
source_sha=$2
output=$3
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
case "$source_sha" in
  *[!0-9a-f]*|'') echo "error: invalid source archive digest" >&2; exit 2 ;;
esac
[ "${#source_sha}" -eq 64 ] || { echo "error: invalid source archive digest" >&2; exit 2; }
[ -f "$base" ] && [ ! -L "$base" ] || { echo "error: base VHD is missing" >&2; exit 2; }
[ ! -e "$output" ] && [ ! -L "$output" ] || {
  echo "error: output directory already exists" >&2
  exit 2
}
for tool in cmp mcopy openssl python3 sbsign sbverify sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: missing Secure Boot tool: $tool" >&2; exit 127; }
done
[ -d /dev/shm ] && [ "$(stat -f -c %T /dev/shm)" = tmpfs ] || {
  echo "error: /dev/shm must be tmpfs for the disposable signing key" >&2
  exit 1
}
umask 077
secrets=$(mktemp -d /dev/shm/hashbox-demo-sign.XXXXXX)
work=$(mktemp -d "${TMPDIR:-/tmp}/hashbox-demo-uki.XXXXXX")
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -f -- "$secrets/db.key"
  rmdir -- "$secrets" || status=1
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -m 0700 -- "$output"
artifact=$output/HashBox-demo-secureboot-x86_64.vhd
certificate=$output/uefi-db.der
metadata=$output/metadata.json
key=$secrets/db.key
pem=$work/db.pem
unsigned=$work/BOOTX64.unsigned.EFI
signed=$work/BOOTX64.signed.EFI
observed=$work/BOOTX64.observed.EFI

python3 -I -B "$project_dir/toolchain/disk/vhd.py" check "$base" >/dev/null
openssl req -new -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout "$key" -out "$pem" -days 7 -subj /CN=HashBox-Demo-UEFI-DB >/dev/null 2>&1
chmod 0600 "$key"
openssl x509 -in "$pem" -outform DER -out "$certificate"
cp --reflink=never --sparse=always -- "$base" "$artifact"
python3 -I -B "$project_dir/toolchain/secure-boot/uki.py" \
  --source-artifact "$base" --output "$unsigned"
sbsign --key "$key" --cert "$pem" --output "$signed" "$unsigned" >/dev/null
sbverify --cert "$pem" "$signed" >/dev/null
python3 -I -B - "$unsigned" "$signed" "$project_dir" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[3]) / 'toolchain/secure-boot'))
import uki
uki.verify_signed_payload(Path(sys.argv[1]).read_bytes(), Path(sys.argv[2]).read_bytes())
PY
# The private key is no longer needed after the signed entry is verified.
rm -- "$key"
key=

offset=$(python3 -I -B - "$artifact" "$project_dir" <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path(sys.argv[2]) / 'toolchain/secure-boot'))
import esp
print(esp.locate_single_esp(Path(sys.argv[1])))
PY
)
MTOOLSRC=/dev/null mcopy -o -m -i "$artifact@@$offset" "$signed" ::/EFI/BOOT/BOOTX64.EFI
python3 -I -B "$project_dir/toolchain/disk/vhd.py" canonicalize "$artifact" >/dev/null
MTOOLSRC=/dev/null mcopy -n -i "$artifact@@$offset" ::/EFI/BOOT/BOOTX64.EFI "$observed"
cmp -s "$signed" "$observed" || { echo "error: VHD does not retain the signed EFI entry" >&2; exit 1; }
sbverify --cert "$pem" "$observed" >/dev/null
python3 -I -B "$project_dir/toolchain/disk/vhd.py" check "$artifact" >/dev/null
python3 -I -B - "$base" "$artifact" "$certificate" "$signed" "$source_sha" "$metadata" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import hashlib,json,sys

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()
base,artifact,cert,entry,source_sha,output=sys.argv[1:]
record={
    'schema':'hashbox.demo-secure-boot/v1',
    'created_at':datetime.now(timezone.utc).isoformat(timespec='seconds'),
    'source_archive_sha256':source_sha,
    'base_vhd_sha256':digest(base),
    'base_vhd_size':Path(base).stat().st_size,
    'derived_vhd_sha256':digest(artifact),
    'derived_vhd_size':Path(artifact).stat().st_size,
    'uefi_db_certificate_sha256':digest(cert),
    'signed_efi_entry_sha256':digest(entry),
}
Path(output).write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
PY
chmod 0644 "$artifact" "$certificate" "$metadata"
echo "$artifact"
