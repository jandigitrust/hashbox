#!/bin/sh
# Build the pinned current-main Attestor OCI artifact on the native Azure builder.
set -eu

[ "$(uname -m)" = x86_64 ] || { echo 'Attestor image build needs native x86_64' >&2; exit 1; }
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
if ! command -v docker >/dev/null 2>&1 || ! docker buildx version >/dev/null 2>&1; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io docker-buildx
fi
sudo systemctl enable --now docker.service
mkdir -p -m 700 "$project_dir/dist"
wrapper_dir=$(mktemp -d "$project_dir/dist/.docker-wrapper.XXXXXX")
trap 'rm -rf -- "$wrapper_dir"' EXIT HUP INT TERM
cat > "$wrapper_dir/docker" <<'WRAPPER'
#!/bin/sh
exec sudo /usr/bin/docker "$@"
WRAPPER
chmod 700 "$wrapper_dir/docker"
cd "$project_dir"
PATH="$wrapper_dir:$PATH" PYTHONPATH="$project_dir/src" python3 - <<'PYCODE'
from pathlib import Path
from hashbox.source.attestor import build_for_image

identity = build_for_image(Path.cwd())
print('Attestor commit:', identity['commit'])
print('Attestor OCI manifest:', identity['manifest_digest'])
print('Attestor OCI archive SHA-256:', identity['archive_sha256'])
PYCODE
