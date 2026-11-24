#!/bin/sh
# Install the signed Microsoft Azure CLI package for managed-identity Blob I/O.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "error: install-azure-cli.sh requires root" >&2; exit 2; }
if command -v az >/dev/null 2>&1; then az version --output none; exit 0; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg
work=$(mktemp -d /var/tmp/hashbox-azure-cli-install.XXXXXX)
chmod 0700 "$work"
curl --fail --location --retry 3 --output "$work/microsoft.asc" https://packages.microsoft.com/keys/microsoft.asc
fingerprint=$(gpg --batch --show-keys --with-colons "$work/microsoft.asc" \
  | awk -F: '$1 == "fpr" { print $10; exit }')
[ "$fingerprint" = BC528686B50D79E339D3721CEB3E94ADBE1229CF ] || {
  echo "error: Microsoft package signing fingerprint differs" >&2
  exit 1
}
mkdir -p /etc/apt/keyrings
gpg --batch --dearmor --output /etc/apt/keyrings/microsoft.gpg "$work/microsoft.asc"
chmod 0644 /etc/apt/keyrings/microsoft.gpg
cat > /etc/apt/sources.list.d/azure-cli.sources <<'SOURCES'
Types: deb
URIs: https://packages.microsoft.com/repos/azure-cli/
Suites: noble
Components: main
Architectures: amd64
Signed-by: /etc/apt/keyrings/microsoft.gpg
SOURCES
apt-get update
apt-get install -y --no-install-recommends azure-cli
az version --output none
rm -rf -- "$work"
