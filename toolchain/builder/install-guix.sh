#!/bin/sh
# Install the authenticated GNU Guix 1.5.0 bootstrap on a fresh Ubuntu builder.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "error: install-guix.sh requires root" >&2; exit 2; }
if command -v guix >/dev/null 2>&1 && [ -S /var/guix/daemon-socket/socket ]; then
  guix --version | grep -F '1.5.0' >/dev/null || {
    echo "error: unexpected existing Guix bootstrap version" >&2
    exit 1
  }
  exit 0
fi
[ ! -e /gnu/store ] && [ ! -e /var/guix ] || {
  echo "error: incomplete Guix installation exists; inspect it before retrying" >&2
  exit 1
}
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl git gnupg make netbase procps python3 xz-utils
work=$(mktemp -d /var/tmp/hashbox-guix-install.XXXXXX)
chmod 0700 "$work"
archive=$work/guix-binary-1.5.0.x86_64-linux.tar.xz
signature=$archive.sig
curl --fail --location --retry 3 --output "$archive" https://ftp.gnu.org/gnu/guix/guix-binary-1.5.0.x86_64-linux.tar.xz
curl --fail --location --retry 3 --output "$signature" https://ftp.gnu.org/gnu/guix/guix-binary-1.5.0.x86_64-linux.tar.xz.sig
GNUPGHOME=$work/gnupg
export GNUPGHOME
mkdir -m 0700 "$GNUPGHOME"
curl --fail --location --retry 3 https://codeberg.org/efraim.gpg | gpg --batch --import
fingerprint=$(gpg --batch --with-colons --fingerprint A28BF40C3E551372662D14F741AAE7DCCA3D8351 \
  | awk -F: '$1 == "fpr" { print $10; exit }')
[ "$fingerprint" = A28BF40C3E551372662D14F741AAE7DCCA3D8351 ] || {
  echo "error: Guix release signing fingerprint differs" >&2
  exit 1
}
gpg --batch --verify "$signature" "$archive"
tar --extract --xz --file "$archive" --directory /
if ! getent group guixbuild >/dev/null; then groupadd --system guixbuild; fi
for number in $(seq -w 1 10); do
  if ! id "guixbuilder$number" >/dev/null 2>&1; then
    useradd --system --gid guixbuild --groups guixbuild \
      --home-dir /var/empty --shell /usr/sbin/nologin \
      --comment "Guix build user $number" "guixbuilder$number"
  fi
done
mkdir -p /root/.config/guix /root/.cache/guix /etc/guix /var/guix/daemon-socket
ln -s /var/guix/profiles/per-user/root/current-guix /root/.guix-profile
ln -s /var/guix/profiles/per-user/root/current-guix/bin/guix /usr/local/bin/guix
ln -s /var/guix/profiles/per-user/root/current-guix/bin/guix-daemon /usr/local/bin/guix-daemon
cat > /etc/systemd/system/guix-daemon.service <<'UNIT'
[Unit]
Description=GNU Guix build daemon for the HashBox demo builder
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/guix-daemon --build-users-group=guixbuild --substitute-urls=https://bordeaux.guix.gnu.org
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now guix-daemon.service
attempt=0
while [ ! -S /var/guix/daemon-socket/socket ]; do
  attempt=$((attempt + 1))
  [ "$attempt" -le 100 ] || { echo "error: guix-daemon socket did not become ready" >&2; exit 1; }
  sleep 1
done
guix archive --authorize < /root/.guix-profile/share/guix/ci.guix.gnu.org.pub
if [ -f /root/.guix-profile/share/guix/bordeaux.guix.gnu.org.pub ]; then
  guix archive --authorize < /root/.guix-profile/share/guix/bordeaux.guix.gnu.org.pub
fi
guix --version
su -s /bin/sh hashbox-builder -c 'guix --version'
su -s /bin/sh hashbox-builder -c 'guix build hello --dry-run'
rm -rf -- "$work"
