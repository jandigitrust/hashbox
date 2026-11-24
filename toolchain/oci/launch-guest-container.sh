#!/bin/sh
# Launch the selected OCI bundle on the Guix CVM without changing the host.
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: launch-guest-container.sh BUNDLE CRUN STATE_DIR CONTAINER_ID" >&2
    exit 2
fi

bundle=$1
runtime=$2
state_dir=$3
container_id=$4

umask 077
log=$state_dir/$container_id.log
if unshare -Ur -m -C sh -c '
    set -eu
    mount -t cgroup2 cgroup2 /sys/fs/cgroup
    exec "$@"
' sh "$runtime" --cgroup-manager=disabled --root "$state_dir" run --detach \
    --bundle "$bundle" --pid-file "$bundle/container.pid" "$container_id" \
    </dev/null >"$log" 2>&1; then
    :
else
    code=$?
    tail -n 30 "$log" >&2
    exit "$code"
fi
