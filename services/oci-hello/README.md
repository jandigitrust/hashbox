# HashBox OCI hello

This minimal service serves `Hello, HashBox!` at `/` and `healthy` at
`/healthz`. Its Dockerfile pins the linux/amd64 BusyBox base manifest. The
image entrypoint listens on container port 80.

`compose.yaml` is a digest placeholder for a newly built image; replace it
with that image's manifest digest before using Compose.

`toolchain/oci/prepare-guest-bundle.py` prepares a guest bundle from a verified
OCI archive. `toolchain/oci/launch-guest-container.sh` starts it with static
`crun` in a rootless user, mount and cgroup namespace. The launcher exposes the
service only on guest loopback port 18080; access from the operator uses a
pinned SSH tunnel, without an additional Azure network rule. Image digest,
container identity, launch command and observed response belong in each
owner-only run record. OCI launch is separate from the demo CLI.
