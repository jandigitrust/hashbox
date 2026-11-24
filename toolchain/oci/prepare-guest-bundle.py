#!/usr/bin/env python3
"""Verify the selected OCI hello archive and prepare its Guix guest bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_blob(archive: tarfile.TarFile, descriptor: dict) -> bytes:
    identity = descriptor["digest"]
    if SHA.fullmatch(identity) is None:
        raise ValueError("invalid OCI descriptor digest")
    member = archive.getmember("blobs/sha256/" + identity[7:])
    if not member.isfile() or member.size != descriptor["size"]:
        raise ValueError("OCI descriptor size differs")
    source = archive.extractfile(member)
    if source is None:
        raise ValueError("OCI descriptor is unreadable")
    payload = source.read()
    if len(payload) != descriptor["size"] or digest(payload) != identity:
        raise ValueError("OCI descriptor bytes differ")
    return payload


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256) or SHA.fullmatch(args.manifest_digest) is None:
        raise ValueError("invalid expected OCI digest")
    if not re.fullmatch(r"[0-9a-f]{16}", args.run_id):
        raise ValueError("invalid run ID")
    if args.output.exists() or not args.output.parent.is_dir():
        raise ValueError("OCI output must be absent under an existing directory")
    if args.archive.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("OCI archive exceeds demo bound")
    archive_bytes = args.archive.read_bytes()
    if hashlib.sha256(archive_bytes).hexdigest() != args.archive_sha256:
        raise ValueError("transferred OCI archive SHA-256 differs")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        layout = json.load(archive.extractfile("oci-layout"))
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise ValueError("OCI layout version differs")
        index = json.load(archive.extractfile("index.json"))
        entries = index.get("manifests") or []
        if len(entries) != 1 or entries[0].get("platform") != {"architecture": "amd64", "os": "linux"}:
            raise ValueError("OCI index must select one linux/amd64 image")
        if entries[0].get("digest") != args.manifest_digest:
            raise ValueError("OCI manifest digest differs")
        manifest = json.loads(read_blob(archive, entries[0]))
        config_descriptor = manifest["config"]
        config = json.loads(read_blob(archive, config_descriptor))
        if config.get("architecture") != "amd64" or config.get("os") != "linux":
            raise ValueError("OCI image platform differs")
        if (config.get("config") or {}).get("Entrypoint") != ["/bin/httpd", "-f", "-p", "80", "-h", "/www"]:
            raise ValueError("selected hello image entrypoint differs")
        layers = manifest.get("layers") or []
        diff_ids = (config.get("rootfs") or {}).get("diff_ids") or []
        if len(layers) != 2 or len(diff_ids) != len(layers):
            raise ValueError("selected hello image layer count differs")
        extracted_layers = []
        for position, descriptor in enumerate(layers):
            if descriptor.get("mediaType") != "application/vnd.oci.image.layer.v1.tar+gzip":
                raise ValueError("selected OCI layer encoding differs")
            compressed = read_blob(archive, descriptor)
            plain = gzip.decompress(compressed)
            if digest(plain) != diff_ids[position]:
                raise ValueError("OCI uncompressed layer digest differs")
            extracted_layers.append((descriptor["digest"], plain))

    args.output.mkdir(mode=0o700)
    rootfs = args.output / "rootfs"
    rootfs.mkdir(mode=0o700)
    for _, plain in extracted_layers:
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as layer:
            if any(member.name.rsplit("/", 1)[-1].startswith(".wh.") for member in layer):
                raise ValueError("selected hello layer unexpectedly has whiteouts")
            layer.extractall(rootfs, filter="data")
    if (rootfs / "www/index.html").read_bytes() != b"Hello, HashBox!\n":
        raise ValueError("selected hello response body differs")
    if (rootfs / "www/healthz").read_bytes() != b"healthy\n":
        raise ValueError("selected hello health response differs")
    if not (rootfs / "bin/httpd").is_file():
        raise ValueError("selected hello runtime binary is absent")

    spec = subprocess.run([str(args.runtime), "spec", "--rootless"], cwd=args.output,
                          capture_output=True, text=True, timeout=30, check=True)
    if spec.stdout or spec.stderr:
        raise ValueError("rootless runc spec emitted unexpected output")
    config_path = args.output / "config.json"
    runtime_config = json.loads(config_path.read_text())
    if runtime_config["linux"].get("uidMappings") != [
        {"containerID": 0, "hostID": os.getuid(), "size": 1}
    ] or runtime_config["linux"].get("gidMappings") != [
        {"containerID": 0, "hostID": os.getgid(), "size": 1}
    ]:
        raise ValueError("rootless runc UID/GID mapping differs")
    if any(item.get("type") == "network" for item in runtime_config["linux"]["namespaces"]):
        raise ValueError("rootless hello must share only the guest network namespace")
    # This Guix guest has no mounted cgroup filesystem. The launcher creates a
    # temporary user/mount/cgroup namespace and mounts cgroup2 there. A second
    # user namespace in this OCI config would require an unavailable gid map.
    cgroup_mounts = [item for item in runtime_config["mounts"]
                     if item.get("destination") == "/sys/fs/cgroup"]
    if len(cgroup_mounts) != 1 or cgroup_mounts[0].get("type") != "cgroup":
        raise ValueError("rootless runc cgroup mount differs")
    runtime_config["mounts"] = [item for item in runtime_config["mounts"]
                                 if item.get("destination") != "/sys/fs/cgroup"]
    user_namespaces = [item for item in runtime_config["linux"]["namespaces"]
                       if item.get("type") == "user"]
    if user_namespaces != [{"type": "user"}]:
        raise ValueError("rootless runc user namespace differs")
    runtime_config["linux"]["namespaces"] = [item for item in runtime_config["linux"]["namespaces"]
                                                if item.get("type") != "user"]
    runtime_config["linux"].pop("uidMappings")
    runtime_config["linux"].pop("gidMappings")
    runtime_config["process"].update({
        "terminal": False,
        "args": ["/bin/httpd", "-f", "-p", "127.0.0.1:18080", "-h", "/www"],
        "cwd": "/",
        "env": ["PATH=/bin:/usr/bin"],
        "noNewPrivileges": True,
        "capabilities": {name: [] for name in
                         ("bounding", "effective", "inheritable", "permitted", "ambient")},
    })
    runtime_config["root"] = {"path": "rootfs", "readonly": True}
    runtime_config["annotations"] = {
        "org.hashbox.demo.run": args.run_id,
        "org.opencontainers.image.digest": args.manifest_digest,
    }
    config_path.write_text(json.dumps(runtime_config, sort_keys=True, indent=2) + "\n")
    config_path.chmod(0o600)
    print(json.dumps({
        "archive_sha256": args.archive_sha256,
        "manifest_digest": args.manifest_digest,
        "config_digest": config_descriptor["digest"],
        "layer_digests": [identity for identity, _ in extracted_layers],
        "bundle": str(args.output),
        "runtime_config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "rootfs_index_sha256": hashlib.sha256((rootfs / "www/index.html").read_bytes()).hexdigest(),
        "rootfs_health_sha256": hashlib.sha256((rootfs / "www/healthz").read_bytes()).hexdigest(),
        "process_args": runtime_config["process"]["args"],
        "host_uid": os.getuid(), "host_gid": os.getgid(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
