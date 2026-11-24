#!/usr/bin/env python3
"""Unpack the embedded Attestor OCI image for one rootless Guix CVM collector."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE = 1024 * 1024 * 1024


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_blob(layout: Path, descriptor: dict) -> bytes:
    name = descriptor.get("digest", "")
    if not SHA.fullmatch(name):
        raise ValueError("invalid OCI descriptor digest")
    path = layout / "blobs" / "sha256" / name[7:]
    if not path.is_file() or path.stat().st_size != descriptor.get("size"):
        raise ValueError("OCI descriptor size differs")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != name[7:]:
        raise ValueError("OCI descriptor bytes differ")
    return data


def unpack_layout(archive: Path, layout: Path) -> None:
    layout.mkdir(mode=0o700)
    total = 0
    with tarfile.open(archive, "r:") as source:
        for member in source:
            relative = PurePosixPath(member.name)
            parts = relative.parts
            if not parts or parts == (".",):
                continue
            if member.isdir() and parts in {("blobs",), ("blobs", "sha256")}:
                continue
            allowed = (parts in {("oci-layout",), ("index.json",)} or
                       len(parts) == 3 and parts[:2] == ("blobs", "sha256") and
                       HEX.fullmatch(parts[2]) is not None)
            if not allowed or not member.isfile() or member.size > MAX_ARCHIVE:
                raise ValueError("OCI archive contains an unexpected member")
            total += member.size
            if total > MAX_ARCHIVE:
                raise ValueError("OCI layout exceeds size bound")
            target = layout.joinpath(*parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            payload = source.extractfile(member)
            if payload is None:
                raise ValueError("OCI archive member is unreadable")
            with target.open("xb") as stream:
                for block in iter(lambda: payload.read(1024 * 1024), b""):
                    stream.write(block)


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{16}", args.run_id):
        raise ValueError("invalid run ID")
    if args.output.exists() or not args.output.parent.is_dir():
        raise ValueError("bundle output must be absent under an existing directory")

    archive = Path("/etc/hashbox/attestor.oci.tar")
    metadata = json.loads(Path("/etc/hashbox/attestor.oci.json").read_text())
    source_lock = json.loads(Path("/etc/hashbox/attestor-source-lock.json").read_text())
    if (archive.stat().st_size > MAX_ARCHIVE or
            file_sha256(archive) != metadata.get("archive_sha256") or
            source_lock.get("commit") != metadata.get("commit") or
            source_lock.get("tree") != metadata.get("tree") or
            not SHA.fullmatch(metadata.get("manifest_digest", ""))):
        raise ValueError("embedded Attestor OCI identity differs")
    ima = Path("/sys/kernel/security/ima/ascii_runtime_measurements")
    if not ima.is_file() or not os.access(ima, os.R_OK):
        raise ValueError("IMA measurements are unavailable to the collector")
    if not os.access("/dev/tpm0", os.R_OK | os.W_OK):
        raise ValueError("operator lacks vTPM device access")

    layout = args.output / "layout"
    args.output.mkdir(mode=0o700)
    unpack_layout(archive, layout)
    if json.loads((layout / "oci-layout").read_text()) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("OCI layout version differs")
    index_path = layout / "index.json"
    index = json.loads(index_path.read_text())
    manifests = index.get("manifests") or []
    if len(manifests) != 1 or manifests[0].get("digest") != metadata["manifest_digest"]:
        raise ValueError("OCI index manifest differs")
    manifest = json.loads(checked_blob(layout, manifests[0]))
    config = json.loads(checked_blob(layout, manifest["config"]))
    if (config.get("architecture") != "amd64" or config.get("os") != "linux" or
            (config.get("config") or {}).get("Entrypoint") != ["/usr/local/bin/attestor-server"]):
        raise ValueError("Attestor OCI platform or entrypoint differs")
    for descriptor in manifest.get("layers") or []:
        checked_blob(layout, descriptor)
    manifests[0].setdefault("annotations", {})["org.opencontainers.image.ref.name"] = "hashbox-attestor"
    index_path.write_text(json.dumps(index, sort_keys=True) + "\n")

    # umoci provides the OCI rootfs and config; only the mounts and process
    # settings needed for this guest are changed below.
    bundle = args.output / "bundle"
    subprocess.run(["umoci", "unpack", "--rootless", "--image",
                    f"{layout}:hashbox-attestor", str(bundle)], check=True, timeout=600)
    config_path = bundle / "config.json"
    runtime = json.loads(config_path.read_text())
    linux = runtime["linux"]
    linux["namespaces"] = [item for item in linux.get("namespaces", [])
                           if item.get("type") not in {"network", "user"}]
    linux.pop("uidMappings", None)
    linux.pop("gidMappings", None)
    linux.pop("cgroupsPath", None)
    # The launcher creates its own user, mount and cgroup namespaces. Retain
    # the host network namespace so guest loopback is reachable over SSH.
    runtime["mounts"] = [item for item in runtime.get("mounts", [])
                         if item.get("destination") != "/sys/fs/cgroup"]
    certs = args.output / "certs"
    certs.mkdir(mode=0o700)
    (bundle / "rootfs/certs").mkdir(exist_ok=True)
    (bundle / "rootfs/sys/kernel/security").mkdir(parents=True, exist_ok=True)
    mounts = [(str(certs), "/certs", ["rbind", "rw"]),
              ("/sys/kernel/security", "/sys/kernel/security", ["rbind", "ro"])]
    for device in ("/dev/tpm0", "/dev/tpmrm0", "/dev/sev-guest"):
        if Path(device).exists():
            if not os.access(device, os.R_OK | os.W_OK):
                raise ValueError(f"operator lacks {device} access")
            target = bundle / "rootfs" / device.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.touch(exist_ok=True)
            mounts.append((device, device, ["bind", "rw"]))
    runtime["mounts"].extend({"source": source, "destination": target,
                              "type": "bind", "options": options}
                             for source, target, options in mounts)
    process = runtime["process"]
    process["args"] = ["/usr/local/bin/attestor-server", "127.0.0.1:18001",
                       "/certs", "sha256", "--tls-hostname", "localhost"]
    process["cwd"] = "/"
    process["terminal"] = False
    process["noNewPrivileges"] = True
    process["user"] = {"uid": 0, "gid": 0}
    process["capabilities"] = {key: [] for key in
                               ("bounding", "effective", "inheritable", "permitted", "ambient")}
    runtime["root"] = {"path": "rootfs", "readonly": True}
    runtime["annotations"] = {"org.hashbox.run": args.run_id,
                              "org.hashbox.attestor.commit": metadata["commit"],
                              "org.opencontainers.image.digest": metadata["manifest_digest"]}
    config_path.write_text(json.dumps(runtime, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"bundle": str(bundle), "certs": str(certs),
                      "runtime_config_sha256": file_sha256(config_path),
                      "archive_sha256": metadata["archive_sha256"],
                      "manifest_digest": metadata["manifest_digest"],
                      "attestor_commit": metadata["commit"],
                      "ima_entries": sum(1 for _ in ima.open())}, sort_keys=True))


if __name__ == "__main__":
    main()
