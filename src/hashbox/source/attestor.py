"""Pinned Attestor source and an advisory upstream revision check."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import tomllib


LOCK = "ATTESTOR_LOCK.json"
SCHEMA = "hashbox.attestor-source/v1"
REPOSITORY = "https://github.com/jandigitrust/attestor.git"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _git(*arguments: str, cwd: Path | None = None, timeout: int = 120) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run(["git", *arguments], cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f"Attestor Git read failed: {result.stderr[-300:].strip()}")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pin(root: Path) -> dict:
    value = json.loads((root / LOCK).read_text(encoding="utf-8"))
    if (value.get("schema") != SCHEMA or value.get("repository") != REPOSITORY or
            value.get("track") != "refs/heads/main" or
            not isinstance(value.get("version"), str) or
            any(HEX40.fullmatch(value.get(key, "")) is None for key in ("commit", "tree")) or
            any(HEX64.fullmatch(value.get(key, "")) is None for key in
                ("cargo_lock_sha256", "cargo_toml_sha256", "license_sha256"))):
        raise ValueError("invalid Attestor source lock")
    return value


def upstream_head(value: dict) -> str:
    result = _git("ls-remote", "--exit-code", value["repository"], value["track"], timeout=25)
    fields = result.split()
    if len(fields) != 2 or fields[1] != value["track"] or HEX40.fullmatch(fields[0]) is None:
        raise ValueError("Attestor upstream returned an invalid branch ref")
    return fields[0]


def advise(root: Path, *, operation: str) -> None:
    """Offer a rebuild before a new image build or CVM deployment; never mutate the pin."""
    value = pin(root)
    try:
        head = upstream_head(value)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        print(f"Attestor update check unavailable before {operation}: {error}; pinned "
              f"{value['version']} at {value['commit']} remains selected.", file=sys.stderr)
        return
    if head != value["commit"]:
        print(f"Attestor upstream has a different revision: {head}; pinned "
              f"{value['version']} at {value['commit']} remains selected.")
        print("To select it: hashbox attestor upgrade; then start a fresh run. "
              "The Azure builder will rebuild Attestor into that run's Guix image. "
              "Existing Gallery versions and CVMs stay unchanged.")


def _checkout(directory: Path, value: dict, revision: str) -> Path:
    source = directory / "source"
    source.mkdir(mode=0o700)
    _git("init", "-q", cwd=source)
    _git("remote", "add", "origin", value["repository"], cwd=source)
    _git("fetch", "--depth=1", "origin", revision, cwd=source, timeout=180)
    _git("checkout", "-q", "--detach", "FETCH_HEAD", cwd=source)
    if _git("rev-parse", "HEAD", cwd=source) != revision:
        raise ValueError("Attestor checkout differs from selected commit")
    return source


def _source_identity(source: Path, value: dict) -> None:
    if _git("rev-parse", "HEAD^{tree}", cwd=source) != value["tree"]:
        raise ValueError("Attestor Git tree differs from the source lock")
    for relative, key in (("server/Cargo.lock", "cargo_lock_sha256"),
                          ("server/Cargo.toml", "cargo_toml_sha256"),
                          ("LICENSE", "license_sha256")):
        if _sha256(source / relative) != value[key]:
            raise ValueError(f"Attestor {relative} differs from the source lock")
    cargo = tomllib.loads((source / "server/Cargo.toml").read_text(encoding="utf-8"))
    if cargo["package"]["name"] != "attestor-server" or cargo["package"]["version"] != value["version"]:
        raise ValueError("Attestor crate name or version differs from the source lock")


def fetch_verified(root: Path, directory: Path) -> tuple[Path, dict]:
    value = pin(root)
    source = _checkout(directory, value, value["commit"])
    _source_identity(source, value)
    return source, value


def upgrade(root: Path) -> dict:
    """Select a verified main-branch descendant; the caller must rebuild afterward."""
    current = pin(root)
    local = root / ".local" / "attestor"
    local.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="upgrade-", dir=local) as temporary:
        source = Path(temporary) / "source"
        _git("clone", "--quiet", "--filter=blob:none", "--branch", "main", "--single-branch",
             current["repository"], str(source), timeout=180)
        revision = _git("rev-parse", "HEAD", cwd=source)
        if revision == current["commit"]:
            return current
        result = subprocess.run(["git", "merge-base", "--is-ancestor", current["commit"], revision],
                                cwd=source, capture_output=True, timeout=20)
        if result.returncode:
            raise ValueError("Attestor upstream revision is not a descendant of the current pin")
        cargo = tomllib.loads((source / "server/Cargo.toml").read_text(encoding="utf-8"))
        package = cargo["package"]
        version = package["version"]
        if package["name"] != "attestor-server" or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ValueError("Attestor upstream crate identity is unsupported")
        if tuple(map(int, version.split("."))) < tuple(map(int, current["version"].split("."))):
            raise ValueError("Attestor upstream version is older than the current pin")
        if "Apache License" not in (source / "LICENSE").read_text(encoding="utf-8"):
            raise ValueError("Attestor upstream licence needs manual review")
        updated = {**current, "version": version, "commit": revision,
                   "tree": _git("rev-parse", "HEAD^{tree}", cwd=source),
                   "cargo_lock_sha256": _sha256(source / "server/Cargo.lock"),
                   "cargo_toml_sha256": _sha256(source / "server/Cargo.toml"),
                   "license_sha256": _sha256(source / "LICENSE")}
        pending = Path(temporary) / LOCK
        pending.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")
        os.chmod(pending, 0o644)
        os.replace(pending, root / LOCK)
        return updated


def _oci_identity(path: Path) -> dict:
    with tarfile.open(path, "r:") as archive:
        index = json.load(archive.extractfile("index.json"))
        manifests = index.get("manifests") or []
        if len(manifests) != 1:
            raise ValueError("Attestor OCI archive must have one manifest")
        def read_blob(descriptor: dict) -> bytes:
            digest = descriptor.get("digest", "")
            if not digest.startswith("sha256:") or HEX64.fullmatch(digest[7:]) is None:
                raise ValueError("invalid Attestor OCI descriptor digest")
            member = archive.getmember("blobs/sha256/" + digest[7:])
            if not member.isfile() or member.size != descriptor.get("size"):
                raise ValueError("Attestor OCI blob size differs")
            payload = archive.extractfile(member).read()
            if hashlib.sha256(payload).hexdigest() != digest[7:]:
                raise ValueError("Attestor OCI blob bytes differ")
            return payload

        manifest = json.loads(read_blob(manifests[0]))
        config = json.loads(read_blob(manifest["config"]))
        layers = manifest.get("layers") or []
        if not layers:
            raise ValueError("Attestor OCI image has no layers")
        for layer in layers:
            read_blob(layer)
        if config.get("architecture") != "amd64" or config.get("os") != "linux":
            raise ValueError("Attestor OCI platform differs")
    return {"archive_sha256": _sha256(path), "manifest_digest": manifests[0]["digest"],
            "config_digest": manifest["config"]["digest"],
            "layer_digests": [layer["digest"] for layer in layers]}


def build(root: Path, *, fetch_only: bool = False, builder_cache: bool = False) -> dict:
    """Fetch the exact source and optionally make a no-replace linux/amd64 OCI archive."""
    local = root / ".local" / "attestor"
    local.mkdir(mode=0o700, parents=True, exist_ok=True)
    value = pin(root)
    if not fetch_only:
        output = local / f"attestor-{value['commit'][:12]}.oci.tar"
        evidence = output.with_suffix(".json")
        if output.exists() or evidence.exists():
            raise ValueError("Attestor OCI output already exists; inspect it before rebuilding")
        host = subprocess.run(["docker", "info", "--format", "{{.OSType}} {{.Architecture}}"],
                              capture_output=True, text=True, timeout=20)
        if host.returncode or host.stdout.strip() not in {"linux x86_64", "linux amd64"}:
            raise ValueError("Attestor OCI build requires a native linux/amd64 Docker host; "
                             "cross-architecture emulation is not part of this demo")
    with tempfile.TemporaryDirectory(prefix="build-", dir=local) as temporary:
        source, selected = fetch_verified(root, Path(temporary))
        if selected != value:
            raise ValueError("Attestor source lock changed during build admission")
        if fetch_only:
            return {"version": value["version"], "commit": value["commit"],
                    "tree": value["tree"], "source_verified": True}
        pending = Path(temporary) / "attestor.oci.tar"
        builder = "hashbox-attestor-cache" if builder_cache else "hashbox-attestor-" + secrets.token_hex(4)
        command = ["docker", "buildx", "build", "--platform", "linux/amd64",
                   "--builder", builder, "--provenance=false", "--sbom=false",
                   "--output", "type=oci,dest=-" if builder_cache else f"type=oci,dest={pending}",
                   "--file", str(root / "services/attestor/Dockerfile"), str(source)]
        existing = subprocess.run(["docker", "buildx", "inspect", builder],
                                  capture_output=True, text=True, timeout=30) if builder_cache else None
        if existing is None or existing.returncode:
            created = subprocess.run(["docker", "buildx", "create", "--driver", "docker-container",
                                      "--name", builder], capture_output=True, text=True, timeout=60)
            if created.returncode:
                raise ValueError(f"could not create Attestor Buildx builder: {created.stderr[-300:]}")
        try:
            if builder_cache:
                with pending.open("xb") as stream:
                    result = subprocess.run(command, stdout=stream, timeout=7200)
            else:
                result = subprocess.run(command, timeout=7200)
        finally:
            if not builder_cache:
                subprocess.run(["docker", "buildx", "rm", "--force", builder],
                               capture_output=True, timeout=120)
        if result.returncode:
            raise ValueError("Attestor OCI build failed")
        identity = _oci_identity(pending)
        identity.update(version=value["version"], commit=value["commit"], tree=value["tree"])
        os.link(pending, output)
        try:
            with evidence.open("x", encoding="utf-8") as stream:
                json.dump(identity, stream, sort_keys=True, indent=2)
                stream.write("\n")
        except BaseException:
            output.unlink(missing_ok=True)
            raise
        return identity


def build_for_image(root: Path) -> dict:
    """On the native Azure builder, produce and retain the exact OCI input to Guix."""
    selected = pin(root)
    head = upstream_head(selected)
    if head != selected["commit"]:
        raise ValueError("Attestor main changed; update ATTESTOR_LOCK.json before building an image")
    local = root / ".local" / "attestor"
    output = local / f"attestor-{selected['commit'][:12]}.oci.tar"
    evidence = output.with_suffix(".json")
    if output.exists() or evidence.exists():
        if not output.is_file() or not evidence.is_file():
            raise ValueError("incomplete cached Attestor OCI artifact")
        identity = _oci_identity(output)
        saved = json.loads(evidence.read_text(encoding="utf-8"))
        if any(saved.get(key) != value for key, value in identity.items()) or \
                saved.get("commit") != selected["commit"] or saved.get("tree") != selected["tree"]:
            raise ValueError("cached Attestor OCI identity differs")
        identity.update(version=selected["version"], commit=selected["commit"], tree=selected["tree"])
    else:
        identity = build(root, builder_cache=True)
    dist = root / "dist"
    dist.mkdir(mode=0o700, exist_ok=True)
    archive = dist / "attestor.oci.tar"
    metadata = dist / "attestor.oci.json"
    if archive.exists() or metadata.exists():
        if not archive.is_file() or not metadata.is_file() or \
                _sha256(archive) != identity["archive_sha256"] or \
                json.loads(metadata.read_text(encoding="utf-8")) != identity:
            raise ValueError("existing Guix Attestor input differs")
    else:
        os.link(output, archive)
        try:
            with metadata.open("x", encoding="utf-8") as stream:
                json.dump(identity, stream, sort_keys=True, indent=2)
                stream.write("\n")
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
    return identity
