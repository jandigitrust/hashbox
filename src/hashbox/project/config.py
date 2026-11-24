"""Owner-controlled Azure demo profile."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import tomllib
import uuid

from hashbox.source.ssh_public_key import from_file
from .root import repository_root

PROFILE_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
REGION = re.compile(r"[a-z0-9-]+\Z")
VM_SIZE = re.compile(r"Standard_[A-Za-z0-9_]+\Z")
IMAGE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+\Z")
MAX_CONFIG_BYTES = 64 * 1024


class ConfigError(ValueError):
    """An Azure profile is missing or malformed."""


@dataclass(frozen=True)
class AzureProfile:
    name: str
    subscription_id: str
    location: str
    builder_size: str
    cvm_size: str
    builder_image_version: str
    ssh_public_key: str
    ssh_private_key: Path
    ssh_source_cidr: str


def _read_toml(path: Path) -> dict:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ConfigError(f"cannot open configuration: {path}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size < 1
            or metadata.st_size > MAX_CONFIG_BYTES
            or metadata.st_mode & 0o077
        ):
            raise ConfigError(f"unsafe configuration file: {path}")
        payload = os.read(descriptor, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        value = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"invalid TOML configuration: {path}") from error
    if not isinstance(value, dict):
        raise ConfigError("configuration must be a TOML table")
    return value


def _string(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ConfigError(f"invalid {label}")
    return value


def load_azure_profile(name: str, root: Path | None = None) -> AzureProfile:
    _string(name, PROFILE_NAME, "profile name")
    project = repository_root(root or Path(__file__).resolve().parents[3])
    configured = os.environ.get("HASHBOX_DEMO_PROFILE_FILE")
    path = Path(configured).expanduser() if configured else project / ".local" / "profiles" / f"{name}.toml"
    data = _read_toml(path)
    if data.get("name") != name or data.get("schema") != "hashbox.azure-profile/v4":
        raise ConfigError("Azure profile name or schema differs from the request")
    try:
        subscription = str(uuid.UUID(data["subscription_id"]))
        location = _string(data["location"], REGION, "Azure region")
        build = data["build"]
        deployment = data["deployment"]
        access = data["access"]
        builder_size = _string(os.environ.get("HASHBOX_DEMO_BUILDER_SIZE", build["vm_size"]),
                               VM_SIZE, "builder size")
        cvm_size = _string(deployment["vm_size"], VM_SIZE, "CVM size")
        image_version = build["source_image_version"]
        if image_version != "auto":
            image_version = _string(image_version, IMAGE_VERSION, "builder image version")
        key_path = Path(access["ssh_public_key"]).expanduser()
        key = from_file(key_path)
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise ConfigError(f"Azure profile is incomplete or invalid: {error}") from error
    if key.key_type not in {"ssh-ed25519", "ssh-rsa"} or not str(key_path).endswith(".pub"):
        raise ConfigError("Azure profile requires an Ed25519 or RSA public-key file")
    private = Path(str(key_path)[:-4])
    try:
        metadata = private.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or
                metadata.st_uid != os.getuid()):
            raise ConfigError("SSH private key is not owner-only")
        generated = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(private)],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise ConfigError("SSH private key is unavailable or requires a prompt") from error
    if " ".join(generated.split()[:2]) != key.public_key:
        raise ConfigError("SSH private and public keys differ")
    cidr = os.environ.get("HASHBOX_DEMO_SSH_SOURCE_CIDR", access.get("ssh_source", ""))
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError as error:
        raise ConfigError("SSH source must be an explicit IPv4 /32") from error
    if network.version != 4 or network.prefixlen != 32:
        raise ConfigError("SSH source must be an explicit IPv4 /32")
    return AzureProfile(
        name=name,
        subscription_id=subscription,
        location=location,
        builder_size=builder_size,
        cvm_size=cvm_size,
        builder_image_version=image_version,
        ssh_public_key=key.public_key,
        ssh_private_key=private,
        ssh_source_cidr=cidr,
    )
