"""Owner-only mutable run record, written before each Azure effect."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import secrets

SCHEMA = "hashbox.demo-run/v1"
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
GROUP_NAME = re.compile(r"[a-z][a-z0-9-]{2,79}\Z")
INSTANCE_NAME = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
ROLES = ("builder", "image", "cvm")


class StateError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def state_root(project: Path) -> Path:
    return project / ".local" / "demo-runs"


def run_path(project: Path, run_id: str) -> Path:
    if RUN_ID.fullmatch(run_id) is None:
        raise StateError("invalid run ID")
    return state_root(project) / run_id


def run_ids(project: Path) -> list[str]:
    parent = state_root(project)
    if not parent.is_dir():
        return []
    return sorted(path.name for path in parent.iterdir()
                  if path.is_dir() and not path.is_symlink() and RUN_ID.fullmatch(path.name))


def validate_group_name(name: str) -> str:
    if not isinstance(name, str) or GROUP_NAME.fullmatch(name) is None or name.endswith("-"):
        raise StateError(
            "group name must be 3-80 lowercase letters, digits or hyphens, starting with a letter"
        )
    return name


def validate_instance_name(name: str) -> str:
    if not isinstance(name, str) or INSTANCE_NAME.fullmatch(name) is None or name.endswith("-"):
        raise StateError(
            "instance name must be 1-48 lowercase letters, digits or hyphens, starting with a letter"
        )
    return name


def next_instance_name(record: dict) -> str:
    used = set(record.get("instances", {})) | {record.get("resources", {}).get("cvm_name")}
    prefix = f"hbx-demo-{record['run_id'][:8]}"
    for number in range(2, 10000):
        candidate = f"{prefix}-{number}"
        if candidate not in used:
            return candidate
    raise StateError("no available default instance name")


def create(project: Path, *, subscription_id: str, location: str, profile: str,
           cvm_group: str | None = None, instance_name: str | None = None) -> dict:
    if cvm_group is not None:
        validate_group_name(cvm_group)
    if instance_name is not None:
        validate_instance_name(instance_name)
    parent = state_root(project)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    for _ in range(8):
        run_id = secrets.token_hex(8)
        directory = run_path(project, run_id)
        try:
            directory.mkdir(mode=0o700)
            break
        except FileExistsError:
            continue
    else:
        raise StateError("could not allocate a unique run ID")
    group_names = {role: f"hbx-demo-{run_id}-{role}-rg" for role in ROLES}
    group_names["cvm"] = cvm_group or group_names["cvm"]
    if len(set(group_names.values())) != len(group_names):
        raise StateError("CVM group name conflicts with another run group")
    first_instance = instance_name or f"hbx-demo-{run_id[:8]}"
    groups = {
        role: {
            "name": group_names[role],
            "id": f"/subscriptions/{subscription_id}/resourceGroups/{group_names[role]}",
            "observed": False,
        }
        for role in ROLES
    }
    record = {
        "schema": SCHEMA,
        "run_id": run_id,
        "profile": profile,
        "subscription_id": subscription_id,
        "location": location,
        "phase": "allocated",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "groups": groups,
        "artifacts": {},
        "resources": {"cvm_name": first_instance},
        "instances": {first_instance: {"name": first_instance, "status": "planned",
                                     "deployment_label": "cvm", "created_at": utc_now()}},
        "errors": [],
    }
    save(project, record)
    return record


@contextmanager
def locked(project: Path, run_id: str):
    """Serialize mutations to one run record and its owned Azure group."""
    path = run_path(project, run_id) / ".lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


@contextmanager
def builder_pool_locked(project: Path):
    """Serialize builder selection, use and deletion across local runs."""
    parent = state_root(project)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(parent / ".builder-pool.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def retained_builders(project: Path, subscription_id: str, location: str,
                      size: str, public_key_sha256: str) -> list[dict]:
    """Find retained builders whose owner no longer has an active build."""
    candidates = []
    for run_id in run_ids(project):
        try:
            record = load(project, run_id)
        except (StateError, OSError):
            continue
        resources = record.get("resources") or {}
        group = (record.get("groups") or {}).get("builder") or {}
        completed = (record.get("phase") == "complete" and
                     record.get("builder_deallocation") == "verified")
        # A failed signer leaves the Guix store intact. It can be lent only
        # before staging, with no temporary Blob role or image/CVM group.
        failed_before_staging = (
            record.get("phase") == "base-vhd-built" and bool(record.get("errors")) and
            record.get("builder_failure_deallocation") == "verified" and
            not resources.get("blob_role_assignment_id") and
            not any((record.get("groups") or {}).get(role, {}).get("observed")
                    for role in ("image", "cvm"))
        )
        if ((completed or failed_before_staging) and
                record.get("builder_disposition") == "retain" and
                not record.get("builder_owner_run_id") and not group.get("deleted") and
                record.get("subscription_id", "").casefold() == subscription_id.casefold() and
                record.get("location", "").casefold() == location.casefold() and
                resources.get("builder_size") == size and
                resources.get("builder_ssh_public_key_sha256") == public_key_sha256 and
                all(resources.get(key) for key in ("builder_vm_name", "builder_public_ip",
                                                     "builder_principal_id"))):
            candidates.append(deepcopy(record))
    return sorted(candidates, key=lambda item: item["created_at"], reverse=True)


def active_builder_borrowers(project: Path, owner_run_id: str) -> list[str]:
    active = []
    for run_id in run_ids(project):
        if run_id == owner_run_id:
            continue
        record = load(project, run_id)
        if (record.get("builder_owner_run_id") == owner_run_id and
                record.get("phase") not in {"complete", "cleanup-complete"}):
            active.append(run_id)
    return active


def save(project: Path, record: dict) -> None:
    # This is the only writer for mutable run state. Keep the old file intact
    # until the new bytes are durable and ready for one atomic replacement.
    run_id = record.get("run_id")
    directory = run_path(project, run_id)
    if record.get("schema") != SCHEMA or not directory.is_dir():
        raise StateError("invalid run record or directory")
    record["updated_at"] = utc_now()
    payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    temporary = directory / f".run-{secrets.token_hex(8)}.json"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / "run.json")
        parent = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def load(project: Path, run_id: str) -> dict:
    path = run_path(project, run_id) / "run.json"
    try:
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise StateError("unsafe run record")
        record = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise StateError(f"cannot read run record: {error}") from error
    if record.get("schema") != SCHEMA or record.get("run_id") != run_id:
        raise StateError("run record identity differs from requested ID")
    return record


def advance(project: Path, record: dict, phase: str, **values: object) -> None:
    record["phase"] = phase
    record.update(values)
    save(project, record)


def record_error(project: Path, record: dict, message: str) -> None:
    record.setdefault("errors", []).append({"at": utc_now(), "message": message[:2000]})
    save(project, record)
