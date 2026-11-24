"""Public single-CVM demo entry points and visible step ordering."""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import re
import time
from typing import Any

from hashbox.build.remote import RemoteSSH
from hashbox.build.source_archive import create as create_archive
from hashbox.operation import state
from hashbox.project.config import load_azure_profile
from hashbox.source.attestor import advise as advise_attestor
from .admission import _account_preflight, _absent_groups, _retail_vm_hourly, available_regions
from .arm_templates import verify as verify_arm_templates
from .builder import (_builder_apply, _builder_build, _deallocate_failed_builder,
                      _ensure_builder_running, _finish_existing_build,
                      _refresh_builder_ssh_rule, _retire_builder, _reusable_builder,
                      _sign_base_vhd, _archive_path, _workdir, _resume_builder_install)
from .cli import AzureCLI, power_codes
from .cvm import _deallocate_failed_cvm, _deploy_cvm
from .errors import DemoError, _log, _require
from .gallery import _gallery, _grant_builder_blob, _stage_blob, _staging
from .instances import (assert_owned_cvm_group, create_instance, delete_cvm_group,
                        delete_instance, list_instances, list_runs)
from .resources import _create_group, _group_readback


def regions(root: Path, profile_name: str) -> dict:
    """Read CVM SKU availability and remaining quota across this subscription's regions."""
    profile = load_azure_profile(profile_name, root)
    return available_regions(AzureCLI(profile.subscription_id), profile)


def run(root: Path, profile_name: str, region: str | None = None,
        group: str | None = None, name: str | None = None,
        delete_builder: bool = False, fresh_builder: bool = False) -> str:
    with state.builder_pool_locked(root):
        return _run_locked(root, profile_name, region, group, name, delete_builder, fresh_builder)


def _run_locked(root: Path, profile_name: str, region: str | None,
                group: str | None, name: str | None,
                delete_builder: bool, fresh_builder: bool) -> str:
    """Run one fresh demo. Failed groups remain for explicit status/cleanup."""
    os.umask(0o077)
    verify_arm_templates(root)
    advise_attestor(root, operation="new image build")
    profile = load_azure_profile(profile_name, root)
    if region is not None:
        _require(re.fullmatch(r"[a-z0-9-]+", region) is not None, "invalid Azure region")
        profile = replace(profile, location=region)
    azure = AzureCLI(profile.subscription_id)
    key_sha = hashlib.sha256(profile.ssh_public_key.encode()).hexdigest()
    candidates = ([] if fresh_builder or delete_builder else
                  state.retained_builders(root, profile.subscription_id, profile.location,
                                          profile.builder_size, key_sha))
    profile = _account_preflight(azure, profile, builder_required=not bool(candidates))
    origin = None
    for candidate in candidates:
        if state.active_builder_borrowers(root, candidate["run_id"]):
            continue
        try:
            if _reusable_builder(azure, candidate):
                origin = candidate
                break
        except Exception as error:
            _log(f"Retained builder {candidate['run_id']} is not reusable: {error}")
    if candidates and origin is None:
        profile = _account_preflight(azure, profile, builder_required=True)
    if origin is not None:
        profile = replace(profile, builder_image_version=origin["resources"]["builder_image_version"])
    builder_hourly = _retail_vm_hourly(profile, profile.builder_size)
    cvm_hourly = _retail_vm_hourly(profile, profile.cvm_size)
    record = state.create(root, subscription_id=profile.subscription_id,
                          location=profile.location, profile=profile.name,
                          cvm_group=group, instance_name=name)
    record["resources"]["builder_image_version"] = profile.builder_image_version
    record["resources"]["builder_size"] = profile.builder_size
    record["resources"]["builder_ssh_public_key_sha256"] = key_sha
    record["resources"]["builder_workdir"] = f"/home/hashbox-builder/project-{record['run_id']}"
    record["resources"]["builder_source_archive"] = f"/home/hashbox-builder/source-{record['run_id']}.tar.gz"
    record["resources"]["cvm_size"] = profile.cvm_size
    record["builder_disposition"] = "delete" if delete_builder else "retain"
    record["cost"] = {"currency": "USD", "builder_vm_per_hour": builder_hourly,
                      "cvm_vm_per_hour": cvm_hourly, "excludes": "disks, IPs, Blob, Gallery and transfer"}
    if origin is not None:
        record["builder_owner_run_id"] = origin["run_id"]
        record["groups"]["builder"] = deepcopy(origin["groups"]["builder"])
        record["groups"]["builder"]["borrowed_from"] = origin["run_id"]
        for key in ("builder_vm_name", "builder_public_ip", "builder_principal_id"):
            record["resources"][key] = origin["resources"][key]
    state.save(root, record)
    run_id = record["run_id"]
    try:
        directory = state.run_path(root, run_id)
        source_sha, file_count = create_archive(root, directory / "source.tar.gz")
        record["artifacts"].update(source_archive_sha256=source_sha, source_file_count=file_count)
        state.advance(root, record, "source-captured")
        _absent_groups(azure, record)
        _log(f"Selected region: {profile.location}; builder, staging, Gallery and CVM stay there.")
        _log(f"Run {run_id}: image and CVM groups are reserved by name.")
        for role, group in record["groups"].items():
            _log(f"  {role}: {group['name']}")
        _log(f"  first instance: {record['resources']['cvm_name']}")
        _log(f"Compute retail: builder ${builder_hourly:.3f}/h while running; "
             f"CVM ${cvm_hourly:.3f}/h until cleanup; disks and storage extra.")
        if origin is None:
            _log("Creating a fresh builder; this run will retain it deallocated by default.")
            _builder_apply(root, profile, record)
        else:
            state.advance(root, record, "builder-reuse-start-submitted")
            _log(f"Reusing deallocated builder from run {origin['run_id']} and its Guix store...")
            _ensure_builder_running(root, azure, record)
            _refresh_builder_ssh_rule(root, azure, record, profile.ssh_source_cidr)
            state.advance(root, record, "builder-created")
        metadata, cert_b64 = _builder_build(root, profile, azure, record)
        _create_group(root, azure, record, "image")
        _staging(root, azure, record)
        _grant_builder_blob(root, azure, record)
        _stage_blob(root, profile, record)
        _gallery(root, azure, record, cert_b64)
        _retire_builder(root, azure, record, delete_builder=delete_builder)
        _create_group(root, azure, record, "cvm")
        _deploy_cvm(root, profile, azure, record)
        state.advance(root, record, "complete")
        _log(f"Run {run_id} complete: Secure Boot CVM at {record['resources']['cvm_public_ip']}")
        _log(f"Gallery version: {record['resources']['gallery_version_id']}")
        _log(f"Derived VHD SHA-256: {metadata['derived_vhd_sha256']}")
        return run_id
    except (Exception, KeyboardInterrupt) as error:
        state.record_error(root, record, f"{type(error).__name__}: {error}")
        _log(f"Run {run_id} failed in phase {record['phase']}: {error}")
        try:
            _deallocate_failed_builder(root, azure, record)
            if record.get("builder_failure_deallocation") == "verified":
                _log("Builder deallocation verified to limit compute cost.")
        except Exception as deallocation_error:
            state.record_error(root, record, f"builder deallocation unresolved: {deallocation_error}")
            _log("Builder deallocation is unresolved; inspect the exact builder group.")
        try:
            _deallocate_failed_cvm(root, azure, record)
        except Exception as deallocation_error:
            state.record_error(root, record, f"CVM deallocation unresolved: {deallocation_error}")
        _log(f"Inspect with: hashbox status {run_id}")
        _log(f"Remove owned groups with: hashbox cleanup {run_id}")
        raise


def resume(root: Path, run_id: str) -> str:
    with state.builder_pool_locked(root):
        return _resume_locked(root, run_id)


def _resume_locked(root: Path, run_id: str) -> str:
    """Resume an already-running builder after operator transport loss."""
    os.umask(0o077)
    verify_arm_templates(root)
    advise_attestor(root, operation="builder resume")
    record = state.load(root, run_id)
    _require(record["phase"] in {"source-on-builder", "builder-install-resume-submitted",
                                 "builder-ready", "resume-builder-wait", "blob-role-created"},
             "this run phase cannot be resumed without a fresh readback")
    previous_phase = record["phase"]
    profile = load_azure_profile(record["profile"], root)
    _require(profile.subscription_id.casefold() == record["subscription_id"].casefold() and
             profile.builder_size == record["resources"].get("builder_size") and
             profile.cvm_size == record["resources"].get("cvm_size"),
             "resume profile subscription or VM sizes differ from saved run")
    profile = replace(profile, location=record["location"])
    archive = state.run_path(root, run_id) / "source.tar.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    _require(digest == record["artifacts"]["source_archive_sha256"],
             "saved source archive differs from the builder source identity")
    azure = AzureCLI(profile.subscription_id)
    account = azure.json("account", "show", timeout=60)
    _require(account.get("id", "").casefold() == profile.subscription_id.casefold(),
             "Azure CLI did not return this run's subscription")
    try:
        profile = _account_preflight(azure, profile)
        if record.get("builder_owner_run_id"):
            profile = replace(profile, builder_image_version=record["resources"]["builder_image_version"])
        _require(profile.builder_image_version == record["resources"].get("builder_image_version"),
                 "builder image version differs from the saved run")
        hourly = _retail_vm_hourly(profile, profile.builder_size)
        _log(f"Retained builder compute retail: ${hourly:.3f}/h while running; disk and IP extra.")
        _ensure_builder_running(root, azure, record)
        _refresh_builder_ssh_rule(root, azure, record, profile.ssh_source_cidr)
        directory = state.run_path(root, run_id)
        remote = RemoteSSH(record["resources"]["builder_public_ip"], profile.ssh_private_key,
                           directory / "builder.known_hosts")
        for attempt in range(20):
            try:
                source_digest = remote.run(["sha256sum", _archive_path(record)], timeout=60).split()[0]
                break
            except Exception:
                if attempt == 19:
                    raise
                time.sleep(15)
        _require(source_digest == digest, "builder source archive differs from the saved run")
    except (Exception, KeyboardInterrupt) as error:
        state.record_error(root, record, f"resume setup: {type(error).__name__}: {error}")
        try:
            _deallocate_failed_builder(root, azure, record)
        except Exception as deallocation_error:
            state.record_error(root, record, f"builder deallocation unresolved: {deallocation_error}")
        raise
    try:
        if previous_phase in {"source-on-builder", "builder-install-resume-submitted"}:
            _resume_builder_install(root, record, remote)
        if previous_phase in {"source-on-builder", "builder-install-resume-submitted",
                              "builder-ready", "resume-builder-wait"}:
            state.advance(root, record, "resume-builder-wait")
            _finish_existing_build(root, record, remote)
            state.advance(root, record, "base-vhd-built")
            _log("Existing Guix build produced a verified base VHD; continuing Secure Boot signing...")
            metadata, cert_b64 = _sign_base_vhd(root, record, remote, digest)
            _create_group(root, azure, record, "image")
            _staging(root, azure, record)
            _grant_builder_blob(root, azure, record)
        else:
            _group_readback(azure, record, "image")
            metadata = record["artifacts"]
            _require(metadata.get("schema") == "hashbox.demo-secure-boot/v1" and
                     metadata.get("source_archive_sha256") == digest,
                     "saved Secure Boot artifact metadata differs")
            signed = f"{_workdir(record)}/dist/secure-boot"
            actual = remote.run(["sha256sum", signed + "/HashBox-demo-secureboot-x86_64.vhd"], timeout=180).split()[0]
            _require(actual == metadata.get("derived_vhd_sha256"), "signed VHD differs from saved metadata")
            cert_b64 = remote.run(["base64", "-w0", signed + "/uefi-db.der"], timeout=60)
            _require(hashlib.sha256(base64.b64decode(cert_b64, validate=True)).hexdigest() ==
                     metadata.get("uefi_db_certificate_sha256"), "UEFI DB certificate differs")
            remaining_keys = remote.run(
                ["sh", "-c", "find /dev/shm -maxdepth 1 -name 'hashbox-demo-sign.*' -print"],
                timeout=60,
            )
            _require(not remaining_keys,
                     "signing key workspace remains on the builder")
        _stage_blob(root, profile, record)
        _gallery(root, azure, record, cert_b64)
        _retire_builder(root, azure, record,
                        delete_builder=record.get("builder_disposition", "delete") == "delete")
        _create_group(root, azure, record, "cvm")
        _deploy_cvm(root, profile, azure, record)
        state.advance(root, record, "complete")
        _log(f"Run {run_id} complete: Secure Boot CVM at {record['resources']['cvm_public_ip']}")
        _log(f"Derived VHD SHA-256: {metadata['derived_vhd_sha256']}")
        return run_id
    except (Exception, KeyboardInterrupt) as error:
        state.record_error(root, record, f"resume: {type(error).__name__}: {error}")
        _log(f"Run {run_id} recovery stopped in phase {record['phase']}: {error}")
        try:
            _deallocate_failed_builder(root, azure, record)
            if record.get("builder_failure_deallocation") == "verified":
                _log("Builder deallocation verified to limit compute cost.")
        except Exception as deallocation_error:
            state.record_error(root, record, f"builder deallocation unresolved: {deallocation_error}")
            _log("Builder deallocation is unresolved; inspect the exact builder group.")
        _log("Inspect the exact owned groups before another recovery or cleanup.")
        raise


def status(root: Path, run_id: str) -> dict:
    """Read local state and fresh Azure group/VM facts without mutation."""
    record = state.load(root, run_id)
    azure = AzureCLI(record["subscription_id"])
    result: dict[str, Any] = {
        "run_id": run_id, "phase": record["phase"],
        "builder_owner_run_id": record.get("builder_owner_run_id", run_id),
        "builder_disposition": record.get("builder_disposition", "delete"),
        "source_archive_sha256": record["artifacts"].get("source_archive_sha256"),
        "base_vhd_sha256": record["artifacts"].get("base_vhd_sha256"),
        "derived_vhd_sha256": record["artifacts"].get("derived_vhd_sha256"),
        "uefi_db_certificate_sha256": record["artifacts"].get("uefi_db_certificate_sha256"),
        "blob_full_readback": record.get("blob_full_readback"),
        "gallery_version_id": record["resources"].get("gallery_version_id"),
        "cvm_azure_readback": record.get("cvm_azure_readback"),
        "cvm_guest_readback": record.get("cvm_guest_readback"),
        "attestation": record.get("attestation"),
        "blocker": record.get("blocker"),
        "cvm_id": record["resources"].get("cvm_id"),
        "cvm_public_ip": record["resources"].get("cvm_public_ip"),
        "groups": {}, "errors": record.get("errors", []),
    }
    for role, group in record["groups"].items():
        try:
            present = azure.group_exists(group["name"])
            if present:
                _group_readback(azure, record, role)
                borrowed = role == "builder" and bool(record.get("builder_owner_run_id"))
                group_status = "borrowed-present" if borrowed else "owned-present"
                result["groups"][role] = {"name": group["name"], "status": group_status}
            else:
                result["groups"][role] = {"name": group["name"], "status": "absent"}
        except Exception as error:
            result["groups"][role] = {"name": group["name"], "status": "unreachable-or-foreign", "error": str(error)}
    version_id = record["resources"].get("gallery_version_id")
    if version_id and result["groups"].get("image", {}).get("status") == "owned-present":
        try:
            observed = azure.json("rest", "--method", "get", "--url",
                                  f"https://management.azure.com{version_id}?api-version=2025-12-03", timeout=120)
            _require(observed.get("id", "").casefold() == version_id.casefold(),
                     "Gallery version identity differs")
            tags = observed.get("tags") or {}
            _require(tags.get("hashbox_demo_run") == run_id and
                     tags.get("uefi_db_sha256") == record["artifacts"].get("uefi_db_certificate_sha256"),
                     "Gallery version ownership or certificate tag differs")
            properties = observed.get("properties") or {}
            security = properties.get("securityProfile") or {}
            db = (((security.get("uefiSettings") or {}).get("additionalSignatures") or {}).get("db") or [])
            cert_hashes = set()
            for signature in db:
                if signature.get("type") != "x509":
                    continue
                for value in signature.get("value", []):
                    cert_hashes.add(hashlib.sha256(base64.b64decode(value, validate=True)).hexdigest())
            result["gallery"] = {
                "provisioning_state": properties.get("provisioningState"),
                "uefi_db_certificate_in_rest_response":
                    record["artifacts"].get("uefi_db_certificate_sha256") in cert_hashes,
                "security_profile_in_rest_response": bool(security),
                "rest_omission_is_inconclusive": not bool(security),
            }
        except Exception as error:
            result["gallery"] = {"status": "unreachable-or-foreign", "error": str(error)}
    builder_vm = record["resources"].get("builder_vm_name")
    if builder_vm and result["groups"].get("builder", {}).get("status") in {"owned-present", "borrowed-present"}:
        try:
            view = azure.json("vm", "get-instance-view", "--resource-group",
                              record["groups"]["builder"]["name"], "--name", builder_vm, timeout=90)
            result["builder_power_states"] = [code for code in power_codes(view)
                                              if code.startswith("PowerState/")]
        except Exception as error:
            result["builder_power_states"] = [f"unreachable: {error}"]
    vm = record["resources"].get("cvm_name")
    if (vm and result["groups"].get("cvm", {}).get("status") == "owned-present" and
            record.get("instances", {}).get(vm, {}).get("status") not in {"deleted", "deleted-with-group"}):
        try:
            view = azure.json("vm", "get-instance-view", "--resource-group",
                              record["groups"]["cvm"]["name"], "--name", vm, timeout=90)
            result["cvm_power_states"] = [code for code in power_codes(view)
                                          if code.startswith("PowerState/")]
        except Exception as error:
            result["cvm_power_states"] = [f"unreachable: {error}"]
    try:
        result["instance_summary"] = list_instances(root, run_id)
    except Exception as error:
        result["instance_summary"] = {"status": "unreachable", "error": str(error)}
    return result


def cleanup(root: Path, run_id: str) -> None:
    with state.builder_pool_locked(root):
        _cleanup_locked(root, run_id)


def _cleanup_locked(root: Path, run_id: str) -> None:
    """Delete only groups whose exact ID and run tags still match the saved run."""
    with state.locked(root, run_id):
        record = state.load(root, run_id)
        azure = AzureCLI(record["subscription_id"])
        account = azure.json("account", "show", timeout=60)
        _require(account.get("id", "").casefold() == record["subscription_id"].casefold(),
                 "Azure CLI did not return this run's subscription")
        if not record.get("builder_owner_run_id"):
            borrowers = state.active_builder_borrowers(root, run_id)
            _require(not borrowers, f"builder is referenced by unfinished runs: {', '.join(borrowers)}")
        for role in ("cvm", "image", "builder"):
            if role == "builder" and record.get("builder_owner_run_id"):
                record["groups"]["builder"]["borrow_released"] = True
                state.save(root, record)
                continue
            group = record["groups"][role]["name"]
            if not azure.group_exists(group):
                record["groups"][role]["deleted"] = True
                state.save(root, record)
                continue
            _group_readback(azure, record, role)
            if role == "cvm":
                assert_owned_cvm_group(azure, record)
            state.advance(root, record, f"cleanup-{role}-submitted")
            _log(f"Deleting owned {role} group {group}...")
            azure.group_delete(group)
            azure.group_wait_deleted(group)
            _require(not azure.group_exists(group), f"{role} group still exists")
            record["groups"][role]["deleted"] = True
            state.save(root, record)
        state.advance(root, record, "cleanup-complete")
        _log(f"Run {run_id}: owned resource groups are absent.")
