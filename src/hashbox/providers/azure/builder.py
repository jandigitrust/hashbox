"""OpenTofu builder, pinned SSH build, signing and retirement."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

from hashbox.build.remote import RemoteSSH, pinned_host_key
from hashbox.operation import state
from hashbox.project.config import AzureProfile
from .cli import AzureCLI, power_codes
from .errors import DemoError, _log, _require
from .resources import _group_readback


def _workdir(record: dict) -> str:
    return record["resources"].get("builder_workdir", "/home/hashbox-builder/project")


def _archive_path(record: dict) -> str:
    return record["resources"].get("builder_source_archive", "/home/hashbox-builder/source.tar.gz")


def _owner(record: dict) -> str:
    return record.get("builder_owner_run_id", record["run_id"])


def _reusable_builder(azure: AzureCLI, origin: dict) -> bool:
    """Read exact Azure identity and deallocated state before lending a builder."""
    group = origin["groups"]["builder"]
    resources = origin["resources"]
    if not azure.group_exists(group["name"]):
        return False
    _group_readback(azure, origin, "builder")
    name = resources["builder_vm_name"]
    expected = group["id"] + "/providers/Microsoft.Compute/virtualMachines/" + name
    vm = azure.json("vm", "show", "--resource-group", group["name"], "--name", name, timeout=90)
    tags = vm.get("tags") or {}
    _require(vm.get("id", "").casefold() == expected.casefold() and
             tags.get("hashbox_demo_run") == origin["run_id"] and
             tags.get("hashbox_demo_role") == "builder" and
             (vm.get("hardwareProfile") or {}).get("vmSize") == resources["builder_size"] and
             (vm.get("identity") or {}).get("principalId", "").casefold() ==
             resources["builder_principal_id"].casefold(),
             "retained builder VM identity, size or principal differs")
    pip_name = name + "-pip"
    pip = azure.json("network", "public-ip", "show", "--resource-group", group["name"],
                     "--name", pip_name, timeout=90)
    pip_id = group["id"] + "/providers/Microsoft.Network/publicIPAddresses/" + pip_name
    pip_tags = pip.get("tags") or {}
    _require(pip.get("id", "").casefold() == pip_id.casefold() and
             pip.get("ipAddress") == resources["builder_public_ip"] and
             pip_tags.get("hashbox_demo_run") == origin["run_id"] and
             pip_tags.get("hashbox_demo_role") == "builder",
             "retained builder public IP identity differs")
    view = azure.json("vm", "get-instance-view", "--resource-group", group["name"],
                      "--name", name, timeout=90)
    return "PowerState/deallocated" in power_codes(view)


def _tofu(root: Path, arguments: list[str], environment: dict[str, str], *, timeout: int) -> str:
    module = root / "infra/providers/azure/builder"
    command = ["tofu", f"-chdir={module}", *arguments]
    try:
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DemoError(f"OpenTofu {arguments[0]} did not complete: {type(error).__name__}") from error
    if result.returncode:
        raise DemoError(f"OpenTofu {arguments[0]} failed: {result.stderr[-700:] or result.stdout[-700:]}")
    return result.stdout.strip()


def _builder_apply(root: Path, profile: AzureProfile, record: dict) -> None:
    directory = state.run_path(root, record["run_id"])
    tfstate = directory / "builder.tfstate"
    environment = os.environ.copy()
    environment.update({
        "TF_IN_AUTOMATION": "1",
        "TF_VAR_subscription_id": profile.subscription_id,
        "TF_VAR_location": profile.location,
        "TF_VAR_run_id": record["run_id"],
        "TF_VAR_resource_group_name": record["groups"]["builder"]["name"],
        "TF_VAR_ssh_public_key": profile.ssh_public_key,
        "TF_VAR_ssh_source_cidr": profile.ssh_source_cidr,
        "TF_VAR_vm_size": profile.builder_size,
        "TF_VAR_source_image_version": profile.builder_image_version,
    })
    _tofu(root, ["init", "-input=false", "-no-color", "-lockfile=readonly"], environment, timeout=600)
    _tofu(root, ["validate", "-no-color"], environment, timeout=120)
    state.advance(root, record, "builder-apply-submitted")
    _log("Creating the fresh builder resource group and VM...")
    _tofu(root, ["apply", "-auto-approve", "-input=false", "-no-color", f"-state={tfstate}"], environment, timeout=1800)
    actual_group = _tofu(root, ["output", f"-state={tfstate}", "-raw", "resource_group"], environment, timeout=30)
    _require(actual_group == record["groups"]["builder"]["name"], "OpenTofu returned another builder group")
    ip = _tofu(root, ["output", f"-state={tfstate}", "-raw", "public_ip"], environment, timeout=30)
    ipaddress.ip_address(ip)
    vm = _tofu(root, ["output", f"-state={tfstate}", "-raw", "vm_name"], environment, timeout=30)
    principal = _tofu(root, ["output", f"-state={tfstate}", "-raw", "builder_principal_id"], environment, timeout=30)
    _require(bool(re.fullmatch(r"[0-9a-fA-F-]{36}", principal)), "builder principal ID is invalid")
    _group_readback(AzureCLI(profile.subscription_id), record, "builder")
    record["groups"]["builder"]["observed"] = True
    record["resources"].update(builder_vm_name=vm, builder_public_ip=ip, builder_principal_id=principal)
    state.advance(root, record, "builder-created")


def _builder_build(root: Path, profile: AzureProfile, azure: AzureCLI, record: dict) -> tuple[dict, str]:
    group = record["groups"]["builder"]["name"]
    vm = record["resources"]["builder_vm_name"]
    ip = record["resources"]["builder_public_ip"]
    directory = state.run_path(root, record["run_id"])
    known_hosts = directory / "builder.known_hosts"
    pinned_host_key(azure, group, vm, ip, known_hosts)
    remote = RemoteSSH(ip, profile.ssh_private_key, known_hosts)
    archive = directory / "source.tar.gz"
    _log("Uploading the bounded source archive to the builder...")
    remote.upload(archive, Path(_archive_path(record)).name, timeout=300)
    remote_sha = remote.run(["sha256sum", _archive_path(record)], timeout=60).split()[0]
    _require(remote_sha == record["artifacts"]["source_archive_sha256"], "builder source archive digest differs")
    workdir = _workdir(record)
    remote.run(["sh", "-c", f"mkdir -m 700 {workdir} && tar -xzf {_archive_path(record)} -C {workdir}"], timeout=120)
    state.advance(root, record, "source-on-builder")
    _log("Checking authenticated Guix and Azure CLI on the builder...")
    remote.run_logged(f"install-guix-{record['run_id']}", f"sudo sh {workdir}/toolchain/builder/install-guix.sh", timeout=2700)
    remote.run_logged(f"install-azure-cli-{record['run_id']}", f"sudo sh {workdir}/toolchain/builder/install-azure-cli.sh", timeout=900)
    state.advance(root, record, "builder-ready")
    _log("Building the Guix raw image and fixed VHD on the builder...")
    _finish_existing_build(root, record, remote)
    state.advance(root, record, "base-vhd-built")
    return _sign_base_vhd(root, record, remote, remote_sha)


def _capture_attestor_image(root: Path, record: dict, remote: RemoteSSH) -> None:
    """Bind the builder OCI bytes to this run when its saved source embeds Attestor."""
    source = state.run_path(root, record["run_id"]) / "source.tar.gz"
    with tarfile.open(source, "r:gz") as archive:
        if "toolchain/builder/build-attestor.sh" not in archive.getnames():
            return  # Older saved source archives predate the embedded collector.
        source_lock = json.load(archive.extractfile("ATTESTOR_LOCK.json"))
    workdir = _workdir(record)
    metadata = json.loads(remote.run(["cat", f"{workdir}/dist/attestor.oci.json"], timeout=60))
    _require(metadata.get("commit") == source_lock["commit"] and
             metadata.get("tree") == source_lock["tree"] and
             re.fullmatch(r"[0-9a-f]{64}", metadata.get("archive_sha256", "")) is not None and
             re.fullmatch(r"sha256:[0-9a-f]{64}", metadata.get("manifest_digest", "")) is not None,
             "builder Attestor OCI metadata differs from saved source")
    actual = remote.run(["sha256sum", f"{workdir}/dist/attestor.oci.tar"], timeout=300).split()[0]
    _require(actual == metadata["archive_sha256"], "builder Attestor OCI archive bytes differ")
    record["artifacts"]["attestor_oci"] = metadata
    state.save(root, record)


def _sign_base_vhd(root: Path, record: dict, remote: RemoteSSH,
                   remote_sha: str) -> tuple[dict, str]:
    workdir = _workdir(record)
    base = f"{workdir}/dist/HashBox-azure-gen2-x86_64.vhd"
    _log("Signing the default EFI entry with a disposable builder tmpfs key...")
    signed_output = f"{workdir}/dist/secure-boot"
    sign_command = (
        f"cd {workdir} && "
        f"./toolchain/secure-boot/run-demo.sh {base} {remote_sha} {signed_output}"
    )
    remote.run_logged(f"secure-boot-{record['run_id']}", sign_command, timeout=3600)
    metadata_text = remote.run(["cat", f"{signed_output}/metadata.json"], timeout=60)
    try:
        metadata = json.loads(metadata_text)
    except json.JSONDecodeError as error:
        raise DemoError("builder Secure Boot metadata is not JSON") from error
    _require(metadata.get("schema") == "hashbox.demo-secure-boot/v1",
             "builder Secure Boot metadata schema differs")
    _require(metadata.get("source_archive_sha256") == remote_sha,
             "signed VHD is bound to another source archive")
    _require(bool(re.fullmatch(r"[0-9a-f]{64}", metadata.get("derived_vhd_sha256", ""))),
             "signed VHD digest is invalid")
    _require(metadata.get("derived_vhd_size", 0) > 0 and metadata.get("derived_vhd_size", 0) % 512 == 0,
             "signed VHD size is invalid")
    cert_b64 = remote.run(["base64", "-w0", f"{signed_output}/uefi-db.der"], timeout=60)
    certificate = base64.b64decode(cert_b64, validate=True)
    _require(hashlib.sha256(certificate).hexdigest() == metadata.get("uefi_db_certificate_sha256"),
             "public UEFI DB certificate differs from signed VHD metadata")
    remaining = remote.run(["sh", "-c", "find /dev/shm -maxdepth 1 -name 'hashbox-demo-sign.*' -print"], timeout=60)
    _require(not remaining, "disposable signing-key workspace remains on the builder")
    record["artifacts"].update(metadata)
    state.advance(root, record, "signed-vhd-ready")
    return metadata, cert_b64


def _retire_builder(root: Path, azure: AzureCLI, record: dict, *, delete_builder: bool) -> None:
    _log("Removing the temporary builder Blob role...")
    assignment = record["resources"].get("blob_role_assignment_id")
    if assignment:
        state.advance(root, record, "blob-role-delete-submitted")
        azure.call("role", "assignment", "delete", "--ids", assignment, timeout=120)
        record["resources"].pop("blob_role_assignment_id", None)
        state.advance(root, record, "blob-role-deleted")
    group = record["groups"]["builder"]["name"]
    _group_readback(azure, record, "builder")
    if delete_builder:
        _require(not record.get("builder_owner_run_id"), "a borrowed builder belongs to its original run")
        state.advance(root, record, "builder-delete-submitted")
        azure.group_delete(group)
        azure.group_wait_deleted(group)
        _require(not azure.group_exists(group), "builder group still exists after deletion")
        record["groups"]["builder"]["deleted"] = True
        state.advance(root, record, "builder-retired")
        return
    name = record["resources"]["builder_vm_name"]
    expected_id = record["groups"]["builder"]["id"] + "/providers/Microsoft.Compute/virtualMachines/" + name
    vm = azure.json("vm", "show", "--resource-group", group, "--name", name, timeout=90)
    tags = vm.get("tags") or {}
    _require(vm.get("id", "").casefold() == expected_id.casefold() and
             tags.get("hashbox_demo_run") == _owner(record) and
             tags.get("hashbox_demo_role") == "builder",
             "builder identity or ownership differs before retention")
    view = azure.json("vm", "get-instance-view", "--resource-group", group, "--name", name, timeout=90)
    if "PowerState/deallocated" not in power_codes(view):
        state.advance(root, record, "builder-deallocate-submitted")
        azure.call("vm", "deallocate", "--resource-group", group, "--name", name,
                   "--no-wait", timeout=120)
        for _ in range(30):
            view = azure.json("vm", "get-instance-view", "--resource-group", group,
                              "--name", name, timeout=90)
            if "PowerState/deallocated" in power_codes(view):
                break
            time.sleep(20)
        else:
            raise DemoError("retained builder did not deallocate within 10 minutes")
    record["builder_deallocation"] = "verified"
    state.advance(root, record, "builder-retained")
    _log(f"Builder {group} retained deallocated; disk and public IP still cost money.")


def _deallocate_failed_builder(root: Path, azure: AzureCLI, record: dict) -> None:
    group = record["groups"]["builder"]["name"]
    if not azure.group_exists(group):
        return
    _group_readback(azure, record, "builder")
    vm = record["resources"].get("builder_vm_name")
    if not vm:
        observed = azure.json("vm", "list", "--resource-group", group, timeout=90)
        owned = [item.get("name") for item in observed
                 if (item.get("tags") or {}).get("hashbox_demo_run") == _owner(record)
                 and (item.get("tags") or {}).get("hashbox_demo_role") == "builder"]
        _require(len(owned) <= 1, "builder group contains ambiguous owned VMs")
        vm = owned[0] if owned else None
    if not vm:
        return
    view = azure.json("vm", "get-instance-view", "--resource-group", group,
                      "--name", vm, timeout=90)
    if "PowerState/deallocated" in power_codes(view):
        record["builder_failure_deallocation"] = "verified"
        state.save(root, record)
        return
    record["builder_failure_deallocation"] = "submitted"
    state.save(root, record)
    azure.call("vm", "deallocate", "--resource-group", group, "--name", vm,
               "--no-wait", timeout=120)
    for _ in range(30):
        view = azure.json("vm", "get-instance-view", "--resource-group", group,
                          "--name", vm, timeout=90)
        codes = power_codes(view)
        if "PowerState/deallocated" in codes:
            record["builder_failure_deallocation"] = "verified"
            state.save(root, record)
            return
        time.sleep(20)
    raise DemoError("builder deallocation was submitted but not verified")


def _ensure_builder_running(root: Path, azure: AzureCLI, record: dict) -> None:
    """Restart only the exact retained builder after verified deallocation."""
    _group_readback(azure, record, "builder")
    group = record["groups"]["builder"]
    name = record["resources"]["builder_vm_name"]
    expected_id = group["id"] + "/providers/Microsoft.Compute/virtualMachines/" + name
    vm = azure.json("vm", "show", "--resource-group", group["name"], "--name", name, timeout=90)
    tags = vm.get("tags") or {}
    _require(vm.get("id", "").casefold() == expected_id.casefold() and
             tags.get("hashbox_demo_run") == _owner(record) and
             tags.get("hashbox_demo_role") == "builder" and
             (vm.get("hardwareProfile") or {}).get("vmSize") == record["resources"].get("builder_size"),
             "retained builder VM identity, tags or size differ")
    pip_name = name + "-pip"
    pip = azure.json("network", "public-ip", "show", "--resource-group", group["name"],
                     "--name", pip_name, timeout=90)
    pip_id = group["id"] + "/providers/Microsoft.Network/publicIPAddresses/" + pip_name
    pip_tags = pip.get("tags") or {}
    _require(pip.get("id", "").casefold() == pip_id.casefold() and
             pip.get("ipAddress") == record["resources"].get("builder_public_ip") and
             pip_tags.get("hashbox_demo_run") == _owner(record) and
             pip_tags.get("hashbox_demo_role") == "builder",
             "retained builder public IP identity differs")
    view = azure.json("vm", "get-instance-view", "--resource-group", group["name"],
                      "--name", name, timeout=90)
    codes = power_codes(view)
    if "PowerState/running" in codes:
        return
    if "PowerState/deallocated" in codes:
        record["builder_restart"] = {"status": "submitted", "at": state.utc_now()}
        state.save(root, record)
        _log("Starting the exact retained builder for bounded resume...")
        azure.call("vm", "start", "--resource-group", group["name"], "--name", name,
                   "--no-wait", timeout=120)
    else:
        _require("PowerState/starting" in codes,
                 f"retained builder is in an unsupported power state: {sorted(codes)}")
    for _ in range(30):
        view = azure.json("vm", "get-instance-view", "--resource-group", group["name"],
                          "--name", name, timeout=90)
        if "PowerState/running" in power_codes(view):
            record["builder_restart"] = {"status": "verified", "at": state.utc_now(),
                                         "vm_id": expected_id, "public_ip_id": pip_id}
            state.save(root, record)
            return
        time.sleep(20)
    raise DemoError("retained builder did not reach running power state")


def _refresh_builder_ssh_rule(root: Path, azure: AzureCLI, record: dict, cidr: str) -> None:
    _group_readback(azure, record, "builder")
    name = record["resources"]["builder_vm_name"] + "-nsg"
    expected_id = (record["groups"]["builder"]["id"] +
                   "/providers/Microsoft.Network/networkSecurityGroups/" + name)
    observed = azure.json("network", "nsg", "show", "--resource-group",
                          record["groups"]["builder"]["name"], "--name", name)
    tags = observed.get("tags") or {}
    _require(observed.get("id", "").casefold() == expected_id.casefold() and
             tags.get("hashbox_demo_run") == _owner(record) and
             tags.get("hashbox_demo_role") == "builder", "builder NSG ownership differs")
    rules = [item for item in observed.get("securityRules", []) if item.get("name") == "AllowOperatorSSH"]
    _require(len(rules) == 1, "builder SSH rule is missing or ambiguous")
    if rules[0].get("sourceAddressPrefix") == cidr:
        return
    _log("Updating the owned builder SSH rule for the current operator IPv4 /32...")
    updated = azure.json("network", "nsg", "rule", "update", "--resource-group",
                         record["groups"]["builder"]["name"], "--nsg-name", name,
                         "--name", "AllowOperatorSSH", "--source-address-prefixes", cidr, timeout=180)
    _require(updated.get("sourceAddressPrefix") == cidr and updated.get("provisioningState") == "Succeeded",
             "builder SSH rule update was not confirmed")
    record["resources"]["builder_ssh_source_cidr"] = cidr
    state.save(root, record)


def _wait_for_existing_build(remote: RemoteSSH) -> None:
    deadline = time.monotonic() + 10800
    while time.monotonic() < deadline:
        try:
            active = remote.run(
                ["sh", "-c", "if pgrep -f '^/bin/sh ./toolchain/release/build.sh$' >/dev/null; "
                 "then echo running; else echo stopped; fi"], timeout=45,
            )
        except Exception:
            _log("Builder SSH temporarily unavailable; retrying the existing build readback...")
            time.sleep(20)
            continue
        if active == "stopped":
            return
        _log("Existing Guix image build is still running...")
        time.sleep(45)
    raise DemoError("existing Guix image build did not finish within the recovery window")


def _image_unit_state(remote: RemoteSSH, unit: str) -> dict[str, str]:
    output = remote.run(["systemctl", "show", unit,
                         "--property=LoadState,ActiveState,Result,ExecMainStatus"], timeout=60)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _wait_for_image_unit(root: Path, record: dict, remote: RemoteSSH) -> None:
    """Poll the exact detached builder job; SSH loss cannot kill its process."""
    unit = record["builder_image_job"]["unit"]
    deadline = time.monotonic() + 14400
    missing = 0
    while time.monotonic() < deadline:
        try:
            observed = _image_unit_state(remote, unit)
        except Exception as error:
            _log(f"Builder SSH readback interrupted ({type(error).__name__}); "
                 "detached image job remains on Azure.")
            time.sleep(30)
            continue
        if observed.get("LoadState") == "not-found":
            workdir = _workdir(record)
            base = f"{workdir}/dist/HashBox-azure-gen2-x86_64.vhd"
            ready = remote.run(["sh", "-c", f"if test -f {base} && test -f {base}.sha256; "
                                "then echo ready; else echo absent; fi"], timeout=60)
            if ready == "ready":
                # systemd may discard a successful transient unit before readback.
                # _finish_existing_build verifies both full VHD digests next.
                record["builder_image_job"]["status"] = "artifact-ready"
                state.save(root, record)
                return
            missing += 1
            if missing < 3:
                time.sleep(5)
                continue
            raise DemoError(f"detached image job {unit} is absent after submission; inspect before retry")
        missing = 0
        if observed.get("ActiveState") in {"active", "activating"}:
            time.sleep(30)
            continue
        if (observed.get("Result") != "success" or observed.get("ExecMainStatus") != "0"):
            log = remote.run(["journalctl", "-u", unit, "--no-pager", "-n", "25"], timeout=60)
            raise DemoError(f"detached image job {unit} failed: {observed}; {log[-1500:]}")
        record["builder_image_job"]["status"] = "succeeded"
        state.save(root, record)
        return
    raise DemoError(f"detached image job {unit} exceeded four hours")


def _finish_existing_build(root: Path, record: dict, remote: RemoteSSH) -> None:
    """Use a verified VHD, or restart an interrupted build on the same builder."""
    if not record.get("builder_image_job"):
        _wait_for_existing_build(remote)
    workdir = _workdir(record)
    base = f"{workdir}/dist/HashBox-azure-gen2-x86_64.vhd"
    presence = remote.run(["sh", "-c", f"if [ -e {base} ] || [ -L {base} ]; "
                           "then echo present; else echo absent; fi"], timeout=60)
    checksum = remote.run(["sh", "-c", f"if [ -e {base}.sha256 ] || [ -L {base}.sha256 ]; "
                           "then echo present; else echo absent; fi"], timeout=60)
    if presence == "absent" and checksum == "absent":
        job = record.get("builder_image_job")
        if job is None:
            attempts = int(record.get("builder_resume_build_attempts", 0))
            _require(attempts < 3, "interrupted Guix build reached the bounded restart limit")
            unit = f"hashbox-image-{record['run_id']}-a{attempts + 1}.service"
            record["builder_resume_build_attempts"] = attempts + 1
            record["builder_image_job"] = {"status": "submitted", "unit": unit,
                                           "at": state.utc_now()}
            state.save(root, record)
            _log("No VHD exists; starting the Guix image as a detached Azure builder service...")
            try:
                remote.run(["sudo", "systemd-run", f"--unit={unit}",
                            "--property=Type=exec", "--property=User=hashbox-builder",
                            f"--property=WorkingDirectory={workdir}",
                            "--property=RuntimeMaxSec=14400", "/usr/bin/make", "image"], timeout=90)
            except Exception:
                # The reply may have been lost after systemd accepted the exact unit.
                _log("Detached image-job reply was uncertain; reading back the exact unit...")
        _wait_for_image_unit(root, record, remote)
    else:
        _require(presence == "present" and checksum == "present",
                 "incomplete VHD or checksum is retained on the builder; refusing overwrite")
    remote.run(["python3", "-I", "-B", f"{workdir}/toolchain/disk/vhd.py",
                "check", base], timeout=180)
    actual = remote.run(["sha256sum", base], timeout=180).split()[0]
    expected = remote.run(["cat", base + ".sha256"], timeout=60).split()[0]
    _require(actual == expected, "completed base VHD checksum differs")
    _capture_attestor_image(root, record, remote)
    if record.get("builder_resume_build"):
        record["builder_resume_build"]["status"] = "verified"
        state.save(root, record)


def _resume_builder_install(root: Path, record: dict, remote: RemoteSSH) -> None:
    """Finish idempotent installer scripts after a lost SSH controller."""
    workdir = _workdir(record)
    active = remote.run(["sh", "-c", f"pgrep -af '^(sudo )?(/bin/)?sh "
                         f"{workdir}/toolchain/builder/install-(guix|azure-cli)\\.sh$' || true"], timeout=60)
    _require(not active, "builder installer is still running; wait before resuming")
    _require(remote.run(["test", "-f", f"{workdir}/toolchain/builder/install-guix.sh"], timeout=60) == "",
             "saved builder source tree is missing")
    state.advance(root, record, "builder-install-resume-submitted")
    remote.run_logged(f"install-guix-resume-{record['run_id']}",
                      f"sudo sh {workdir}/toolchain/builder/install-guix.sh", timeout=2700)
    remote.run_logged(f"install-azure-cli-resume-{record['run_id']}",
                      f"sudo sh {workdir}/toolchain/builder/install-azure-cli.sh", timeout=900)
    state.advance(root, record, "builder-ready")
