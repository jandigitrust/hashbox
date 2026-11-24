"""List, add and remove CVMs in one run-owned deployment group."""

from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import secrets
import time

from hashbox.operation import state
from hashbox.project.config import load_azure_profile
from hashbox.source.attestor import advise as advise_attestor
from .admission import _account_preflight, _retail_vm_hourly
from .arm_templates import verify as verify_arm_templates
from .cli import AzureCLI
from .cvm import _deallocate_failed_cvm, _deploy_cvm
from .errors import DemoError, _log, _require
from .resources import _group_readback


def _known(record: dict) -> dict:
    """Expose old single-CVM records without rewriting their evidence."""
    if "instances" in record:
        return record["instances"]
    name = record["resources"].get("cvm_name")
    if not name:
        return {}
    return {name: {"name": name, "status": "verified" if record.get("cvm_guest_readback") else "unknown",
                   "legacy": True, "vm_id": record["resources"].get("cvm_id"),
                   "public_ip": record["resources"].get("cvm_public_ip")}}


def _inventory(azure: AzureCLI, group: str) -> dict[str, dict]:
    items = azure.json("resource", "list", "--resource-group", group, timeout=120)
    _require(isinstance(items, list), "CVM group inventory is invalid")
    result = {}
    for item in items:
        resource_id = item.get("id") if isinstance(item, dict) else None
        _require(isinstance(resource_id, str) and resource_id.casefold() not in result,
                 "CVM group inventory has missing or repeated IDs")
        result[resource_id.casefold()] = item
    return result


def _expected_ids(record: dict, name: str) -> dict[str, str]:
    group_id = record["groups"]["cvm"]["id"]
    return {
        "vm": f"{group_id}/providers/Microsoft.Compute/virtualMachines/{name}",
        "disk": f"{group_id}/providers/Microsoft.Compute/disks/{name}-os",
        "nic": f"{group_id}/providers/Microsoft.Network/networkInterfaces/{name}-nic",
        "pip": f"{group_id}/providers/Microsoft.Network/publicIPAddresses/{name}-pip",
        "nsg": f"{group_id}/providers/Microsoft.Network/networkSecurityGroups/{name}-nsg",
        "vnet": f"{group_id}/providers/Microsoft.Network/virtualNetworks/{name}-vnet",
    }


def _owned_resources(record: dict, name: str, inventory: dict[str, dict], *, legacy: bool) -> dict[str, str]:
    ids = _expected_ids(record, name)
    expected = {value.casefold() for value in ids.values()}
    for kind, resource_id in ids.items():
        item = inventory.get(resource_id.casefold())
        if item is None:
            continue
        tags = item.get("tags") or {}
        instance_tag = tags.get("hashbox_demo_instance")
        matching_instance = instance_tag in (None, name) if legacy else instance_tag == name
        _require(tags.get("hashbox_demo_run") == record["run_id"] and
                 tags.get("hashbox_demo_role") == "cvm" and
                 matching_instance,
                 f"{kind} ownership differs; refusing instance deletion")
    for resource_id, item in inventory.items():
        if (item.get("tags") or {}).get("hashbox_demo_instance") == name:
            _require(resource_id in expected, "instance has an untracked resource")
    return ids


def _gallery_admission(root: Path, azure: AzureCLI, record: dict) -> None:
    archive = state.run_path(root, record["run_id"]) / "source.tar.gz"
    _require(hashlib.sha256(archive.read_bytes()).hexdigest() ==
             record["artifacts"]["source_archive_sha256"], "saved source archive differs")
    publication = record.get("gallery_publication") or {}
    version_id = record["resources"]["gallery_version_id"]
    if publication:
        _require(publication.get("transport") == "rest" and
                 publication.get("version_id", "").casefold() == version_id.casefold(),
                 "saved Gallery publication identity differs")
        request = state.run_path(root, record["run_id"]) / publication["request_file"]
        request_bytes = request.read_bytes()
        _require(hashlib.sha256(request_bytes).hexdigest() == publication.get("request_sha256"),
                 "saved Gallery request differs")
        body = json.loads(request_bytes)
        signatures = (((body.get("properties") or {}).get("securityProfile") or {}).get("uefiSettings") or {})
        db = ((signatures.get("additionalSignatures") or {}).get("db") or [])
        cert_hashes = {hashlib.sha256(base64.b64decode(value, validate=True)).hexdigest()
                       for item in db if item.get("type") == "x509" for value in item.get("value", [])}
        _require(record["artifacts"]["uefi_db_certificate_sha256"] in cert_hashes,
                 "saved Gallery request certificate differs")
    else:
        _require((record.get("cvm_azure_readback") or {}).get("gallery_version_id", "").casefold() ==
                 version_id.casefold(), "saved guest proof is not bound to this Gallery version")
    observed = azure.json("rest", "--method", "get", "--url",
                          f"https://management.azure.com{version_id}?api-version=2025-12-03", timeout=120)
    tags = observed.get("tags") or {}
    _require(observed.get("id", "").casefold() == version_id.casefold() and
             (observed.get("properties") or {}).get("provisioningState") == "Succeeded" and
             tags.get("hashbox_demo_run") == record["run_id"] and
             tags.get("artifact_sha256") == record["artifacts"]["derived_vhd_sha256"] and
             tags.get("uefi_db_sha256") == record["artifacts"]["uefi_db_certificate_sha256"],
             "Gallery version ID, provisioning or digest tags differ")
    properties = observed.get("properties") or {}
    source = ((properties.get("storageProfile") or {}).get("osDiskImage") or {}).get("source") or {}
    _require(source.get("uri") == record["resources"].get("blob_uri") and
             source.get("storageAccountId", "").casefold() ==
             record["resources"].get("storage_account_id", "").casefold(),
             "Gallery version source Blob identity differs")
    security = properties.get("securityProfile") or {}
    observed_db = (((security.get("uefiSettings") or {}).get("additionalSignatures") or {}).get("db") or [])
    returned_hashes = {hashlib.sha256(base64.b64decode(value, validate=True)).hexdigest()
                       for item in observed_db if item.get("type") == "x509" for value in item.get("value", [])}
    _require(not returned_hashes or record["artifacts"]["uefi_db_certificate_sha256"] in returned_hashes,
             "Gallery returned a different UEFI DB certificate")


def list_instances(root: Path, run_id: str) -> dict:
    record = state.load(root, run_id)
    azure = AzureCLI(record["subscription_id"])
    group = record["groups"]["cvm"]["name"]
    if not azure.group_exists(group):
        return {"run_id": run_id, "group": group, "group_status": "absent", "count": 0, "instances": []}
    _group_readback(azure, record, "cvm")
    listed = azure.json("vm", "list", "--resource-group", group, "--show-details", timeout=180)
    _require(isinstance(listed, list), "CVM list readback is invalid")
    known = _known(record)
    rows = []
    foreign = 0
    for vm in listed:
        name = vm.get("name", "")
        tags = vm.get("tags") or {}
        if tags.get("hashbox_demo_run") != run_id or tags.get("hashbox_demo_role") != "cvm":
            foreign += 1
            continue
        _require(vm.get("id", "").casefold() == _expected_ids(record, name)["vm"].casefold() and
                 (tags.get("hashbox_demo_instance") in (None, name)),
                 "CVM list contains an identity or instance tag mismatch")
        rows.append({"name": name, "power": vm.get("powerState"), "address": vm.get("publicIps"),
                     "record_status": known.get(name, {}).get("status", "unrecorded")})
    rows.sort(key=lambda item: item["name"])
    return {"run_id": run_id, "group": group, "group_status": "owned-present",
            "count": len(rows), "foreign_vm_count": foreign, "instances": rows}


def list_runs(root: Path) -> dict:
    """Count instances in locally recorded groups with fresh Azure reads."""
    rows = []
    for run_id in state.run_ids(root):
        record = state.load(root, run_id)
        try:
            found = list_instances(root, run_id)
            rows.append({"run_id": run_id, "region": record["location"],
                         "group": found["group"], "group_status": found["group_status"],
                         "instance_count": found["count"]})
        except Exception as error:
            rows.append({"run_id": run_id, "region": record["location"],
                         "group": record["groups"]["cvm"]["name"],
                         "group_status": f"unreachable: {error}", "instance_count": None})
    return {"runs": rows, "reachable_instance_count": sum(row["instance_count"] or 0 for row in rows),
            "unreachable_run_count": sum(row["instance_count"] is None for row in rows)}


def create_instance(root: Path, run_id: str, name: str | None = None) -> str:
    advise_attestor(root, operation="new CVM deployment")
    with state.locked(root, run_id):
        verify_arm_templates(root)
        record = state.load(root, run_id)
        _require(record["phase"] == "complete", "run must be complete before adding an instance")
        guest = (record.get("cvm_guest_readback") or {}).get("observation") or {}
        _require(guest.get("secure_boot_enabled") is True and
                 guest.get("uefi_db_certificate_sha256") == record["artifacts"].get("uefi_db_certificate_sha256") and
                 guest.get("tpm_device") == "/dev/tpm0",
                 "the first CVM has no matching saved guest Secure Boot proof")
        name = state.validate_instance_name(name or state.next_instance_name(record))
        known = _known(record)
        _require(name not in known, "instance name was already used in this run")
        profile = load_azure_profile(record["profile"], root)
        _require(profile.subscription_id.casefold() == record["subscription_id"].casefold() and
                 profile.cvm_size == record["resources"].get("cvm_size"),
                 "profile subscription or CVM size differs from the saved run")
        profile = replace(profile, location=record["location"])
        azure = AzureCLI(record["subscription_id"])
        _account_preflight(azure, profile, builder_required=False)
        _group_readback(azure, record, "image")
        _group_readback(azure, record, "cvm")
        assert_owned_cvm_group(azure, record)
        _gallery_admission(root, azure, record)
        hourly = _retail_vm_hourly(profile, profile.cvm_size)
        inventory = _inventory(azure, record["groups"]["cvm"]["name"])
        _require(not any(resource_id.casefold() in inventory for resource_id in _expected_ids(record, name).values()),
                 "proposed instance name already has resources in the CVM group")
        deployment_label = f"cvm-{secrets.token_hex(4)}"
        record["instances"] = known
        record["instances"][name] = {"name": name, "status": "reserved",
                                     "deployment_label": deployment_label, "created_at": state.utc_now()}
        state.save(root, record)
        _log(f"Instance: {name}; group: {record['groups']['cvm']['name']}; "
             f"Gallery: {record['resources']['gallery_version_id']}")
        _log(f"Compute retail: ${hourly:.3f}/h while running; disk and public IP extra.")
        _log(f"To remove it: hashbox instance delete {run_id} {name}")
        try:
            _deploy_cvm(root, profile, azure, record, vm_name=name, deployment_label=deployment_label)
            state.advance(root, record, "complete")
            _log(f"Instance {name} verified at {record['instances'][name]['public_ip']}")
            return name
        except (Exception, KeyboardInterrupt) as error:
            record["instances"][name]["status"] = "failed"
            state.record_error(root, record, f"instance {name}: {type(error).__name__}: {error}")
            try:
                _deallocate_failed_cvm(root, azure, record, vm_name=name)
            except Exception as deallocation_error:
                state.record_error(root, record, f"instance {name} deallocation: {deallocation_error}")
            _log(f"Inspect with: hashbox instance list {run_id}")
            _log(f"Remove owned resources with: hashbox instance delete {run_id} {name}")
            raise


def delete_instance(root: Path, run_id: str, name: str) -> None:
    name = state.validate_instance_name(name)
    with state.locked(root, run_id):
        record = state.load(root, run_id)
        _require(record.get("cvm_guest_readback") is not None,
                 "the first CVM has not completed guest verification; use group delete or cleanup")
        known = _known(record)
        _require(name in known, "instance is not recorded in this run")
        record["instances"] = known
        azure = AzureCLI(record["subscription_id"])
        group = record["groups"]["cvm"]["name"]
        account = azure.json("account", "show", timeout=60)
        _require(account.get("id", "").casefold() == record["subscription_id"].casefold(),
                 "Azure CLI subscription differs from the run")
        if not azure.group_exists(group):
            if record["phase"] == "cleanup-complete":
                _log(f"Instance {name} is already absent with its cleaned-up group.")
                return
            record["instances"][name]["status"] = "deleted-with-group"
            state.save(root, record)
            return
        _group_readback(azure, record, "cvm")
        inventory = _inventory(azure, group)
        ids = _owned_resources(record, name, inventory, legacy=bool(known[name].get("legacy")))
        vm = inventory.get(ids["vm"].casefold())
        if vm is not None:
            observed = azure.json("vm", "show", "--ids", ids["vm"], timeout=120)
            disk = (observed.get("storageProfile") or {}).get("osDisk") or {}
            disk_id = (disk.get("managedDisk") or {}).get("id", "")
            nics = ((observed.get("networkProfile") or {}).get("networkInterfaces") or [])
            _require(disk_id.casefold() == ids["disk"].casefold() and len(nics) == 1 and
                     nics[0].get("id", "").casefold() == ids["nic"].casefold(),
                     "VM disk or NIC binding differs; refusing instance deletion")
        for kind in ("vm", "nic", "disk", "pip", "nsg", "vnet"):
            resource_id = ids[kind]
            inventory = _inventory(azure, group)
            _owned_resources(record, name, inventory, legacy=bool(known[name].get("legacy")))
            if resource_id.casefold() not in inventory:
                continue
            record["instances"][name]["status"] = f"deleting-{kind}"
            state.save(root, record)
            _log(f"Deleting owned {kind} for {name}...")
            azure.call("resource", "delete", "--ids", resource_id, timeout=900)
            for _ in range(30):
                if resource_id.casefold() not in _inventory(azure, group):
                    break
                time.sleep(10)
            else:
                raise DemoError(f"{kind} deletion was submitted but not verified")
        remaining = azure.json("vm", "list", "--resource-group", group, timeout=120)
        _require(isinstance(remaining, list) and not any(vm.get("name") == name for vm in remaining),
                 "VM still appears after instance deletion")
        record["instances"][name]["status"] = "deleted"
        recovering_add = record["phase"] != "complete" and not record["phase"].startswith("cleanup-")
        if recovering_add and azure.group_exists(record["groups"]["image"]["name"]):
            state.advance(root, record, "complete")
        else:
            state.save(root, record)
        _log(f"Instance {name}: VM, disk and network resources are absent.")


def assert_owned_cvm_group(azure: AzureCLI, record: dict) -> None:
    """Refuse whole-group deletion if someone placed unrelated resources inside."""
    group = record["groups"]["cvm"]["name"]
    for item in _inventory(azure, group).values():
        tags = item.get("tags") or {}
        _require(tags.get("hashbox_demo_run") == record["run_id"] and
                 tags.get("hashbox_demo_role") == "cvm",
                 "CVM group contains an unowned resource; refusing group deletion")


def delete_cvm_group(root: Path, run_id: str) -> None:
    with state.locked(root, run_id):
        record = state.load(root, run_id)
        _require(record["phase"] in {"complete", "cvm-group-delete-submitted",
                                     "cvm-group-deleted", "cleanup-complete"} or
                 bool(record.get("errors")), "run is still active; wait for completion before deleting its CVM group")
        azure = AzureCLI(record["subscription_id"])
        account = azure.json("account", "show", timeout=60)
        _require(account.get("id", "").casefold() == record["subscription_id"].casefold(),
                 "Azure CLI subscription differs from the run")
        group = record["groups"]["cvm"]["name"]
        if record["phase"] == "cleanup-complete":
            _require(not azure.group_exists(group), "CVM group exists after recorded cleanup")
            _log(f"CVM group {group} is already absent.")
            return
        if azure.group_exists(group):
            _group_readback(azure, record, "cvm")
            assert_owned_cvm_group(azure, record)
            state.advance(root, record, "cvm-group-delete-submitted")
            _log(f"Deleting owned CVM group {group} and all its instances...")
            azure.group_delete(group)
            azure.group_wait_deleted(group)
            _require(not azure.group_exists(group), "CVM group deletion was not verified")
        record["groups"]["cvm"]["deleted"] = True
        for instance in record.setdefault("instances", _known(record)).values():
            instance["status"] = "deleted-with-group"
        state.advance(root, record, "cvm-group-deleted")
        _log(f"CVM group absent. Gallery group remains; remove it with: hashbox cleanup {run_id}")
