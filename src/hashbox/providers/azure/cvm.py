"""Exact Gallery CVM deployment, pinned guest proof and failure deallocation."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time

from hashbox.build.remote import RemoteSSH
from hashbox.operation import state
from hashbox.project.config import AzureProfile
from .cli import AzureCLI, power_codes
from .errors import DemoError, _log, _require
from .resources import _deployment, _group_readback


def _guest_host_key(azure: AzureCLI, group: str, vm: str, ip: str, output: Path) -> None:
    expected = None
    latest_log = ""
    for attempt in range(30):
        try:
            log = azure.call("vm", "boot-diagnostics", "get-boot-log", "--resource-group", group,
                             "--name", vm, timeout=90)
            latest_log = log
            match = re.findall(r"ssh-ed25519 [A-Za-z0-9+/=]+", log)
            if len(set(match)) == 1:
                expected = match[0]
                break
        except Exception:
            pass
        time.sleep(20)
    if latest_log:
        serial_path = output.with_name(f"{vm}.serial.log")
        serial_path.write_text(latest_log, encoding="utf-8")
        serial_path.chmod(0o600)
    _require(expected is not None, "CVM serial log did not publish one SSH host key")
    for attempt in range(30):
        result = subprocess.run(["ssh-keyscan", "-T", "10", "-t", "ed25519", ip],
                                capture_output=True, text=True, timeout=15)
        lines = [line for line in result.stdout.splitlines() if line and not line.startswith("#")]
        keys = {" ".join(line.split()[1:3]) for line in lines if len(line.split()) >= 3}
        if expected in keys:
            output.write_text(f"{ip} {expected}\n", encoding="ascii")
            output.chmod(0o600)
            return
        if keys:
            raise DemoError("CVM SSH host key differs from Azure serial readback")
        time.sleep(20)
    raise DemoError("CVM SSH host key was not reachable")


GUEST_PROOF_SCRIPT = """\
import glob, hashlib, json, pathlib, struct, sys, uuid

expected = sys.argv[1].lower()
secure = glob.glob('/sys/firmware/efi/efivars/SecureBoot-*')
db = glob.glob('/sys/firmware/efi/efivars/db-*')
assert len(secure) == 1 and len(db) == 1, 'UEFI SecureBoot or db variable missing'
secure_bytes = pathlib.Path(secure[0]).read_bytes()
assert len(secure_bytes) >= 5 and secure_bytes[4] == 1, 'Secure Boot disabled'
raw_db = pathlib.Path(db[0]).read_bytes()
assert len(raw_db) >= 32, 'UEFI db is too short'
payload = raw_db[4:]
x509_type = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072')
found = []
offset = 0
while offset < len(payload):
    assert len(payload) - offset >= 28, 'truncated EFI_SIGNATURE_LIST'
    signature_type = uuid.UUID(bytes_le=payload[offset:offset+16])
    list_size, header_size, signature_size = struct.unpack_from('<III', payload, offset+16)
    assert list_size >= 28 + header_size and signature_size > 16, 'invalid EFI_SIGNATURE_LIST sizes'
    end = offset + list_size
    assert end <= len(payload), 'EFI_SIGNATURE_LIST exceeds db'
    entries = list_size - 28 - header_size
    assert entries % signature_size == 0, 'EFI_SIGNATURE_LIST entries are misaligned'
    start = offset + 28 + header_size
    for position in range(start, end, signature_size):
        if signature_type == x509_type:
            certificate = payload[position+16:position+signature_size]
            found.append(hashlib.sha256(certificate).hexdigest())
    offset = end
assert expected in found, 'expected X.509 DER SHA-256 absent from UEFI db'
tpm = pathlib.Path('/sys/class/tpm/tpm0')
assert tpm.exists() and pathlib.Path('/dev/tpm0').exists(), 'guest TPM device absent'
version_file = tpm / 'tpm_version_major'
tpm_major = version_file.read_text().strip() if version_file.exists() else None
assert tpm_major is None or tpm_major == '2', 'guest TPM version differs from 2.0'
print(json.dumps({'secure_boot_enabled': True, 'uefi_db_certificate_sha256': expected,
                  'uefi_db_payload_sha256': hashlib.sha256(payload).hexdigest(),
                  'x509_entry_count': len(found), 'tpm_device': '/dev/tpm0',
                  'tpm_version_major': tpm_major}, sort_keys=True))
"""


def _deploy_cvm(root: Path, profile: AzureProfile, azure: AzureCLI, record: dict,
                vm_name: str | None = None, deployment_label: str = "cvm") -> None:
    group = record["groups"]["cvm"]["name"]
    vm = vm_name or record["resources"].get("cvm_name") or f"hbx-demo-{record['run_id'][:8]}"
    if vm_name is None:
        record["resources"]["cvm_name"] = vm
    instance = record.setdefault("instances", {}).setdefault(vm, {"name": vm})
    tags = {"hashbox_demo_run": record["run_id"], "hashbox_demo_role": "cvm",
            "hashbox_demo_instance": vm}
    cloud_config = (
        "#cloud-config\n"
        "runcmd:\n"
        "  - [sh, -c, 'cat /etc/ssh/ssh_host_ed25519_key.pub > /dev/ttyS0']\n"
    )
    custom_data = base64.b64encode(cloud_config.encode()).decode()
    _log("Deploying one Secure Boot Confidential VM from the exact Gallery version...")
    instance["status"] = "deployment-submitted"
    state.save(root, record)
    response = _deployment(root, azure, record, "cvm", deployment_label,
                           "infra/providers/azure/deployment/cvm.arm.json",
                           {
                               "vmName": vm, "location": record["location"], "vmSize": profile.cvm_size,
                               "imageVersionId": record["resources"]["gallery_version_id"],
                               "sshPublicKey": profile.ssh_public_key,
                               "sshSourceCidr": profile.ssh_source_cidr,
                               "customData": custom_data, "resourceTags": tags,
                           }, timeout=3600)
    outputs = response["properties"].get("outputs") or {}
    vm_id = outputs.get("vmId", {}).get("value")
    ip = outputs.get("publicIpAddress", {}).get("value")
    _require(isinstance(vm_id, str) and vm_id.lower().endswith(f"/virtualmachines/{vm.lower()}"), "CVM ID differs")
    _require(vm_id.casefold() ==
             (record["groups"]["cvm"]["id"] + "/providers/Microsoft.Compute/virtualMachines/" + vm).casefold(),
             "CVM ID is outside the exact owned group")
    ipaddress.ip_address(ip)
    observed = azure.json("vm", "show", "--resource-group", group, "--name", vm)
    _require(observed.get("id", "").casefold() == vm_id.casefold() and
             (observed.get("tags") or {}).get("hashbox_demo_run") == record["run_id"] and
             (observed.get("tags") or {}).get("hashbox_demo_role") == "cvm" and
             (observed.get("hardwareProfile") or {}).get("vmSize") == profile.cvm_size,
             "CVM readback ID, ownership or size differs")
    security = observed.get("securityProfile") or {}
    uefi = security.get("uefiSettings") or {}
    _require(security.get("securityType") == "ConfidentialVM" and
             uefi.get("secureBootEnabled") is True and uefi.get("vTpmEnabled") is True,
             "CVM Secure Boot or vTPM readback differs")
    image_id = ((observed.get("storageProfile") or {}).get("imageReference") or {}).get("id", "")
    _require(image_id.casefold() == record["resources"]["gallery_version_id"].casefold(),
             "CVM did not use the exact Gallery version")
    os_disk = ((observed.get("storageProfile") or {}).get("osDisk") or {})
    encryption = ((os_disk.get("managedDisk") or {}).get("securityProfile") or {}).get("securityEncryptionType")
    _require(encryption == "VMGuestStateOnly", "CVM disk encryption mode differs")
    pip_id = outputs.get("publicIpId", {}).get("value")
    _require(isinstance(pip_id, str) and pip_id.casefold().startswith(record["groups"]["cvm"]["id"].casefold() + "/"),
             "CVM public IP ID differs")
    pip = azure.json("network", "public-ip", "show", "--ids", pip_id, timeout=120)
    _require(pip.get("id", "").casefold() == pip_id.casefold() and
             pip.get("ipAddress") == ip and
             (pip.get("tags") or {}).get("hashbox_demo_run") == record["run_id"],
             "CVM public IP address or ownership differs")
    azure_readback = {
        "checked_at": state.utc_now(), "vm_id": vm_id, "public_ip_id": pip_id,
        "public_ip": ip, "gallery_version_id": image_id,
        "security_type": security["securityType"], "secure_boot_enabled": True,
        "vtpm_enabled": True, "security_encryption_type": encryption,
        "vm_size": profile.cvm_size,
        "commands": ["az deployment group create", "az vm show", "az network public-ip show"],
    }
    instance.update(status="azure-verified", vm_id=vm_id, public_ip=ip,
                    public_ip_id=pip_id, azure_readback=azure_readback)
    if vm == record["resources"].get("cvm_name"):
        record["resources"].update(cvm_id=vm_id, cvm_public_ip=ip)
        record["cvm_azure_readback"] = azure_readback
    state.advance(root, record, "cvm-created")
    for attempt in range(30):
        view = azure.json("vm", "get-instance-view", "--resource-group", group, "--name", vm, timeout=90)
        codes = power_codes(view)
        if "PowerState/running" in codes:
            break
        time.sleep(20)
    else:
        raise DemoError("CVM did not reach running power state")
    azure_readback["power_state"] = "PowerState/running"
    azure_readback["power_checked_at"] = state.utc_now()
    state.save(root, record)
    known_hosts = state.run_path(root, record["run_id"]) / f"{vm}.known_hosts"
    _guest_host_key(azure, group, vm, ip, known_hosts)
    guest = RemoteSSH(ip, profile.ssh_private_key, known_hosts, user="hashbox")
    proof_path = state.run_path(root, record["run_id"]) / f"{vm}.guest-check.py"
    proof_path.write_text(GUEST_PROOF_SCRIPT, encoding="utf-8")
    proof_path.chmod(0o600)
    expected_cert_sha = record["artifacts"]["uefi_db_certificate_sha256"]
    last_error = None
    for attempt in range(20):
        try:
            proof = guest.run(["python3", "-c", GUEST_PROOF_SCRIPT, expected_cert_sha], timeout=45)
            observation = json.loads(proof)
            _require(observation.get("secure_boot_enabled") is True and
                     observation.get("uefi_db_certificate_sha256") == expected_cert_sha and
                     observation.get("tpm_device") == "/dev/tpm0",
                     "CVM guest proof values differ")
            break
        except Exception as error:
            last_error = error
            if attempt == 19:
                raise DemoError(f"CVM guest SSH or UEFI/TPM readback failed: {str(last_error)[:500]}") from error
            time.sleep(20)
    guest_readback = {
        "checked_at": state.utc_now(), "observation": observation,
        "proof_script_sha256": hashlib.sha256(proof_path.read_bytes()).hexdigest(),
        "commands": ["az vm boot-diagnostics get-boot-log", "ssh-keyscan -t ed25519",
                     f"ssh hashbox@{ip} python3 -c <cvm-guest-check.py> {expected_cert_sha}"],
    }
    instance.update(status="verified", guest_readback=guest_readback)
    if vm == record["resources"].get("cvm_name"):
        record["cvm_guest_readback"] = guest_readback
    state.advance(root, record, "guest-secure-boot-verified")


def _deallocate_failed_cvm(root: Path, azure: AzureCLI, record: dict,
                           vm_name: str | None = None) -> None:
    """Stop only the exact owned CVM if boot or guest verification fails."""
    group = record["groups"]["cvm"]["name"]
    if not azure.group_exists(group):
        return
    _group_readback(azure, record, "cvm")
    name = vm_name or record["resources"].get("cvm_name") or f"hbx-demo-{record['run_id'][:8]}"
    result = record.setdefault("instances", {}).setdefault(name, {"name": name}) if vm_name else record
    result_field = "failure_deallocation" if vm_name else "cvm_failure_deallocation"
    listed = azure.json("vm", "list", "--resource-group", group, timeout=120)
    found = [vm for vm in listed if vm.get("name") == name]
    _require(len(found) <= 1, "CVM group contains ambiguous matching VMs")
    if not found:
        return
    vm = found[0]
    _require(vm.get("id", "").casefold() ==
             (record["groups"]["cvm"]["id"] + "/providers/Microsoft.Compute/virtualMachines/" + name).casefold() and
             (vm.get("tags") or {}).get("hashbox_demo_run") == record["run_id"] and
             (vm.get("tags") or {}).get("hashbox_demo_role") == "cvm" and
             (vm.get("tags") or {}).get("hashbox_demo_instance", name) == name,
             "CVM ownership differs; refusing deallocation")
    view = azure.json("vm", "get-instance-view", "--resource-group", group, "--name", name, timeout=120)
    if "PowerState/deallocated" in power_codes(view):
        result[result_field] = "verified"
        state.save(root, record)
        return
    result[result_field] = "submitted"
    state.save(root, record)
    azure.call("vm", "deallocate", "--resource-group", group, "--name", name,
               "--no-wait", timeout=120)
    for _ in range(30):
        view = azure.json("vm", "get-instance-view", "--resource-group", group,
                          "--name", name, timeout=90)
        if "PowerState/deallocated" in power_codes(view):
            result[result_field] = "verified"
            state.save(root, record)
            return
        time.sleep(20)
    raise DemoError("failed CVM deallocation was submitted but not verified")
