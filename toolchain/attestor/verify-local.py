#!/usr/bin/env python3
"""Collect two fresh local-tunnel challenges and verify the second with Confido.

The first snapshot makes a run-local, self-enrolled reference. It is evidence
of this boot, not an independently approved baseline or TLS session binding.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from hashbox.operation import state  # noqa: E402
from hashbox.build.remote import RemoteSSH  # noqa: E402
from hashbox.project.config import load_azure_profile  # noqa: E402
from hashbox.providers.azure.cli import AzureCLI, power_codes  # noqa: E402
from hashbox.providers.azure.cvm import GUEST_PROOF_SCRIPT  # noqa: E402
from hashbox.providers.azure.resources import _group_readback  # noqa: E402
from hashbox.source.attestor import pin as attestor_pin  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def collect(nonce: bytes) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", 18001, timeout=30)
    body = json.dumps({"nonce": base64.b64encode(nonce).decode()}).encode()
    try:
        connection.request("POST", "/tee-report", body=body,
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        cache = response.getheader("Cache-Control", "")
        if response.status != 200 or not any(value.strip().lower() == "no-store"
                                              for value in cache.split(",")):
            raise ValueError(f"Attestor HTTP {response.status} or missing no-store")
        payload = response.read(4 * 1024 * 1024 + 1)
    finally:
        connection.close()
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError("Attestor response exceeds bound")
    value = json.loads(payload)
    if value.get("profile") != "azure-snp-vtpm-ima/1" or value.get("wireVersion") != 1:
        raise ValueError("Attestor evidence profile differs")
    return value


def selectors(evidence: dict, product: str) -> dict:
    # These fields only select public KDS material. Confido later checks the
    # SNP signature and compares the authenticated fields with the policy.
    report = bytes(evidence["evidence"]["report"])
    if (not 1236 <= len(report) <= 65536 or
            int.from_bytes(report[1224:1228], "little") != 2 or
            int.from_bytes(report[1228:1232], "little") != 1 or
            1236 + int.from_bytes(report[1232:1236], "little") > len(report)):
        raise ValueError("unsupported Azure HCL/SNP report")
    raw = report[32:32 + 1184]
    version = int.from_bytes(raw[:4], "little")
    if version not in (2, 3, 5):
        raise ValueError("unsupported SNP report version")
    if version != 2:
        family, model = raw[392], raw[393]
        inferred = ("Milan" if family == 0x19 and model < 0x10 else
                    "Genoa" if family == 0x19 and 0x10 <= model < 0x20 else None)
        if inferred != product:
            raise ValueError("SNP processor hint differs from selected product")
    tcb = [raw[384], raw[385], raw[390], raw[391]]
    return {"report": report, "version": version, "chip_id": raw[416:480].hex(),
            "tcb": tcb, "launch_measurement": raw[144:192].hex()}


def fetch(url: str, limit: int = 65536) -> bytes:
    request = Request(url, headers={"User-Agent": "hashbox-demo-attestation/1"})
    with urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("AMD KDS response exceeds bound")
    return data


def kds(product: str, selected: dict) -> tuple[bytes, bytes, str]:
    base = f"https://kdsintf.amd.com/vcek/v1/{product}"
    chain = fetch(base + "/cert_chain")
    tcb = selected["tcb"]
    vcek = fetch(base + f"/{selected['chip_id']}?blSPL={tcb[0]:02}&teeSPL={tcb[1]:02}"
                      f"&snpSPL={tcb[2]:02}&ucodeSPL={tcb[3]:02}")
    certificates = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                              chain, flags=re.DOTALL)
    if len(certificates) != 2:
        raise ValueError("AMD KDS did not return ASK and ARK certificates")
    ark_der = ssl.PEM_cert_to_DER_cert(certificates[1].decode("ascii"))
    return chain, vcek, sha256(ark_der)


def pcr10(evidence: dict) -> str:
    banks = evidence["evidence"]["quote"]["pcr_banks"]
    sha256_banks = [bank for bank in banks if bank.get("algo") == "Sha256"]
    if len(sha256_banks) != 1 or len(sha256_banks[0].get("pcr_values", [])) <= 10:
        raise ValueError("vTPM quote lacks SHA-256 PCR 10")
    value = bytes(sha256_banks[0]["pcr_values"][10])
    if len(value) != 32:
        raise ValueError("vTPM PCR 10 length differs")
    return value.hex()


def git_commit(reference_dir: Path) -> str:
    subprocess.run(["git", "init", "-q", str(reference_dir)], check=True)
    subprocess.run(["git", "-C", str(reference_dir), "add", "reference.json"], check=True)
    environment = {**os.environ, "GIT_AUTHOR_NAME": "HashBox local demo",
                   "GIT_AUTHOR_EMAIL": "local@hashbox.invalid",
                   "GIT_COMMITTER_NAME": "HashBox local demo",
                   "GIT_COMMITTER_EMAIL": "local@hashbox.invalid"}
    subprocess.run(["git", "-C", str(reference_dir), "commit", "-q", "-m",
                    "Enroll this boot's IMA and PCR 10 reference"], check=True, env=environment)
    return subprocess.check_output(["git", "-C", str(reference_dir), "rev-parse", "HEAD"],
                                   text=True).strip()


def start_tunnel(record: dict, profile: object, known_hosts: Path) -> subprocess.Popen:
    command = ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
               "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=20",
               "-i", str(profile.ssh_private_key), "-L", "127.0.0.1:18001:127.0.0.1:18001",
               f"hashbox@{record['resources']['cvm_public_ip']}"]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(20):
        if process.poll() is not None:
            raise ValueError("pinned SSH tunnel exited before Attestor became reachable")
        try:
            with socket.create_connection(("127.0.0.1", 18001), timeout=1):
                return process
        except OSError:
            time.sleep(1)
    process.terminate()
    raise ValueError("pinned SSH tunnel did not become reachable")


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id")
    parser.add_argument("--product", choices=("Milan", "Genoa"), required=True)
    args = parser.parse_args()
    record = state.load(ROOT, args.run_id)
    if record.get("phase") != "complete" or not record.get("cvm_guest_readback"):
        raise ValueError("run has no completed Secure Boot guest proof")
    profile = load_azure_profile(record["profile"], ROOT)
    if profile.subscription_id.casefold() != record["subscription_id"].casefold():
        raise ValueError("profile subscription differs from run")
    azure = AzureCLI(record["subscription_id"])
    _group_readback(azure, record, "cvm")
    name = record["resources"]["cvm_name"]
    vm = azure.json("vm", "show", "-g", record["groups"]["cvm"]["name"], "-n", name)
    security = vm.get("securityProfile") or {}
    uefi = security.get("uefiSettings") or {}
    os_disk = ((vm.get("storageProfile") or {}).get("osDisk") or {})
    disk_mode = ((os_disk.get("managedDisk") or {}).get("securityProfile") or {}).get("securityEncryptionType")
    if (vm.get("id", "").casefold() != record["resources"]["cvm_id"].casefold() or
            (vm.get("tags") or {}).get("hashbox_demo_run") != args.run_id or
            (vm.get("hardwareProfile") or {}).get("vmSize") != record["resources"]["cvm_size"] or
            ((vm.get("storageProfile") or {}).get("imageReference") or {}).get("id", "").casefold() !=
            record["resources"]["gallery_version_id"].casefold() or
            security.get("securityType") != "ConfidentialVM" or
            uefi.get("secureBootEnabled") is not True or
            uefi.get("vTpmEnabled") is not True or disk_mode != "VMGuestStateOnly"):
        raise ValueError("live Azure CVM identity, image or confidential settings differ")
    view = azure.json("vm", "get-instance-view", "-g", record["groups"]["cvm"]["name"], "-n", name)
    if "PowerState/running" not in power_codes(view):
        raise ValueError("CVM is not running")
    known_hosts = state.run_path(ROOT, args.run_id) / f"{name}.known_hosts"
    if not known_hosts.is_file():
        raise ValueError("pinned guest SSH host-key file is absent")
    expected_image = record["artifacts"].get("attestor_oci")
    if not isinstance(expected_image, dict):
        raise ValueError("run has no builder-verified embedded Attestor OCI identity")
    guest = RemoteSSH(record["resources"]["cvm_public_ip"], profile.ssh_private_key,
                      known_hosts, user="hashbox")
    proof = json.loads(guest.run(["python3", "-c", GUEST_PROOF_SCRIPT,
                                  record["artifacts"]["uefi_db_certificate_sha256"]], timeout=60))
    if proof.get("secure_boot_enabled") is not True or \
            proof.get("uefi_db_certificate_sha256") != record["artifacts"]["uefi_db_certificate_sha256"]:
        raise ValueError("fresh guest Secure Boot and UEFI db proof differs")
    guest_image = json.loads(guest.run(["cat", "/etc/hashbox/attestor.oci.json"], timeout=60))
    guest_archive_sha = guest.run(["sha256sum", "/etc/hashbox/attestor.oci.tar"],
                                  timeout=300).split()[0]
    if guest_image != expected_image or guest_archive_sha != expected_image["archive_sha256"]:
        raise ValueError("guest Attestor OCI bytes differ from the builder artifact")
    confido = ROOT / ".local/attestation-tools/confido"
    binary = confido / "client/target/release/confido-cli"
    if not binary.is_file():
        raise ValueError("local Confido main verifier is not built")
    head = subprocess.check_output(["git", "-C", str(confido), "rev-parse", "HEAD"],
                                   text=True).strip()
    upstream = subprocess.check_output(["git", "ls-remote",
                                        "https://github.com/jandigitrust/confido.git",
                                        "refs/heads/main"], text=True, timeout=30).split()[0]
    if head != upstream:
        raise ValueError("local Confido checkout differs from current main")

    output = state.run_path(ROOT, args.run_id) / f"attestation-{int(time.time())}-{secrets.token_hex(4)}"
    output.mkdir(mode=0o700)
    write_new(output / "guest-secure-boot.json", json_bytes(proof))
    write_new(output / "guest-attestor-image.json", json_bytes({
        "metadata": guest_image, "archive_sha256": guest_archive_sha,
        "vm_id": record["resources"]["cvm_id"],
        "gallery_version_id": record["resources"]["gallery_version_id"],
    }))
    tunnel = start_tunnel(record, profile, known_hosts)
    try:
        # Enroll one snapshot from this boot. It is deliberately described as
        # local enrollment, not as an independently trusted reference.
        first_nonce = secrets.token_bytes(32)
        first = collect(first_nonce)
        selected = selectors(first, args.product)
        reference = {"ima_measurements": first["evidence"]["ima_measurements"],
                     "pcr10_sha256": pcr10(first)}
        reference_bytes = json_bytes(reference)
        reference_dir = output / "reference-source"
        reference_dir.mkdir(mode=0o700)
        write_new(reference_dir / "reference.json", reference_bytes)
        reference_commit = git_commit(reference_dir)
        chain, vcek, ark = kds(args.product, selected)
        policy = {"schema_version": 2, "profile": "azure-snp-vtpm-ima/1",
                  "platform": {"product": args.product, "ark_sha256": ark,
                               "launch_measurement": selected["launch_measurement"],
                               "minimum_tcb": selected["tcb"]},
                  "reference": {"repository": "hashbox-demo/local-reference",
                                "commit": reference_commit, "path": "reference.json",
                                "sha256": sha256(reference_bytes)}}
        policy_path = output / "verifier-policy.json"
        write_new(policy_path, json_bytes(policy))
        write_new(output / "enrollment-response.json", json_bytes(first))
        # A second, independently generated challenge must match the enrolled
        # IMA log and PCR value before this demo records a verified result.
        second_nonce = secrets.token_bytes(32)
        started = time.monotonic()
        second = collect(second_nonce)
        if selectors(second, args.product)["chip_id"] != selected["chip_id"]:
            raise ValueError("second SNP report identifies another chip")
        evaluated_at = int(time.time())
        archive = {"schema_version": 2, "mode": "live_collection",
                   "origin": f"ssh://{record['resources']['cvm_public_ip']}:18001",
                   "inputs": {"report": base64.b64encode(json_bytes(second)).decode(),
                              "amd_chain": base64.b64encode(chain).decode(),
                              "vcek": base64.b64encode(vcek).decode(),
                              "reference": base64.b64encode(reference_bytes).decode()},
                   "context": {"expected_nonce_base64": base64.b64encode(second_nonce).decode(),
                               "evaluation_unix_seconds": evaluated_at}}
        archive_path = output / "live-archive.json"
        write_new(archive_path, json_bytes(archive))
        verification = subprocess.run([str(binary), "verify", str(policy_path), str(archive_path),
                                       base64.b64encode(second_nonce).decode(), str(evaluated_at)],
                                      capture_output=True, text=True, timeout=90)
        write_new(output / "confido-result.json", verification.stdout.encode())
        if verification.stderr:
            write_new(output / "confido-stderr.txt", verification.stderr.encode())
        elapsed = time.monotonic() - started
        if elapsed > 120:
            raise ValueError("live challenge exceeded 120-second collection and verification window")
        result = json.loads(verification.stdout)
        summary = {"run_id": args.run_id,
                   "attestor_source_commit": guest_image["commit"],
                   "attestor_oci_archive_sha256": guest_archive_sha,
                   "attestor_oci_manifest_digest": guest_image["manifest_digest"],
                   "selected_source_lock_commit": attestor_pin(ROOT)["commit"],
                   "confido_main_commit": head, "confido_binary_sha256": sha256(binary.read_bytes()),
                   "reference_commit": reference_commit, "reference_sha256": sha256(reference_bytes),
                   "ima_entries": len(reference["ima_measurements"]),
                   "challenge_seconds": round(elapsed, 3), "status": result.get("status"),
                   "reason": result.get("reason"), "evidence_dir": str(output),
                   "reference_enrollment": "local first snapshot; independent approval absent",
                   "tls_session_binding": "not evaluated"}
        write_new(output / "summary.json", json_bytes(summary))
        print(json.dumps(summary, indent=2, sort_keys=True))
        if verification.returncode or result.get("status") != "verified":
            raise ValueError("Confido did not verify the second fresh challenge")
        with state.locked(ROOT, args.run_id):
            latest = state.load(ROOT, args.run_id)
            if latest.get("phase") != "complete" or latest["resources"].get("cvm_id") != record["resources"]["cvm_id"]:
                raise ValueError("run state changed during attestation")
            latest["attestation"] = summary
            state.save(ROOT, latest)
    finally:
        tunnel.terminate()
        try:
            tunnel.wait(timeout=10)
        except subprocess.TimeoutExpired:
            tunnel.kill()


if __name__ == "__main__":
    main()
