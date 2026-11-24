"""Private Page Blob staging and one conditional REST Gallery publication."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import time

from hashbox.build.remote import RemoteSSH
from hashbox.operation import state
from hashbox.project.config import AzureProfile
from .builder import _workdir
from .cli import AzureCLI, AzureError
from .errors import DemoError, _log, _require
from .resources import _deployment, _json_file


def _staging(root: Path, azure: AzureCLI, record: dict) -> None:
    group = record["groups"]["image"]["name"]
    account = f"hbxd{record['run_id']}"
    blob_name = f"hashbox-demo-{record['run_id']}.vhd"
    tags = {"hashbox_demo_run": record["run_id"], "hashbox_demo_role": "image"}
    _log("Creating private VHD staging storage...")
    response = _deployment(root, azure, record, "image", "staging",
                           "infra/providers/azure/cvm/staging.arm.json",
                           {"storageAccountName": account, "location": record["location"], "resourceTags": tags})
    outputs = response["properties"].get("outputs") or {}
    storage_id = outputs.get("storageAccountId", {}).get("value")
    endpoint = outputs.get("blobEndpoint", {}).get("value")
    _require(isinstance(storage_id, str) and storage_id.lower().endswith(f"/storageaccounts/{account}"),
             "staging storage account ID differs")
    _require(endpoint == f"https://{account}.blob.core.windows.net/", "staging Blob endpoint differs")
    observed = azure.json("storage", "account", "show", "--resource-group", group, "--name", account)
    _require(observed.get("id", "").casefold() == storage_id.casefold(), "staging storage ID readback differs")
    _require(observed.get("allowBlobPublicAccess") is False and observed.get("allowSharedKeyAccess") is True,
             "staging storage access policy differs from the private Gallery-import route")
    container = azure.json("storage", "container-rm", "show", "--resource-group", group,
                           "--storage-account", account, "--name", "vhds")
    _require((container.get("publicAccess") or "None").casefold() == "none", "staging container is public")
    record["resources"].update(storage_account_name=account, storage_account_id=storage_id,
                               blob_name=blob_name, blob_uri=endpoint + "vhds/" + blob_name)
    state.advance(root, record, "staging-created")


def _grant_builder_blob(root: Path, azure: AzureCLI, record: dict) -> None:
    storage_id = record["resources"]["storage_account_id"]
    principal = record["resources"]["builder_principal_id"]
    state.advance(root, record, "blob-role-create-submitted")
    assignment = azure.json(
        "role", "assignment", "create", "--assignee-object-id", principal,
        "--assignee-principal-type", "ServicePrincipal", "--role", "Storage Blob Data Contributor",
        "--scope", storage_id, timeout=180,
    )
    assignment_id = assignment.get("id") if isinstance(assignment, dict) else None
    _require(isinstance(assignment_id, str) and assignment_id.casefold().startswith(
             (storage_id + "/providers/Microsoft.Authorization/roleAssignments/").casefold()),
             "builder Blob role assignment readback differs")
    _require(assignment.get("principalId", "").casefold() == principal.casefold(),
             "builder Blob role principal differs")
    record["resources"]["blob_role_assignment_id"] = assignment_id
    state.advance(root, record, "blob-role-created")


def _stage_blob(root: Path, profile: AzureProfile, record: dict) -> None:
    resources = record["resources"]
    remote = RemoteSSH(resources["builder_public_ip"], profile.ssh_private_key,
                       state.run_path(root, record["run_id"]) / "builder.known_hosts")
    account = resources["storage_account_name"]
    blob = resources["blob_name"]
    signed = f"{_workdir(record)}/dist/secure-boot"
    source = f"{signed}/HashBox-demo-secureboot-x86_64.vhd"
    readback = f"{signed}/readback.vhd"
    _log("Authenticating the builder managed identity for its storage account...")
    remote.run(["az", "login", "--identity", "--allow-no-subscriptions", "--output", "none"], timeout=120)
    for attempt in range(30):
        try:
            remote.run(["az", "storage", "container", "show", "--account-name", account,
                        "--name", "vhds", "--auth-mode", "login", "--output", "none"], timeout=90)
            break
        except Exception:
            if attempt == 29:
                raise DemoError("builder Blob data-plane role did not become effective")
            time.sleep(20)
    _log("Uploading the signed VHD as a new Page Blob from the builder...")
    state.advance(root, record, "blob-upload-submitted")
    upload = (
        f"az storage blob upload --account-name {account} --container-name vhds "
        f"--name {blob} --file {source} --type page --auth-mode login "
        "--overwrite false --output none"
    )
    remote.run_logged("blob-upload", upload, timeout=7200)
    _log("Downloading the staged Blob on the builder for a full SHA-256 readback...")
    download = (
        f"az storage blob download --account-name {account} --container-name vhds "
        f"--name {blob} --file {readback} --auth-mode login --overwrite false --output none"
    )
    remote.run_logged("blob-readback", download, timeout=7200)
    digest = remote.run(["sha256sum", readback], timeout=120).split()[0]
    _require(digest == record["artifacts"]["derived_vhd_sha256"], "staged Blob bytes differ from signed VHD")
    size_text = remote.run(["az", "storage", "blob", "show", "--account-name", account,
                            "--container-name", "vhds", "--name", blob, "--auth-mode", "login",
                            "--query", "properties.contentLength", "--output", "tsv"], timeout=90)
    _require(int(size_text) == record["artifacts"]["derived_vhd_size"], "staged Blob size differs")
    remote.run(["rm", "--", readback], timeout=60)
    state.advance(root, record, "blob-verified")


def _version_request(record: dict, tags: dict[str, str], cert_b64: str) -> dict:
    """Build the exact conditional REST request for this run's version."""
    return {
        "location": record["location"],
        "tags": tags,
        "properties": {
            "publishingProfile": {
                "excludeFromLatest": True, "replicationMode": "Full",
                "targetRegions": [{"name": record["location"], "regionalReplicaCount": 1,
                                   "storageAccountType": "Standard_LRS", "excludeFromLatest": True}],
            },
            "storageProfile": {"osDiskImage": {
                "hostCaching": "ReadOnly",
                "source": {"uri": record["resources"]["blob_uri"],
                           "storageAccountId": record["resources"]["storage_account_id"]},
            }},
            "safetyProfile": {"allowDeletionOfReplicatedLocations": True},
            "securityProfile": {"uefiSettings": {
                "signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
                "additionalSignatures": {"db": [{"type": "x509", "value": [cert_b64]}]},
            }},
        },
    }


def _wait_version(azure: AzureCLI, version_id: str) -> None:
    """Wait for this submitted version without submitting it again."""
    url = f"https://management.azure.com{version_id}?api-version=2025-12-03"
    deadline = time.monotonic() + 90 * 60
    for attempt in range(270):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            observed = azure.json("rest", "--method", "get", "--url", url,
                                  timeout=min(120, max(1, int(remaining))))
        except AzureError as error:
            if "404" not in str(error) or attempt >= 6:
                raise
            time.sleep(min(20, max(0, deadline - time.monotonic())))
            continue
        phase = (observed.get("properties") or {}).get("provisioningState")
        if phase == "Succeeded":
            return
        if phase in {"Failed", "Canceled"}:
            raise DemoError(f"Gallery version provisioning {phase}")
        if attempt % 3 == 0:
            _log(f"Gallery version provisioning: {phase}...")
        time.sleep(min(20, max(0, deadline - time.monotonic())))
    raise DemoError("Gallery version did not finish within 90 minutes")


def _gallery(root: Path, azure: AzureCLI, record: dict, cert_b64: str) -> None:
    group = record["groups"]["image"]["name"]
    run_id = record["run_id"]
    gallery = f"HbxDemo{run_id}"
    definition = "HashBoxDemo"
    version = "1.0.0"
    tags = {"hashbox_demo_run": run_id, "hashbox_demo_role": "image"}
    common = {"galleryName": gallery, "location": record["location"], "resourceTags": tags}
    _log("Creating the run-owned Compute Gallery and image definition...")
    _deployment(root, azure, record, "image", "gallery", "infra/providers/azure/cvm/gallery.arm.json", common)
    _deployment(root, azure, record, "image", "definition", "infra/providers/azure/cvm/gallery-definition.arm.json",
                {**common, "imageDefinitionName": definition})
    image = azure.json("sig", "image-definition", "show", "--resource-group", group,
                       "--gallery-name", gallery, "--gallery-image-definition", definition)
    expected_image_id = (record["groups"]["image"]["id"] +
                         f"/providers/Microsoft.Compute/galleries/{gallery}/images/{definition}")
    _require(image.get("id", "").casefold() == expected_image_id.casefold() and
             (image.get("tags") or {}).get("hashbox_demo_run") == run_id and
             (image.get("tags") or {}).get("hashbox_demo_role") == "image",
             "Gallery definition ID or ownership differs")
    features = {item.get("name"): item.get("value") for item in image.get("features", [])}
    _require(features.get("SecurityType") == "TrustedLaunchAndConfidentialVmSupported",
             "Gallery definition does not support custom UEFI DB and CVM")

    version_id = f"{image['id']}/versions/{version}"
    listed = azure.json("resource", "list", "--resource-group", group, timeout=120)
    _require(not any(item.get("id", "").casefold() == version_id.casefold() for item in listed),
             "exact Gallery version already exists")
    version_tags = {**tags, "artifact_sha256": record["artifacts"]["derived_vhd_sha256"],
                    "uefi_db_sha256": record["artifacts"]["uefi_db_certificate_sha256"]}
    body_path = state.run_path(root, run_id) / "version-1-0-0.request.json"
    _require(not body_path.exists(), "Gallery REST request file already exists")
    _json_file(body_path, _version_request(record, version_tags, cert_b64))
    record["resources"].update(gallery_name=gallery, image_definition_name=definition,
                               gallery_version=version, gallery_version_id=version_id)
    record["gallery_publication"] = {
        "transport": "rest", "api_version": "2025-12-03", "version_id": version_id,
        "request_file": body_path.name, "request_sha256": hashlib.sha256(body_path.read_bytes()).hexdigest(),
        "conditional_header": "If-None-Match=*",
    }
    state.advance(root, record, "gallery-version-put-submitted")
    _log("Publishing one exact Gallery version with conditional REST PUT...")
    url = f"https://management.azure.com{version_id}?api-version=2025-12-03"
    azure.call("rest", "--method", "put", "--url", url,
               "--headers", "If-None-Match=*", "Content-Type=application/json",
               "--body", f"@{body_path}", timeout=300)
    _wait_version(azure, version_id)
    state.advance(root, record, "gallery-version-provisioned")

    observed = azure.json("rest", "--method", "get", "--url", url, timeout=120)
    properties = observed.get("properties") or {}
    _require(observed.get("id", "").casefold() == version_id.casefold() and
             properties.get("provisioningState") == "Succeeded", "Gallery version readback differs")
    observed_tags = observed.get("tags") or {}
    _require(all(observed_tags.get(key) == value for key, value in version_tags.items()),
             "Gallery version ownership or digest tags differ")
    source = ((properties.get("storageProfile") or {}).get("osDiskImage") or {}).get("source") or {}
    _require(source.get("uri") == record["resources"]["blob_uri"] and
             source.get("storageAccountId", "").casefold() ==
             record["resources"]["storage_account_id"].casefold(),
             "Gallery version source Blob identity differs")
    uefi = ((properties.get("securityProfile") or {}).get("uefiSettings") or {})
    if uefi:
        _require("MicrosoftUefiCertificateAuthorityTemplate" in (uefi.get("signatureTemplateNames") or []),
                 "Gallery version UEFI signature template differs")
    signatures = ((uefi.get("additionalSignatures") or {}).get("db") or [])
    values = [value for item in signatures if item.get("type") == "x509"
              for value in item.get("value", [])]
    if values:
        expected = base64.b64decode(cert_b64, validate=True)
        if not any(base64.b64decode(value, validate=True) == expected for value in values):
            record["blocker"] = "The completed Azure Gallery version returned a different UEFI DB certificate."
            state.advance(root, record, "gallery-uefi-blocked")
            raise DemoError(record["blocker"])
    record["gallery_api_certificate_observed"] = bool(values)
    record["gallery_publication"]["readback"] = "certificate-present" if values else "omitted-guest-required"
    state.advance(root, record, "gallery-api-checked")
