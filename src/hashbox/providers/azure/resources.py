"""Run-owned group readback and bounded ARM deployment mechanics."""

from __future__ import annotations

import json
from pathlib import Path

from hashbox.operation import state
from .cli import AzureCLI
from .errors import _require


def _json_file(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _group_readback(azure: AzureCLI, record: dict, role: str) -> dict:
    group = record["groups"][role]
    observed = azure.group_show(group["name"])
    tags = observed.get("tags") or {}
    _require(observed.get("id", "").casefold() == group["id"].casefold(), f"{role} group ID differs")
    _require(observed.get("location", "").casefold() == record["location"].casefold(), f"{role} group location differs")
    owner = record.get("builder_owner_run_id", record["run_id"]) if role == "builder" else record["run_id"]
    _require(tags.get("hashbox_demo_run") == owner and tags.get("hashbox_demo_role") == role,
             f"{role} group ownership tags differ")
    return observed


def _deployment(root: Path, azure: AzureCLI, record: dict, role: str, label: str,
                template: str, parameters: dict, *, timeout: int = 1800) -> dict:
    directory = state.run_path(root, record["run_id"])
    params_path = directory / f"{label}.parameters.json"
    _json_file(params_path, {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {key: {"value": value} for key, value in parameters.items()},
    })
    state.advance(root, record, f"{label}-submitted")
    response = azure.json(
        "deployment", "group", "create",
        "--resource-group", record["groups"][role]["name"],
        "--name", f"hbx-{label}-{record['run_id']}",
        "--template-file", str(root / template),
        "--parameters", f"@{params_path}",
        timeout=timeout,
    )
    properties = response.get("properties") if isinstance(response, dict) else None
    _require(isinstance(properties, dict) and properties.get("provisioningState") == "Succeeded",
             f"{label} ARM deployment did not succeed")
    return response


def _create_group(root: Path, azure: AzureCLI, record: dict, role: str) -> None:
    _require(role in {"image", "cvm"}, "unsupported demo group role")
    group = record["groups"][role]["name"]
    label = "CVM" if role == "cvm" else "image"
    _require(not azure.group_exists(group), f"{label} group name already exists")
    state.advance(root, record, f"{role}-group-create-submitted")
    azure.group_create(group, record["location"], record["run_id"], role)
    _group_readback(azure, record, role)
    record["groups"][role]["observed"] = True
    state.advance(root, record, f"{role}-group-created")
