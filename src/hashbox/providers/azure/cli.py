"""Narrow Azure CLI boundary with explicit subscription and bounded calls."""

from __future__ import annotations

import json
import subprocess
from typing import Any


class AzureError(RuntimeError):
    pass


def power_codes(view: dict) -> set[str]:
    details = view.get("instanceView") or view
    return {item.get("code", "") for item in details.get("statuses", [])}


class AzureCLI:
    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id

    def call(self, *arguments: str, timeout: int = 120) -> str:
        command = ["az", *arguments, "--subscription", self.subscription_id, "--only-show-errors", "--output", "json"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AzureError(f"Azure command {arguments[:3]} did not complete: {type(error).__name__}") from error
        if result.returncode:
            # Azure CLI does not receive secrets on the command line in this flow.
            detail = result.stderr.strip().splitlines()[-1:] or ["no detail"]
            raise AzureError(f"Azure command {arguments[:3]} failed ({result.returncode}): {detail[0][:600]}")
        return result.stdout

    def json(self, *arguments: str, timeout: int = 120) -> Any:
        payload = self.call(*arguments, timeout=timeout)
        try:
            return json.loads(payload)
        except json.JSONDecodeError as error:
            raise AzureError(f"Azure command {arguments[:3]} returned invalid JSON") from error

    def group_exists(self, name: str) -> bool:
        value = self.json("group", "exists", "--name", name)
        if not isinstance(value, bool):
            raise AzureError("Azure group existence readback was not boolean")
        return value

    def group_show(self, name: str) -> dict:
        value = self.json("group", "show", "--name", name)
        if not isinstance(value, dict):
            raise AzureError("Azure group readback was not an object")
        return value

    def group_create(self, name: str, location: str, run_id: str, role: str) -> dict:
        value = self.json(
            "group", "create", "--name", name, "--location", location,
            "--tags", f"hashbox_demo_run={run_id}", f"hashbox_demo_role={role}",
            timeout=180,
        )
        if not isinstance(value, dict):
            raise AzureError("Azure group creation had no object readback")
        return value

    def group_delete(self, name: str) -> None:
        self.call("group", "delete", "--name", name, "--yes", "--no-wait", timeout=120)

    def group_wait_deleted(self, name: str) -> None:
        self.call("group", "wait", "--name", name, "--deleted", "--interval", "15", "--timeout", "1800", timeout=1860)
