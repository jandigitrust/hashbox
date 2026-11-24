"""Pinned-host SSH transport for the builder and CVM guest."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import re
import shlex
import subprocess
import time


class RemoteError(RuntimeError):
    pass


class RemoteSSH:
    def __init__(self, public_ip: str, private_key: Path, known_hosts: Path, *, user: str = "hashbox-builder") -> None:
        ipaddress.ip_address(public_ip)
        if not re.fullmatch(r"[a-z][a-z0-9-]*", user):
            raise RemoteError("invalid SSH user")
        if not private_key.is_file() or not known_hosts.is_file():
            raise RemoteError("SSH key or pinned host-key file is missing")
        self.public_ip = public_ip
        self.private_key = private_key
        self.known_hosts = known_hosts
        self.user = user

    def _options(self) -> list[str]:
        return [
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=20",
            "-i", str(self.private_key),
        ]

    def run(self, arguments: list[str], *, timeout: int = 120, heartbeat: str | None = None) -> str:
        command = ["ssh", *self._options(), f"{self.user}@{self.public_ip}", shlex.join(arguments)]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except OSError as error:
            raise RemoteError("could not start remote SSH") from error
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.terminate()
                    raise RemoteError(f"remote SSH timed out during {arguments[0]}")
                try:
                    stdout, stderr = process.communicate(timeout=min(30, remaining))
                    break
                except subprocess.TimeoutExpired:
                    if heartbeat:
                        print(f"{heartbeat}: still running", flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        if process.returncode:
            detail = (stdout + stderr)[-2000:]
            raise RemoteError(f"remote command {arguments[0]} failed ({process.returncode}): {detail}")
        return stdout.strip()

    def run_logged(self, step: str, command: str, *, timeout: int) -> None:
        log = f"/home/{self.user}/{step}.log"
        script = f"{command} > {log} 2>&1; code=$?; tail -n 30 {log}; exit $code"
        self.run(["sh", "-c", script], timeout=timeout, heartbeat=step)

    def upload(self, source: Path, remote_name: str, *, timeout: int = 180) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", remote_name):
            raise RemoteError("invalid remote source name")
        command = [
            "scp", *self._options(), str(source),
            f"{self.user}@{self.public_ip}:/home/{self.user}/{remote_name}",
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RemoteError("remote upload did not complete") from error
        if result.returncode:
            raise RemoteError(f"remote upload failed: {result.stderr[-700:]}")


def pinned_host_key(azure: object, group: str, vm_name: str, public_ip: str, output: Path) -> None:
    """Take the host public key from Azure Run Command, never from SSH keyscan."""
    ipaddress.ip_address(public_ip)
    records = azure.json(
        "vm", "run-command", "invoke", "--resource-group", group,
        "--name", vm_name, "--command-id", "RunShellScript",
        "--scripts", "cloud-init status --wait; cat /etc/ssh/ssh_host_ed25519_key.pub",
        timeout=600,
    )
    values = records.get("value") if isinstance(records, dict) else None
    if not isinstance(values, list) or not values:
        raise RemoteError("Azure VM Run Command returned no host key")
    lines = [line.strip() for value in values for line in str(value.get("message", "")).splitlines()]
    keys = [line for line in lines if re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]+(?: .*)?", line)]
    if len(set(keys)) != 1:
        raise RemoteError("Azure VM Run Command returned an ambiguous host key")
    output.write_text(f"{public_ip} {keys[0]}\n", encoding="ascii")
    output.chmod(0o600)
