"""Shared operator diagnostics and admission failures."""

from __future__ import annotations
class DemoError(RuntimeError):
    pass


def _log(message: str) -> None:
    print(message, flush=True)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DemoError(message)
