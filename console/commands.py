"""Fixed allowlist of DefenseClaw actions; executed without a shell."""

from __future__ import annotations

import datetime as dt
import re
import subprocess
from pathlib import Path
from typing import Callable

from console.security import name_ok

CONFIRMATION_WORD = "ENFORCE"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_MAX_OUTPUT = 4000

ACTIONS: dict[str, Callable[[str], list[str]]] = {
    "alert_ack": lambda x: ["alerts", "acknowledge", "--id", x],
    "alert_dismiss": lambda x: ["alerts", "dismiss", "--id", x],
    "mode": lambda x: ["guardrail", "mode", x, "--connector", "claudecode"],
}
for _kind in ("skill", "plugin"):
    for _verb in ("block", "allow", "unblock", "restore"):
        ACTIONS[f"{_kind}_{_verb}"] = (lambda k, v: lambda x: [k, v, x])(_kind, _verb)
for _verb in ("block", "allow", "unblock"):
    ACTIONS[f"tool_{_verb}"] = (lambda v: lambda x: ["tool", v, x])(_verb)


def build_argv(action: str, target: str, confirmation: str = "") -> list[str]:
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action!r}")
    if not name_ok(target):
        raise ValueError(f"invalid name: {target!r}")
    if action == "mode":
        if target not in ("observe", "action"):
            raise ValueError("mode must be observe or action")
        if target == "action" and confirmation != CONFIRMATION_WORD:
            raise ValueError(f"enforcing requires the confirmation {CONFIRMATION_WORD}")
    return ACTIONS[action](target)


def _log(log: Path | None, argv: list[str], code: int) -> None:
    if log is None:
        return
    when = dt.datetime.now().isoformat(timespec="seconds")
    with open(log, "a") as f:
        f.write(f"{when}\t{code}\t{' '.join(argv)}\n")


def run(argv: list[str], cli: str, timeout: int = 30, log: Path | None = None) -> dict:
    try:
        r = subprocess.run([cli, *argv], shell=False, capture_output=True, text=True, timeout=timeout)
        text, code = (r.stdout or "") + (r.stderr or ""), r.returncode
    except subprocess.TimeoutExpired:
        text, code = f"timed out after {timeout} s", -1
    except OSError as exc:
        text, code = f"could not start: {exc}", -2
    _log(log, argv, code)
    return {"ok": code == 0, "output": _ANSI.sub("", text).strip()[:_MAX_OUTPUT], "code": code}
