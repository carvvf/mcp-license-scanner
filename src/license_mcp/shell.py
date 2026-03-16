from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .errors import LicenseMcpError


def require_command(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise LicenseMcpError(f"Required command not found: {name}")
    return path


def run_command(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture_output: bool = True,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=capture_output,
        check=False,
    )
    if completed.returncode != 0 and not allow_failure:
        stderr = (completed.stderr or "").strip()
        stdout = (completed.stdout or "").strip()
        details = stderr or stdout or "No command output."
        raise LicenseMcpError(
            f"Command failed (exit {completed.returncode}): {' '.join(args)}\n{details}"
        )
    return completed


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")

