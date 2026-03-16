from __future__ import annotations

import json
import tarfile
from pathlib import Path
from typing import Any

from ..errors import LicenseMcpError
from ..shell import require_command, run_command, write_json


def ensure_docker_available() -> None:
    require_command("docker")
    run_command(["docker", "info"], capture_output=True)


def ensure_tooling_for_repo_mode() -> None:
    require_command("tar")


def write_empty_array(path: Path) -> None:
    write_json(path, [])


def write_empty_object(path: Path) -> None:
    write_json(path, {})


def read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def run_syft(target: str, fmt: str, output_file: Path) -> None:
    if Path(target).exists() and not target.startswith("dir:"):
        target_arg = f"dir:{target}"
    else:
        target_arg = target

    if _can_run_local_syft():
        completed = run_command(["syft", target_arg, "-o", fmt], capture_output=True)
        output_file.write_text(completed.stdout, encoding="utf-8")
        return

    ensure_docker_available()
    if target_arg.startswith("dir:"):
        host_dir = target_arg.removeprefix("dir:")
        completed = run_command(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{host_dir}:/scan:ro",
                "anchore/syft:latest",
                "dir:/scan",
                "-o",
                fmt,
            ],
            capture_output=True,
        )
        output_file.write_text(completed.stdout, encoding="utf-8")
        return

    raise LicenseMcpError("Syft docker fallback currently supports only local directory targets.")


def _can_run_local_syft() -> bool:
    try:
        require_command("syft")
        return True
    except LicenseMcpError:
        return False


def export_container_rootfs(image_ref: str, output_tar: Path, output_dir: Path) -> None:
    ensure_docker_available()
    container = run_command(["docker", "create", image_ref], capture_output=True).stdout.strip()
    if not container:
        raise LicenseMcpError(f"Could not create container for image: {image_ref}")
    try:
        run_command(["docker", "export", container, "-o", str(output_tar)], capture_output=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output_tar) as archive:
            archive.extractall(output_dir)
    finally:
        run_command(["docker", "rm", "-v", container], allow_failure=True, capture_output=True)


def collect_rootfs_summary(rootfs_dir: Path, output_file: Path) -> None:
    import re

    license_name_re = re.compile(r"^(license|licence|copying|notice)(\..+)?$", re.IGNORECASE)
    file_count = 0
    license_like_paths: list[str] = []
    for path in rootfs_dir.rglob("*"):
        if not path.is_file():
            continue
        file_count += 1
        if license_name_re.match(path.name):
            license_like_paths.append(str(path.relative_to(rootfs_dir)))
    license_like_paths.sort()
    write_json(
        output_file,
        {
            "file_count": file_count,
            "license_like_file_count": len(license_like_paths),
            "license_like_files_sample": license_like_paths[:200],
        },
    )
