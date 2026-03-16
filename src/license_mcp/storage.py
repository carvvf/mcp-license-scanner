from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import LicenseMcpError
from .models import ScanMetadata


def slugify(value: str) -> str:
    slug = value.replace("/", "_").replace(":", "_").replace("@", "_")
    slug = re.sub(r"[^a-zA-Z0-9._-]", "_", slug)
    return slug or "scan"


def default_root() -> Path:
    return Path.home() / ".cache" / "license-mcp" / "scans"


def create_scan_dir(root: Path, kind: str, target: str) -> tuple[str, Path]:
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan_id = f"{kind}-{slugify(target)}-{timestamp}"
    output_dir = root / scan_id
    output_dir.mkdir(parents=True, exist_ok=False)
    return scan_id, output_dir


def write_metadata(path: Path, metadata: ScanMetadata) -> None:
    payload = asdict(metadata)
    payload["output_dir"] = str(metadata.output_dir)
    with (path / "scan-metadata.json").open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def read_metadata(path: Path) -> dict[str, Any]:
    metadata_path = path / "scan-metadata.json"
    if not metadata_path.exists():
        raise LicenseMcpError(f"Missing metadata file: {metadata_path}")
    with metadata_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def resolve_scan_dir(scan_id: str, root: Path) -> Path:
    output_dir = root / scan_id
    if not output_dir.exists():
        raise LicenseMcpError(f"Scan id not found: {scan_id}")
    return output_dir


def list_scans(root: Path, limit: int = 20) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    rows: list[dict[str, Any]] = []
    for candidate in sorted(root.iterdir(), reverse=True):
        if not candidate.is_dir():
            continue
        metadata_file = candidate / "scan-metadata.json"
        if not metadata_file.exists():
            continue
        try:
            with metadata_file.open("r", encoding="utf-8") as handle:
                rows.append(json.load(handle))
        except json.JSONDecodeError:
            continue
        if len(rows) >= max(limit, 0):
            break
    return rows

