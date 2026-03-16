from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


DEFAULT_DENYLIST = (
    "AGPL-1.0,AGPL-3.0,AGPL-3.0-ONLY,AGPL-3.0-OR-LATER,"
    "GPL-1.0,GPL-2.0,GPL-3.0,GPL-3.0-ONLY,GPL-3.0-OR-LATER,"
    "LGPL-3.0,LGPL-3.0-ONLY,LGPL-3.0-OR-LATER,SSPL-1.0,BUSL-1.1"
)


ScanKind = Literal["image", "repo"]
EnforceSeverity = Literal["high", "any"]
ScanCodeMode = Literal["off", "auto", "local", "docker"]


@dataclass(frozen=True)
class ScanRequestBase:
    include_os_packages: bool = False
    enforce_policy: bool = False
    enforce_severity: EnforceSeverity = "high"
    denylist: str = DEFAULT_DENYLIST
    max_findings: int = 200
    scancode_mode: ScanCodeMode = "auto"


@dataclass(frozen=True)
class ImageScanRequest(ScanRequestBase):
    image_ref: str = ""
    pull_if_missing: bool = True
    scancode_image: str = "ghcr.io/aboutcode-org/scancode-toolkit:latest"


@dataclass(frozen=True)
class RepoScanRequest(ScanRequestBase):
    repo_path: str = "."
    trivy_mode: Literal["fs", "rootfs"] = "fs"
    scancode_image: str = "ghcr.io/aboutcode-org/scancode-toolkit:latest"


@dataclass(frozen=True)
class ScanMetadata:
    scan_id: str
    kind: ScanKind
    target: str
    output_dir: Path
    created_at_utc: str
    request: dict[str, Any]

    @staticmethod
    def build(scan_id: str, kind: ScanKind, target: str, output_dir: Path, request: dict[str, Any]) -> "ScanMetadata":
        now_utc = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        return ScanMetadata(
            scan_id=scan_id,
            kind=kind,
            target=target,
            output_dir=output_dir,
            created_at_utc=now_utc,
            request=request,
        )


@dataclass
class ScanResult:
    scan_id: str
    kind: ScanKind
    target: str
    output_dir: Path
    summary: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    policy_failed: bool = False

