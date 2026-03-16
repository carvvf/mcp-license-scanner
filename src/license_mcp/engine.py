from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .filtering import FilterOptions, evaluate_artifacts, finding_to_dict, parse_denylist, write_filter_outputs
from .models import ImageScanRequest, RepoScanRequest, ScanMetadata, ScanResult
from .scanners import run_image_scan, run_repo_scan
from .storage import create_scan_dir, default_root, list_scans as list_scans_storage, resolve_scan_dir, write_metadata


def scan_image(request: ImageScanRequest, scans_root: Path | None = None) -> ScanResult:
    root = scans_root or default_root()
    root.mkdir(parents=True, exist_ok=True)
    scan_id, output_dir = create_scan_dir(root=root, kind="image", target=request.image_ref)
    metadata = ScanMetadata.build(
        scan_id=scan_id,
        kind="image",
        target=request.image_ref,
        output_dir=output_dir,
        request=asdict(request),
    )
    write_metadata(output_dir, metadata)

    run_image_scan(request=request, output_dir=output_dir)
    return _finalize_scan(request=request, output_dir=output_dir, scan_id=scan_id, kind="image", target=request.image_ref)


def scan_repo(request: RepoScanRequest, scans_root: Path | None = None) -> ScanResult:
    root = scans_root or default_root()
    root.mkdir(parents=True, exist_ok=True)
    target = str(Path(request.repo_path).expanduser().resolve())
    scan_id, output_dir = create_scan_dir(root=root, kind="repo", target=target)
    metadata = ScanMetadata.build(
        scan_id=scan_id,
        kind="repo",
        target=target,
        output_dir=output_dir,
        request=asdict(request),
    )
    write_metadata(output_dir, metadata)

    run_repo_scan(request=request, output_dir=output_dir)
    return _finalize_scan(request=request, output_dir=output_dir, scan_id=scan_id, kind="repo", target=target)


def get_scan_report(scan_id: str, scans_root: Path | None = None) -> dict[str, Any]:
    root = scans_root or default_root()
    output_dir = resolve_scan_dir(scan_id=scan_id, root=root)
    metadata_path = output_dir / "scan-metadata.json"
    summary_path = output_dir / "review_summary.json"
    candidates_path = output_dir / "review_candidates.json"
    markdown_path = output_dir / "review.md"

    payload: dict[str, Any] = {
        "scan_id": scan_id,
        "output_dir": str(output_dir),
        "metadata": _load_json(metadata_path),
        "summary": _load_json(summary_path),
        "findings": _load_json(candidates_path),
        "markdown_path": str(markdown_path) if markdown_path.exists() else "",
    }
    return payload


def list_scans(limit: int = 20, scans_root: Path | None = None) -> list[dict[str, Any]]:
    root = scans_root or default_root()
    return list_scans_storage(root=root, limit=limit)


def _finalize_scan(
    request: ImageScanRequest | RepoScanRequest,
    output_dir: Path,
    scan_id: str,
    kind: str,
    target: str,
) -> ScanResult:
    options = FilterOptions(
        denylist=parse_denylist(request.denylist),
        max_findings=request.max_findings,
        include_os_packages=request.include_os_packages,
        enforce=request.enforce_policy,
        enforce_severity=request.enforce_severity,
    )
    filtered = evaluate_artifacts(output_dir=output_dir, options=options)
    write_filter_outputs(output_dir=output_dir, result=filtered)
    return ScanResult(
        scan_id=scan_id,
        kind=kind,  # type: ignore[arg-type]
        target=target,
        output_dir=output_dir,
        summary=filtered.summary,
        findings=[finding_to_dict(item) for item in filtered.selected_findings],
        policy_failed=filtered.should_fail_policy,
    )


def _load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

