from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from .engine import (
    get_scan_report,
    list_scans,
    scan_image as run_image_scan_engine,
    scan_repo as run_repo_scan_engine,
)
from .models import DEFAULT_DENYLIST, ImageScanRequest, RepoScanRequest

mcp = FastMCP("license-scan")


@mcp.tool()
def scan_image(
    image_ref: str,
    include_os_packages: bool = False,
    enforce_policy: bool = False,
    enforce_severity: Literal["high", "any"] = "high",
    denylist: str = DEFAULT_DENYLIST,
    max_findings: int = 200,
    scancode_mode: Literal["off", "auto", "local", "docker"] = "auto",
    pull_if_missing: bool = True,
    scancode_image: str = "ghcr.io/aboutcode-org/scancode-toolkit:latest",
) -> dict[str, Any]:
    """
    Scan a Docker image licenses and generate high-signal review artifacts.
    """
    request = ImageScanRequest(
        image_ref=image_ref,
        include_os_packages=include_os_packages,
        enforce_policy=enforce_policy,
        enforce_severity=enforce_severity,
        denylist=denylist,
        max_findings=max_findings,
        scancode_mode=scancode_mode,
        pull_if_missing=pull_if_missing,
        scancode_image=scancode_image,
    )
    result = run_image_scan_engine(request=request)
    return {
        "scan_id": result.scan_id,
        "kind": result.kind,
        "target": result.target,
        "output_dir": str(result.output_dir),
        "summary": result.summary,
        "findings": result.findings,
        "policy_failed": result.policy_failed,
    }


@mcp.tool()
def scan_repo(
    repo_path: str = ".",
    include_os_packages: bool = False,
    enforce_policy: bool = False,
    enforce_severity: Literal["high", "any"] = "high",
    denylist: str = DEFAULT_DENYLIST,
    max_findings: int = 200,
    scancode_mode: Literal["off", "auto", "local", "docker"] = "auto",
    trivy_mode: Literal["fs", "rootfs"] = "fs",
    scancode_image: str = "ghcr.io/aboutcode-org/scancode-toolkit:latest",
) -> dict[str, Any]:
    """
    Scan a repository directory licenses and generate high-signal review artifacts.
    """
    request = RepoScanRequest(
        repo_path=repo_path,
        include_os_packages=include_os_packages,
        enforce_policy=enforce_policy,
        enforce_severity=enforce_severity,
        denylist=denylist,
        max_findings=max_findings,
        scancode_mode=scancode_mode,
        trivy_mode=trivy_mode,
        scancode_image=scancode_image,
    )
    result = run_repo_scan_engine(request=request)
    return {
        "scan_id": result.scan_id,
        "kind": result.kind,
        "target": result.target,
        "output_dir": str(result.output_dir),
        "summary": result.summary,
        "findings": result.findings,
        "policy_failed": result.policy_failed,
    }


@mcp.tool()
def get_report(scan_id: str) -> dict[str, Any]:
    """
    Return metadata and report artifacts for a previous scan id.
    """
    return get_scan_report(scan_id=scan_id)


@mcp.tool()
def list_recent_scans(limit: int = 20) -> dict[str, Any]:
    """
    List recent scan metadata entries.
    """
    return {"items": list_scans(limit=limit)}


@mcp.tool()
def health() -> dict[str, Any]:
    """
    Basic health endpoint for MCP registration troubleshooting.
    """
    return {
        "status": "ok",
        "cache_root": str(Path.home() / ".cache" / "license-mcp" / "scans"),
    }


def run_stdio_server() -> None:
    mcp.run()
