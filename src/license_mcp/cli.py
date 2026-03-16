from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .engine import get_scan_report, scan_image, scan_repo
from .errors import LicenseMcpError
from .mcp_server import run_stdio_server
from .models import DEFAULT_DENYLIST, ImageScanRequest, RepoScanRequest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="License MCP scanner.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run MCP server over stdio.")
    serve.set_defaults(handler=cmd_serve)

    image = subparsers.add_parser("scan-image", help="Run image scan without MCP.")
    image.add_argument("--image-ref", required=True)
    image.add_argument("--include-os-packages", action="store_true")
    image.add_argument("--enforce-policy", action="store_true")
    image.add_argument("--enforce-severity", choices=["high", "any"], default="high")
    image.add_argument("--denylist", default=DEFAULT_DENYLIST)
    image.add_argument("--max-findings", type=int, default=200)
    image.add_argument("--scancode-mode", choices=["off", "auto", "local", "docker"], default="auto")
    image.add_argument("--pull-if-missing", action=argparse.BooleanOptionalAction, default=True)
    image.set_defaults(handler=cmd_scan_image)

    repo = subparsers.add_parser("scan-repo", help="Run repo scan without MCP.")
    repo.add_argument("--repo-path", default=".")
    repo.add_argument("--include-os-packages", action="store_true")
    repo.add_argument("--enforce-policy", action="store_true")
    repo.add_argument("--enforce-severity", choices=["high", "any"], default="high")
    repo.add_argument("--denylist", default=DEFAULT_DENYLIST)
    repo.add_argument("--max-findings", type=int, default=200)
    repo.add_argument("--scancode-mode", choices=["off", "auto", "local", "docker"], default="auto")
    repo.add_argument("--trivy-mode", choices=["fs", "rootfs"], default="fs")
    repo.set_defaults(handler=cmd_scan_repo)

    report = subparsers.add_parser("get-report", help="Print report payload for a scan id.")
    report.add_argument("--scan-id", required=True)
    report.set_defaults(handler=cmd_get_report)

    return parser


def cmd_serve(_args: argparse.Namespace) -> int:
    run_stdio_server()
    return 0


def cmd_scan_image(args: argparse.Namespace) -> int:
    request = ImageScanRequest(
        image_ref=args.image_ref,
        include_os_packages=args.include_os_packages,
        enforce_policy=args.enforce_policy,
        enforce_severity=args.enforce_severity,
        denylist=args.denylist,
        max_findings=args.max_findings,
        scancode_mode=args.scancode_mode,
        pull_if_missing=args.pull_if_missing,
    )
    result = scan_image(request=request)
    print(json.dumps(asdict(result), indent=2, default=str))
    return 0 if not result.policy_failed else 4


def cmd_scan_repo(args: argparse.Namespace) -> int:
    request = RepoScanRequest(
        repo_path=args.repo_path,
        include_os_packages=args.include_os_packages,
        enforce_policy=args.enforce_policy,
        enforce_severity=args.enforce_severity,
        denylist=args.denylist,
        max_findings=args.max_findings,
        scancode_mode=args.scancode_mode,
        trivy_mode=args.trivy_mode,
    )
    result = scan_repo(request=request)
    print(json.dumps(asdict(result), indent=2, default=str))
    return 0 if not result.policy_failed else 4


def cmd_get_report(args: argparse.Namespace) -> int:
    report = get_scan_report(scan_id=args.scan_id)
    print(json.dumps(report, indent=2))
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        rc = args.handler(args)
    except LicenseMcpError as exc:
        print(f"[license-mcp] {exc}")
        raise SystemExit(2) from exc
    raise SystemExit(rc)
