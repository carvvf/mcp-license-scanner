from __future__ import annotations

import json
from pathlib import Path

from license_mcp.filtering import FilterOptions, evaluate_artifacts, parse_denylist


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_filters_os_only_packages_by_default(tmp_path: Path) -> None:
    _write(
        tmp_path / "trivy-license.json",
        {
            "Results": [
                {
                    "Type": "deb",
                    "Packages": [{"Name": "zlib1g", "Version": "1.2.13", "Licenses": ["Zlib"]}],
                }
            ]
        },
    )

    result = evaluate_artifacts(
        output_dir=tmp_path,
        options=FilterOptions(denylist=parse_denylist("GPL-3.0"), include_os_packages=False),
    )
    assert result.summary["total_findings"] == 0


def test_detects_denylist_match_from_package_sources(tmp_path: Path) -> None:
    _write(
        tmp_path / "trivy-license.json",
        {
            "Results": [
                {
                    "Type": "python-pkg",
                    "Packages": [{"Name": "foo", "Version": "1.0.0", "Licenses": ["GPL-3.0"]}],
                }
            ]
        },
    )

    result = evaluate_artifacts(
        output_dir=tmp_path,
        options=FilterOptions(denylist=parse_denylist("GPL-3.0"), include_os_packages=False),
    )
    assert result.summary["high"] >= 1
    assert any(item.finding_type == "denylist_match" for item in result.selected_findings)


def test_policy_failure_threshold_high(tmp_path: Path) -> None:
    _write(
        tmp_path / "trivy-license.json",
        {
            "Results": [
                {
                    "Type": "python-pkg",
                    "Packages": [{"Name": "bar", "Version": "2.0.0", "Licenses": ["MIT OR Apache-2.0"]}],
                }
            ]
        },
    )
    result = evaluate_artifacts(
        output_dir=tmp_path,
        options=FilterOptions(
            denylist=parse_denylist("GPL-3.0"),
            include_os_packages=False,
            enforce=True,
            enforce_severity="high",
        ),
    )
    assert result.should_fail_policy is False

