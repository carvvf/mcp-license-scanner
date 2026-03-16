from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TOKEN_RE = re.compile(r"[A-Za-z0-9.+-]+")
UNKNOWN_MARKERS = {"", "NOASSERTION", "NONE", "UNKNOWN", "UNLICENSED", "UNLICENCED", "NULL"}
EXPRESSION_OPERATORS = {"AND", "OR", "WITH"}
INTERESTING_FILE_PREFIXES = ("app/", "opt/", "usr/local/", "/app/", "/opt/", "/usr/local/")
BINARY_EXTENSIONS = {
    ".a",
    ".bin",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".jar",
    ".lib",
    ".node",
    ".o",
    ".obj",
    ".pyd",
    ".pyc",
    ".pyo",
    ".so",
    ".wasm",
}


@dataclass(frozen=True)
class Evidence:
    source: str
    subject: str
    version: str
    license_expr: str


@dataclass(frozen=True)
class Finding:
    severity: str
    finding_type: str
    subject: str
    version: str
    license_expr: str
    sources: str
    reason: str


@dataclass(frozen=True)
class FilterOptions:
    denylist: set[str]
    max_findings: int = 200
    include_os_packages: bool = False
    enforce: bool = False
    enforce_severity: str = "high"


@dataclass(frozen=True)
class FilterResult:
    selected_findings: list[Finding]
    all_findings_count: int
    summary: dict[str, Any]
    evidence_count: int
    should_fail_policy: bool


def source_group(source: str) -> str:
    if source.startswith("sbom-"):
        return "sbom"
    if source.startswith("trivy-license:"):
        return "scanner"
    if source in {
        "python-metadata",
        "npm-license-checker",
        "npm-metadata",
        "rpm-query",
        "dpkg-copyright",
        "apk-query",
    }:
        return "runtime"
    return "other"


def source_scope(source: str) -> str:
    if source in {"python-metadata", "npm-license-checker", "npm-metadata"}:
        return "app"
    if source in {"rpm-query", "dpkg-copyright", "apk-query"}:
        return "os"
    if source.startswith("trivy-license:"):
        trivy_type = source.split(":", 1)[1].lower()
        if any(token in trivy_type for token in ("deb", "rpm", "apk", "alpine", "debian", "ubuntu", "os")):
            return "os"
        if any(token in trivy_type for token in ("python", "pip", "npm", "node", "jar", "go", "cargo", "gem")):
            return "app"
    return "other"


def load_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = handle.read().strip()
        if not raw:
            return None
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def normalize_expr(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text.lower().startswith("see license in"):
        return "UNKNOWN"
    return text


def tokenize(expr: str) -> set[str]:
    tokens = set()
    for raw in TOKEN_RE.findall(expr.upper()):
        if raw in EXPRESSION_OPERATORS:
            continue
        tokens.add(raw)
    return tokens


def parse_denylist(value: str) -> set[str]:
    deny_tokens: set[str] = set()
    for raw_item in value.split(","):
        candidate = raw_item.strip()
        if not candidate:
            continue
        deny_tokens.update(tokenize(candidate))
    return {token.upper() for token in deny_tokens}


def add_evidence(
    container: dict[tuple[str, str], list[Evidence]],
    source: str,
    subject: Any,
    version: Any,
    license_expr: Any,
) -> None:
    subject_value = str(subject or "").strip()
    if not subject_value:
        return
    if subject_value.startswith("/"):
        return
    version_value = str(version or "").strip()
    expr = normalize_expr(license_expr)
    container[(subject_value, version_value)].append(
        Evidence(source=source, subject=subject_value, version=version_value, license_expr=expr)
    )


def collect_spdx(data: Any, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if not isinstance(data, dict):
        return
    for pkg in data.get("packages", []) or []:
        if not isinstance(pkg, dict):
            continue
        spdx_id = str(pkg.get("SPDXID", ""))
        if spdx_id == "SPDXRef-DOCUMENT":
            continue
        license_expr = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        add_evidence(
            evidences,
            source="sbom-spdx",
            subject=pkg.get("name"),
            version=pkg.get("versionInfo"),
            license_expr=license_expr,
        )


def cyclonedx_license_expr(component: dict[str, Any]) -> str:
    values: list[str] = []
    for item in component.get("licenses", []) or []:
        if not isinstance(item, dict):
            continue
        license_obj = item.get("license")
        if isinstance(license_obj, dict):
            value = license_obj.get("id") or license_obj.get("name")
            if value:
                values.append(str(value).strip())
    unique = sorted({value for value in values if value})
    return " OR ".join(unique)


def collect_cyclonedx(data: Any, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if not isinstance(data, dict):
        return
    for component in data.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        add_evidence(
            evidences,
            source="sbom-cyclonedx",
            subject=component.get("name"),
            version=component.get("version"),
            license_expr=cyclonedx_license_expr(component),
        )


def collect_trivy(data: Any, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if not isinstance(data, dict):
        return
    for result in data.get("Results", []) or []:
        if not isinstance(result, dict):
            continue
        result_type = result.get("Type") or result.get("Class") or "unknown"
        source = f"trivy-license:{result_type}"
        for package in result.get("Packages", []) or []:
            if not isinstance(package, dict):
                continue
            licenses = package.get("Licenses")
            if isinstance(licenses, list):
                license_expr = " OR ".join(str(item).strip() for item in licenses if str(item).strip())
            else:
                license_expr = str(licenses or "").strip()
            add_evidence(
                evidences,
                source=source,
                subject=package.get("Name"),
                version=package.get("Version"),
                license_expr=license_expr,
            )


def collect_python(data: Any, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if not isinstance(data, list):
        return
    for item in data:
        if not isinstance(item, dict):
            continue
        license_expr = item.get("license") or item.get("License") or item.get("license_expression")
        classifiers = item.get("license_classifiers")
        if isinstance(classifiers, list):
            classifier_values: list[str] = []
            for value in classifiers:
                text = str(value).strip()
                if not text:
                    continue
                if "::" in text:
                    text = text.split("::")[-1].strip()
                classifier_values.append(text)
            if classifier_values:
                license_expr = " OR ".join(classifier_values)
        elif isinstance(license_expr, str):
            compact = license_expr.strip()
            if len(compact) > 240 or "\n" in compact:
                license_expr = ""
        add_evidence(
            evidences,
            source="python-metadata",
            subject=item.get("name") or item.get("Name"),
            version=item.get("version") or item.get("Version"),
            license_expr=license_expr,
        )


def collect_npm(data: Any, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if isinstance(data, dict):
        if data and all(isinstance(value, dict) for value in data.values()):
            for package_ref, details in data.items():
                if not isinstance(package_ref, str) or "@" not in package_ref:
                    continue
                name, version = package_ref.rsplit("@", 1)
                license_expr = details.get("licenses") if isinstance(details, dict) else ""
                add_evidence(
                    evidences,
                    source="npm-license-checker",
                    subject=name,
                    version=version,
                    license_expr=license_expr,
                )
            return

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            add_evidence(
                evidences,
                source="npm-metadata",
                subject=item.get("name"),
                version=item.get("version"),
                license_expr=item.get("license"),
            )


def collect_os(data: Any, source_name: str, evidences: dict[tuple[str, str], list[Evidence]]) -> None:
    if not isinstance(data, list):
        return
    for item in data:
        if not isinstance(item, dict):
            continue
        add_evidence(
            evidences,
            source=source_name,
            subject=item.get("name") or item.get("package"),
            version=item.get("version"),
            license_expr=item.get("license") or item.get("licenses"),
        )


def collect_scancode_findings(data: Any, denylist: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(data, dict):
        return findings

    for entry in data.get("files", []) or []:
        if not isinstance(entry, dict):
            continue
        path = str(entry.get("path") or "")
        if not path:
            continue

        license_exprs: set[str] = set()
        for key in (
            "detected_license_expression_spdx",
            "declared_license_expression_spdx",
            "license_expression",
            "declared_license_expression",
        ):
            value = normalize_expr(entry.get(key))
            if value:
                license_exprs.add(value)

        for license_item in entry.get("licenses", []) or []:
            if not isinstance(license_item, dict):
                continue
            value = normalize_expr(
                license_item.get("spdx_license_key")
                or license_item.get("key")
                or license_item.get("short_name")
                or license_item.get("name")
            )
            if value:
                license_exprs.add(value)

        for detection in entry.get("license_detections", []) or []:
            if not isinstance(detection, dict):
                continue
            value = normalize_expr(
                detection.get("license_expression_spdx") or detection.get("license_expression")
            )
            if value:
                license_exprs.add(value)

        tokens = set()
        for expression in license_exprs:
            tokens.update(tokenize(expression))

        if tokens.intersection(denylist):
            findings.append(
                Finding(
                    severity="high",
                    finding_type="denylist_match",
                    subject=path,
                    version="",
                    license_expr=" OR ".join(sorted(license_exprs)),
                    sources="scancode",
                    reason="Detected denylisted license in scanned file.",
                )
            )

        non_unknown_tokens = {token for token in tokens if token not in UNKNOWN_MARKERS}
        if len(non_unknown_tokens) > 1:
            findings.append(
                Finding(
                    severity="medium",
                    finding_type="multiple_licenses",
                    subject=path,
                    version="",
                    license_expr=" OR ".join(sorted(license_exprs)),
                    sources="scancode",
                    reason="Multiple license signals detected in one file.",
                )
            )

        path_lower = path.lower()
        extension = Path(path_lower).suffix
        is_binary_path = extension in BINARY_EXTENSIONS
        interesting_path = path.startswith(INTERESTING_FILE_PREFIXES)
        if is_binary_path and interesting_path and not non_unknown_tokens:
            findings.append(
                Finding(
                    severity="medium",
                    finding_type="binary_without_metadata",
                    subject=path,
                    version="",
                    license_expr="UNKNOWN",
                    sources="scancode",
                    reason="Binary file in application/runtime path without license metadata.",
                )
            )

    return findings


def package_findings(
    evidences: dict[tuple[str, str], list[Evidence]],
    denylist: set[str],
    include_os_packages: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    for (subject, version), package_evidences in evidences.items():
        sources = sorted({item.source for item in package_evidences})
        source_groups = {source_group(source) for source in sources}
        source_scopes = {source_scope(source) for source in sources}
        has_confident_source = "runtime" in source_groups or "scanner" in source_groups
        has_app_scope = "app" in source_scopes
        has_os_scope = "os" in source_scopes
        if has_os_scope and not has_app_scope and not include_os_packages:
            continue

        token_sets: list[set[str]] = []
        deny_hit = False

        for item in package_evidences:
            tokens = tokenize(item.license_expr)
            if tokens.intersection(denylist):
                deny_hit = True
            token_sets.append({token for token in tokens if token not in UNKNOWN_MARKERS})

        if deny_hit:
            findings.append(
                Finding(
                    severity="high",
                    finding_type="denylist_match",
                    subject=subject,
                    version=version,
                    license_expr=" | ".join(
                        sorted(
                            {
                                evidence.license_expr
                                for evidence in package_evidences
                                if evidence.license_expr.strip()
                            }
                        )
                    ),
                    sources=", ".join(sources),
                    reason="Package has at least one denylisted license signal.",
                )
            )

        non_empty_token_sets = [token_set for token_set in token_sets if token_set]
        if not non_empty_token_sets and has_confident_source:
            findings.append(
                Finding(
                    severity="medium",
                    finding_type="missing_license",
                    subject=subject,
                    version=version,
                    license_expr="UNKNOWN",
                    sources=", ".join(sources),
                    reason="No reliable license metadata found across all sources.",
                )
            )
            continue

        unique_token_sets = {frozenset(token_set) for token_set in non_empty_token_sets}
        if len(unique_token_sets) > 1 and has_confident_source:
            findings.append(
                Finding(
                    severity="medium",
                    finding_type="source_conflict",
                    subject=subject,
                    version=version,
                    license_expr=" | ".join(
                        sorted(
                            {
                                evidence.license_expr
                                for evidence in package_evidences
                                if evidence.license_expr.strip()
                            }
                        )
                    ),
                    sources=", ".join(sources),
                    reason="Different sources report incompatible license token sets.",
                )
            )

        has_multiple_tokens = any(len(token_set) > 1 for token_set in non_empty_token_sets)
        if has_multiple_tokens and has_confident_source:
            findings.append(
                Finding(
                    severity="medium",
                    finding_type="multiple_licenses",
                    subject=subject,
                    version=version,
                    license_expr=" | ".join(
                        sorted(
                            {
                                evidence.license_expr
                                for evidence in package_evidences
                                if evidence.license_expr.strip()
                            }
                        )
                    ),
                    sources=", ".join(sources),
                    reason="Package appears under multiple licenses and requires human decision.",
                )
            )

    return findings


def deduplicate_findings(items: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str, str]] = set()
    deduped: list[Finding] = []
    for item in items:
        key = (
            item.finding_type,
            item.subject,
            item.version,
            item.license_expr,
            item.sources,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def finding_sort_key(item: Finding) -> tuple[int, str, str, str]:
    severity_weight = {"high": 0, "medium": 1, "low": 2}.get(item.severity, 9)
    return (severity_weight, item.finding_type, item.subject.lower(), item.version.lower())


def build_markdown(findings: list[Finding], evidence_count: int, denylist: set[str]) -> str:
    now_utc = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    lines: list[str] = [
        "# License Review Candidates",
        "",
        f"Generated at: `{now_utc}`",
        f"Evidence records analyzed: `{evidence_count}`",
        f"Findings selected for review: `{len(findings)}`",
        f"Denylist: `{', '.join(sorted(denylist)) if denylist else '(none)'}`",
        "",
    ]

    if not findings:
        lines.append("No concrete review candidates were detected.")
        lines.append("")
        return "\n".join(lines)

    lines.extend(
        [
            "| Severity | Type | Subject | Version | License Signal | Sources | Reason |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in findings:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.severity,
                    item.finding_type,
                    item.subject.replace("|", "\\|"),
                    item.version.replace("|", "\\|"),
                    item.license_expr.replace("|", "\\|") or "-",
                    item.sources.replace("|", "\\|") or "-",
                    item.reason.replace("|", "\\|"),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def evaluate_artifacts(output_dir: Path, options: FilterOptions) -> FilterResult:
    evidences: dict[tuple[str, str], list[Evidence]] = defaultdict(list)

    collect_spdx(load_json(output_dir / "sbom.spdx.json"), evidences)
    collect_cyclonedx(load_json(output_dir / "sbom.cyclonedx.json"), evidences)
    collect_trivy(load_json(output_dir / "trivy-license.json"), evidences)
    collect_python(load_json(output_dir / "python-licenses.json"), evidences)
    collect_npm(load_json(output_dir / "npm-licenses.json"), evidences)
    collect_os(load_json(output_dir / "rpm-licenses.json"), "rpm-query", evidences)
    collect_os(load_json(output_dir / "dpkg-licenses.json"), "dpkg-copyright", evidences)
    collect_os(load_json(output_dir / "apk-licenses.json"), "apk-query", evidences)

    findings = package_findings(
        evidences,
        options.denylist,
        include_os_packages=options.include_os_packages,
    )
    findings.extend(collect_scancode_findings(load_json(output_dir / "scancode.json"), options.denylist))

    deduped = deduplicate_findings(findings)
    deduped.sort(key=finding_sort_key)
    selected = deduped[: max(options.max_findings, 0)]

    summary = {
        "total_findings": len(selected),
        "total_findings_untruncated": len(deduped),
        "high": sum(1 for item in selected if item.severity == "high"),
        "medium": sum(1 for item in selected if item.severity == "medium"),
        "low": sum(1 for item in selected if item.severity == "low"),
        "evidence_records": sum(len(items) for items in evidences.values()),
        "denylist": sorted(options.denylist),
    }

    if options.enforce:
        if options.enforce_severity == "high":
            should_fail_policy = summary["high"] > 0
        else:
            should_fail_policy = summary["total_findings"] > 0
    else:
        should_fail_policy = False

    return FilterResult(
        selected_findings=selected,
        all_findings_count=len(deduped),
        summary=summary,
        evidence_count=summary["evidence_records"],
        should_fail_policy=should_fail_policy,
    )


def write_filter_outputs(output_dir: Path, result: FilterResult) -> None:
    findings_payload = [
        {
            "severity": item.severity,
            "type": item.finding_type,
            "subject": item.subject,
            "version": item.version,
            "license_signal": item.license_expr,
            "sources": item.sources,
            "reason": item.reason,
        }
        for item in result.selected_findings
    ]

    markdown = build_markdown(
        findings=result.selected_findings,
        evidence_count=result.evidence_count,
        denylist=set(result.summary.get("denylist", [])),
    )

    with (output_dir / "review_candidates.json").open("w", encoding="utf-8") as handle:
        json.dump(findings_payload, handle, indent=2)
        handle.write("\n")

    with (output_dir / "review_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(result.summary, handle, indent=2)
        handle.write("\n")

    with (output_dir / "review.md").open("w", encoding="utf-8") as handle:
        handle.write(markdown)


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return asdict(finding)

