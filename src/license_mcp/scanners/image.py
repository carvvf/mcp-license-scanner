from __future__ import annotations

import os
import textwrap
from pathlib import Path

from ..errors import LicenseMcpError
from ..models import ImageScanRequest
from ..shell import run_command
from .common import (
    collect_rootfs_summary,
    ensure_docker_available,
    export_container_rootfs,
    run_syft,
    write_empty_array,
)


def run_image_scan(request: ImageScanRequest, output_dir: Path) -> None:
    ensure_docker_available()
    image_ref = request.image_ref.strip()
    if not image_ref:
        raise LicenseMcpError("image_ref is required.")

    _ensure_image(image_ref=image_ref, pull_if_missing=request.pull_if_missing)

    (output_dir / "scan.log").write_text("", encoding="utf-8")
    (output_dir / "image-inspect.json").write_text(
        run_command(["docker", "image", "inspect", image_ref], capture_output=True).stdout,
        encoding="utf-8",
    )
    (output_dir / "image-history.txt").write_text(
        run_command(["docker", "history", "--no-trunc", image_ref], capture_output=True).stdout,
        encoding="utf-8",
    )

    rootfs_tar = output_dir / "image-rootfs.tar"
    rootfs_dir = output_dir / "rootfs"
    export_container_rootfs(image_ref=image_ref, output_tar=rootfs_tar, output_dir=rootfs_dir)
    collect_rootfs_summary(rootfs_dir, output_dir / "rootfs-summary.json")

    run_syft(str(rootfs_dir), "spdx-json", output_dir / "sbom.spdx.json")
    run_syft(str(rootfs_dir), "cyclonedx-json", output_dir / "sbom.cyclonedx.json")
    _run_trivy_rootfs_scan(rootfs_dir=rootfs_dir, output_file=output_dir / "trivy-license.json")
    _run_scancode_image(
        mode=request.scancode_mode,
        rootfs_dir=rootfs_dir,
        output_file=output_dir / "scancode.json",
        scancode_image=request.scancode_image,
    )

    _collect_python_licenses(image_ref=image_ref, output_file=output_dir / "python-licenses.json")
    _collect_npm_licenses(image_ref=image_ref, output_file=output_dir / "npm-licenses.json")
    _collect_rpm_licenses(image_ref=image_ref, output_file=output_dir / "rpm-licenses.json")
    _collect_dpkg_licenses(image_ref=image_ref, output_file=output_dir / "dpkg-licenses.json")
    _collect_apk_licenses(image_ref=image_ref, output_file=output_dir / "apk-licenses.json")


def _ensure_image(image_ref: str, pull_if_missing: bool) -> None:
    inspect = run_command(
        ["docker", "image", "inspect", image_ref],
        capture_output=True,
        allow_failure=True,
    )
    if inspect.returncode == 0:
        return
    if not pull_if_missing:
        raise LicenseMcpError(f"Docker image not found locally: {image_ref}")
    run_command(["docker", "pull", image_ref], capture_output=True)


def _run_trivy_rootfs_scan(rootfs_dir: Path, output_file: Path) -> None:
    cache_dir = output_file.parent / ".trivy-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    run_command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{rootfs_dir}:/scan:ro",
            "-v",
            f"{cache_dir}:/root/.cache/trivy",
            "-v",
            f"{output_file.parent}:/out",
            "aquasec/trivy:0.60.0",
            "rootfs",
            "--scanners",
            "license",
            "--format",
            "json",
            "--timeout",
            "40m",
            "--output",
            f"/out/{output_file.name}",
            "/scan",
        ],
        capture_output=True,
    )


def _run_scancode_image(mode: str, rootfs_dir: Path, output_file: Path, scancode_image: str) -> None:
    targets = [rootfs_dir / "app", rootfs_dir / "opt", rootfs_dir / "usr" / "local"]
    targets = [target for target in targets if target.exists()]
    if not targets:
        write_empty_array(output_file)
        return

    if mode == "off":
        write_empty_array(output_file)
        return

    if mode == "auto":
        mode = "local" if _can_run_scancode_local() else "off"
        if mode == "off":
            write_empty_array(output_file)
            return

    if mode == "local":
        if not _can_run_scancode_local():
            raise LicenseMcpError("ScanCode local mode requested but scancode is not available in PATH.")
        args = ["scancode", "--license", "--summary", "--strip-root", "--json-pp", str(output_file)]
        args.extend(str(item) for item in targets)
        run_command(args, capture_output=True)
        return

    if mode == "docker":
        docker_targets = [f"/scan/{item.relative_to(rootfs_dir)}" for item in targets]
        run = run_command(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{rootfs_dir}:/scan:ro",
                "-v",
                f"{output_file.parent}:/out",
                scancode_image,
                "--license",
                "--summary",
                "--strip-root",
                "--json-pp",
                f"/out/{output_file.name}",
                *docker_targets,
            ],
            capture_output=True,
            allow_failure=True,
        )
        if run.returncode != 0:
            write_empty_array(output_file)
        return

    raise LicenseMcpError(f"Unsupported scancode_mode: {mode}")


def _can_run_scancode_local() -> bool:
    return bool(os.environ.get("PATH")) and run_command(
        ["bash", "-lc", "command -v scancode >/dev/null 2>&1"],
        capture_output=True,
        allow_failure=True,
    ).returncode == 0


def _docker_shell(image_ref: str, script: str, *, allow_failure: bool = False) -> str:
    completed = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", script],
        capture_output=True,
        allow_failure=allow_failure,
    )
    return completed.stdout


def _collect_python_licenses(image_ref: str, output_file: Path) -> None:
    probe = run_command(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image_ref,
            "-lc",
            "command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1",
        ],
        capture_output=True,
        allow_failure=True,
    )
    if probe.returncode != 0:
        write_empty_array(output_file)
        return

    script = textwrap.dedent(
        """
        set -eu
        if command -v pip-licenses >/dev/null 2>&1; then
          pip-licenses --format=json --with-authors --with-urls
          exit 0
        fi
        if command -v python3 >/dev/null 2>&1; then
          PYTHON_BIN="python3"
        else
          PYTHON_BIN="python"
        fi
        "${PYTHON_BIN}" - <<'PY'
        import importlib.metadata as md
        import json

        rows = []
        for dist in md.distributions():
            metadata = dist.metadata
            name = (metadata.get("Name") or "").strip()
            if not name:
                continue
            classifiers = [
                item.replace("License ::", "", 1).strip()
                for item in (metadata.get_all("Classifier") or [])
                if item.startswith("License ::")
            ]
            rows.append(
                {
                    "name": name,
                    "version": str(dist.version or "").strip(),
                    "license": str(metadata.get("License") or "").strip(),
                    "license_classifiers": classifiers,
                    "home_page": str(metadata.get("Home-page") or "").strip(),
                }
            )
        rows.sort(key=lambda item: (item["name"].lower(), item["version"]))
        print(json.dumps(rows, indent=2))
        PY
        """
    ).strip()
    output_file.write_text(_docker_shell(image_ref, script), encoding="utf-8")


def _collect_npm_licenses(image_ref: str, output_file: Path) -> None:
    probe = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", "command -v node >/dev/null 2>&1"],
        capture_output=True,
        allow_failure=True,
    )
    if probe.returncode != 0:
        write_empty_array(output_file)
        return

    script = textwrap.dedent(
        """
        set -eu
        if command -v license-checker >/dev/null 2>&1 && [ -d /app ] && [ -f /app/package.json ]; then
          cd /app
          license-checker --json
          exit 0
        fi
        node - <<'NODE'
        const fs = require("fs");
        const path = require("path");
        const roots = ["/app/node_modules", "/usr/lib/node_modules", "/usr/local/lib/node_modules"];
        const visited = new Set();
        const results = [];

        function parseJson(filePath) {
          try { return JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { return null; }
        }

        function scan(rootPath) {
          if (!fs.existsSync(rootPath)) return;
          const stack = [rootPath];
          while (stack.length) {
            const current = stack.pop();
            let entries = [];
            try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { continue; }
            for (const entry of entries) {
              if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
              const full = path.join(current, entry.name);
              if (entry.name.startsWith("@")) { stack.push(full); continue; }
              const pkgPath = path.join(full, "package.json");
              if (fs.existsSync(pkgPath)) {
                const parsed = parseJson(pkgPath);
                if (parsed && parsed.name) {
                  const key = `${parsed.name}@${parsed.version || ""}`;
                  if (!visited.has(key)) {
                    visited.add(key);
                    results.push({ name: parsed.name, version: parsed.version || "", license: parsed.license || "", path: full });
                  }
                }
              }
              const nested = path.join(full, "node_modules");
              if (fs.existsSync(nested)) stack.push(nested);
            }
          }
        }

        roots.forEach(scan);
        results.sort((a, b) => {
          const n = a.name.localeCompare(b.name);
          if (n !== 0) return n;
          return a.version.localeCompare(b.version);
        });
        console.log(JSON.stringify(results, null, 2));
        NODE
        """
    ).strip()
    output_file.write_text(_docker_shell(image_ref, script), encoding="utf-8")


def _collect_rpm_licenses(image_ref: str, output_file: Path) -> None:
    probe = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", "command -v rpm >/dev/null 2>&1"],
        capture_output=True,
        allow_failure=True,
    )
    if probe.returncode != 0:
        write_empty_array(output_file)
        return
    script = textwrap.dedent(
        """
        set -eu
        rpm -qa --qf '{"name":"%{NAME}","version":"%{VERSION}-%{RELEASE}","license":"%{LICENSE}"}\n' | \
        python3 - <<'PY'
        import json
        import sys
        rows = []
        for line in sys.stdin:
            text = line.strip()
            if not text:
                continue
            try:
                rows.append(json.loads(text))
            except json.JSONDecodeError:
                continue
        rows.sort(key=lambda item: (str(item.get("name", "")).lower(), str(item.get("version", ""))))
        print(json.dumps(rows, indent=2))
        PY
        """
    ).strip()
    run = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", script],
        capture_output=True,
        allow_failure=True,
    )
    if run.returncode != 0:
        write_empty_array(output_file)
        return
    output_file.write_text(run.stdout, encoding="utf-8")


def _collect_dpkg_licenses(image_ref: str, output_file: Path) -> None:
    script = textwrap.dedent(
        """
        set -eu
        if ! command -v dpkg-query >/dev/null 2>&1; then
          exit 10
        fi
        if command -v python3 >/dev/null 2>&1; then
          PYTHON_BIN="python3"
        elif command -v python >/dev/null 2>&1; then
          PYTHON_BIN="python"
        else
          exit 11
        fi
        "${PYTHON_BIN}" - <<'PY'
        import json
        import subprocess
        from pathlib import Path

        output = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"], text=True)
        rows = []
        for line in output.splitlines():
            if not line.strip() or "\\t" not in line:
                continue
            package_name, version = line.split("\\t", 1)
            copyright_path = Path("/usr/share/doc") / package_name / "copyright"
            licenses = []
            if copyright_path.exists():
                seen = set()
                for raw_line in copyright_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if raw_line.startswith("License:"):
                        value = raw_line.split(":", 1)[1].strip()
                        if value and value not in seen:
                            seen.add(value)
                            licenses.append(value)
            rows.append({"name": package_name, "version": version, "license": " OR ".join(licenses) if licenses else ""})
        rows.sort(key=lambda item: (item["name"].lower(), item["version"]))
        print(json.dumps(rows, indent=2))
        PY
        """
    ).strip()
    run = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", script],
        capture_output=True,
        allow_failure=True,
    )
    if run.returncode != 0:
        write_empty_array(output_file)
        return
    output_file.write_text(run.stdout, encoding="utf-8")


def _collect_apk_licenses(image_ref: str, output_file: Path) -> None:
    script = textwrap.dedent(
        """
        set -eu
        if [ ! -f /lib/apk/db/installed ]; then
          exit 12
        fi
        if command -v python3 >/dev/null 2>&1; then
          PYTHON_BIN="python3"
        elif command -v python >/dev/null 2>&1; then
          PYTHON_BIN="python"
        else
          exit 13
        fi
        "${PYTHON_BIN}" - <<'PY'
        import json
        from pathlib import Path

        installed_path = Path("/lib/apk/db/installed")
        rows = []
        package = ""
        version = ""
        license_value = ""
        for line in installed_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line == "":
                if package:
                    rows.append({"name": package, "version": version, "license": license_value})
                package = ""
                version = ""
                license_value = ""
                continue
            if line.startswith("P:"):
                package = line[2:]
            elif line.startswith("V:"):
                version = line[2:]
            elif line.startswith("L:"):
                license_value = line[2:]
        if package:
            rows.append({"name": package, "version": version, "license": license_value})
        rows.sort(key=lambda item: (item["name"].lower(), item["version"]))
        print(json.dumps(rows, indent=2))
        PY
        """
    ).strip()
    run = run_command(
        ["docker", "run", "--rm", "--entrypoint", "sh", image_ref, "-lc", script],
        capture_output=True,
        allow_failure=True,
    )
    if run.returncode != 0:
        write_empty_array(output_file)
        return
    output_file.write_text(run.stdout, encoding="utf-8")
