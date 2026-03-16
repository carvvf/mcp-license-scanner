from __future__ import annotations

import shutil
import textwrap
from pathlib import Path

from ..errors import LicenseMcpError
from ..models import RepoScanRequest
from ..shell import require_command, run_command
from .common import run_syft, write_empty_array


def run_repo_scan(request: RepoScanRequest, output_dir: Path) -> None:
    repo_path = Path(request.repo_path).expanduser().resolve()
    if not repo_path.exists() or not repo_path.is_dir():
        raise LicenseMcpError(f"Repository path not found or not a directory: {repo_path}")

    run_syft(str(repo_path), "spdx-json", output_dir / "sbom.spdx.json")
    run_syft(str(repo_path), "cyclonedx-json", output_dir / "sbom.cyclonedx.json")
    _run_trivy_fs_scan(
        repo_path=repo_path,
        output_file=output_dir / "trivy-license.json",
        mode=request.trivy_mode,
    )
    _run_scancode_repo(
        repo_path=repo_path,
        mode=request.scancode_mode,
        output_file=output_dir / "scancode.json",
        scancode_image=request.scancode_image,
    )

    _collect_python_licenses_from_repo(repo_path=repo_path, output_file=output_dir / "python-licenses.json")
    _collect_npm_licenses_from_repo(repo_path=repo_path, output_file=output_dir / "npm-licenses.json")
    write_empty_array(output_dir / "rpm-licenses.json")
    write_empty_array(output_dir / "dpkg-licenses.json")
    write_empty_array(output_dir / "apk-licenses.json")


def _run_trivy_fs_scan(repo_path: Path, output_file: Path, mode: str) -> None:
    cache_dir = output_file.parent / ".trivy-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    trivy_bin = shutil.which("trivy")
    if trivy_bin:
        run_command(
            [
                trivy_bin,
                mode,
                "--scanners",
                "license",
                "--format",
                "json",
                "--timeout",
                "40m",
                "--output",
                str(output_file),
                str(repo_path),
            ],
            capture_output=True,
        )
        return

    require_command("docker")
    run_command(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repo_path}:/scan:ro",
            "-v",
            f"{cache_dir}:/root/.cache/trivy",
            "-v",
            f"{output_file.parent}:/out",
            "aquasec/trivy:0.60.0",
            mode,
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


def _run_scancode_repo(repo_path: Path, mode: str, output_file: Path, scancode_image: str) -> None:
    targets = _repo_scancode_targets(repo_path)
    if mode == "off":
        write_empty_array(output_file)
        return
    if mode == "auto":
        mode = "local" if shutil.which("scancode") else "off"
        if mode == "off":
            write_empty_array(output_file)
            return

    if mode == "local":
        if not shutil.which("scancode"):
            raise LicenseMcpError("ScanCode local mode requested but scancode is not available in PATH.")
        run_command(
            [
                "scancode",
                "--license",
                "--summary",
                "--strip-root",
                "--json-pp",
                str(output_file),
                *[str(target) for target in targets],
            ],
            capture_output=True,
        )
        return

    if mode == "docker":
        docker_targets = [f"/scan/{target.relative_to(repo_path)}" for target in targets]
        run = run_command(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{repo_path}:/scan:ro",
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


def _repo_scancode_targets(repo_path: Path) -> list[Path]:
    candidate_names = ("app", "src", "packages", "services", "libs")
    targets = [repo_path / name for name in candidate_names if (repo_path / name).exists()]
    if targets:
        return targets
    return [repo_path]


def _collect_python_licenses_from_repo(repo_path: Path, output_file: Path) -> None:
    candidates = [
        repo_path / ".venv" / "bin" / "python",
        repo_path / ".venv-dev" / "bin" / "python",
        repo_path / ".venv" / "bin" / "python3",
        repo_path / ".venv-dev" / "bin" / "python3",
    ]
    python_bin = next((candidate for candidate in candidates if candidate.exists()), None)
    if not python_bin:
        write_empty_array(output_file)
        return

    script = textwrap.dedent(
        """
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
        """
    ).strip()

    completed = run_command([str(python_bin), "-c", script], capture_output=True)
    output_file.write_text(completed.stdout, encoding="utf-8")


def _collect_npm_licenses_from_repo(repo_path: Path, output_file: Path) -> None:
    if not shutil.which("node"):
        write_empty_array(output_file)
        return
    if not (repo_path / "package.json").exists():
        write_empty_array(output_file)
        return

    script = textwrap.dedent(
        """
        const fs = require("fs");
        const path = require("path");
        const repoRoot = process.argv[1];
        const roots = [path.join(repoRoot, "node_modules")];
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
                    results.push({
                      name: parsed.name,
                      version: parsed.version || "",
                      license: parsed.license || "",
                      path: full,
                    });
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
        """
    ).strip()
    completed = run_command(
        ["node", "-e", script, str(repo_path)],
        cwd=repo_path,
        capture_output=True,
        allow_failure=True,
    )
    if completed.returncode != 0:
        write_empty_array(output_file)
        return
    output_file.write_text(completed.stdout, encoding="utf-8")

