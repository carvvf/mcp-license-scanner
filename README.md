# license-mcp-scanner

MCP server for realistic license scanning across:

- local repositories (`scan_repo`)
- Docker images (`scan_image`)

The server aggregates multiple evidence sources (SBOM, Trivy, optional ScanCode, package metadata), filters low-signal noise by default, and returns actionable findings for operational decision-making.

## Key Behavior

- Default focus is application/runtime dependencies.
- OS package noise (`dpkg`/`rpm`/`apk`) is excluded unless `include_os_packages=true`.
- Findings are categorized and deduplicated with severity and rationale.
- Reports are persisted under `~/.cache/license-mcp/scans/<scan-id>/`.

Generated artifacts include:

- `sbom.spdx.json`
- `sbom.cyclonedx.json`
- `trivy-license.json`
- `scancode.json` (optional)
- `python-licenses.json`
- `npm-licenses.json`
- `rpm-licenses.json`
- `dpkg-licenses.json`
- `apk-licenses.json`
- `review_candidates.json`
- `review_summary.json`
- `review.md`

## Requirements

For image scans:

- `docker` daemon reachable
- `tar`

For repo scans:

- `syft` local binary, or Docker (for Syft fallback container)
- `trivy` local binary, or Docker (for Trivy fallback container)
- optional: `scancode` (local) or ScanCode docker image
- optional: local `.venv` / `.venv-dev` and `node_modules` for richer app metadata

## Installation

Install once globally (`pipx`):

```bash
cd /home/carlo/mcp-license-scanner
pipx install .
```

Alternative if `pipx` is unavailable (`uv`):

```bash
cd /home/carlo/mcp-license-scanner
uv tool install --force .
```

If reinstalling after updates (`pipx`):

```bash
cd /home/carlo/mcp-license-scanner
pipx reinstall .
```

## Global Codex Configuration

Add one global MCP server entry in `~/.codex/config.toml`:

```toml
[mcp_servers.license_scan]
command = "license-mcp"
args = ["serve"]
```

This keeps repository impact minimal or zero, because config is user-level.

## Quick CLI Smoke Commands

Direct CLI use (outside MCP):

```bash
license-mcp scan-repo --repo-path /path/to/repo
license-mcp scan-image --image-ref ubuntu:24.04
```

Run MCP server manually:

```bash
license-mcp serve
```

## MCP Tools

- `scan_repo`
- `scan_image`
- `get_report`
- `list_recent_scans`
- `health`
