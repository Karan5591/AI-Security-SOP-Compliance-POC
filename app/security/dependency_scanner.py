"""
Dependency-level scanning via Trivy, operating on a project's manifest files
(requirements.txt, package.json/package-lock.json) rather than a pasted code
snippet - a different threat model (vulnerable third-party libraries) and a
different input shape (a manifest, or a small set of them) from the other
four scanners in this project.

IMPORTANT ASYMMETRY vs. Gitleaks/Semgrep/Bandit/ESLint: those are fully
self-contained (a pinned binary or a local rule file - no network access
needed at scan time). Trivy's vulnerability database is a large, frequently
updated CVE dataset that must be fetched from an external OCI registry
(ghcr.io/aquasecurity or mirror.gcr.io) - it cannot be meaningfully bundled
and pinned the same way. If that registry isn't reachable from wherever this
runs (a real possibility on a restricted network), CVE scanning will fail
with a clear error - see scan_dependencies_for_cves()'s return shape. SBOM
generation (generate_sbom) does NOT need the vulnerability DB and works
fully offline - it was verified working without DB access during development.
CVE scanning (scan_dependencies_for_cves) was written to Trivy's documented,
stable JSON schema but could not be verified against a live DB in the same
sandboxed environment used to build everything else in this project, since
that environment also blocks the DB registry. Test it against your own
network before relying on it.
"""
import json
import subprocess
import tempfile
from pathlib import Path

TRIVY_TIMEOUT_SECONDS = 120


def _write_manifest_files(directory: Path, files: list[dict]) -> None:
    """files: [{"filename": "requirements.txt", "content": "..."}]"""
    for f in files:
        (directory / f["filename"]).write_text(f["content"])


def generate_sbom(files: list[dict]) -> dict | None:
    """Generate a CycloneDX SBOM from the given manifest file(s). Works
    fully offline - no vulnerability DB required. Returns None on failure
    (never raises)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        _write_manifest_files(tmpdir_path, files)
        report_path = tmpdir_path / "sbom.json"

        try:
            subprocess.run(
                [
                    "trivy", "fs",
                    "--scanners", "license",  # avoids touching the vuln DB entirely
                    "--format", "cyclonedx",
                    "--output", str(report_path),
                    "--quiet",
                    str(tmpdir_path),
                ],
                capture_output=True,
                text=True,
                timeout=TRIVY_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

        if not report_path.exists():
            return None

        try:
            return json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return None


def scan_dependencies_for_cves(files: list[dict]) -> dict:
    """Scan the given manifest file(s) for known CVEs. Requires network
    access to Trivy's vulnerability DB registry - see module docstring.

    Returns {"vulnerabilities": [...], "error": None} on success, or
    {"vulnerabilities": [], "error": "<message>"} if the scan couldn't run
    (e.g. DB unreachable) - never raises.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        _write_manifest_files(tmpdir_path, files)
        report_path = tmpdir_path / "trivy-report.json"

        try:
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--scanners", "vuln",
                    "--format", "json",
                    "--output", str(report_path),
                    "--quiet",
                    str(tmpdir_path),
                ],
                capture_output=True,
                text=True,
                timeout=TRIVY_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return {"vulnerabilities": [], "error": "trivy is not installed/available"}
        except subprocess.TimeoutExpired:
            return {"vulnerabilities": [], "error": "trivy scan timed out"}

        if result.returncode != 0 and not report_path.exists():
            stderr_tail = (result.stderr or "")[-500:]
            return {"vulnerabilities": [], "error": f"trivy scan failed: {stderr_tail}"}

        if not report_path.exists():
            return {"vulnerabilities": [], "error": "trivy produced no report"}

        try:
            report = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return {"vulnerabilities": [], "error": "trivy report was not valid JSON"}

        vulnerabilities = []
        for result_entry in report.get("Results", []) or []:
            for vuln in result_entry.get("Vulnerabilities", []) or []:
                vulnerabilities.append(
                    {
                        "id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity"),
                        "title": vuln.get("Title"),
                    }
                )
        return {"vulnerabilities": vulnerabilities, "error": None}
