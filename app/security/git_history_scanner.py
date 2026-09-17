"""
Git-history secret scanning via Gitleaks' `git` mode - a different workflow
from app/security/secret_scanner.py (which scans a single pasted snippet via
stdin, no history). This scans an entire repository's commit history, so it
catches a secret that was committed and later "removed" in a subsequent
commit - stdin scanning of the current file contents would miss that
entirely, since the secret is gone from the current state but still exists
in an earlier commit.

Takes a repo URL (or local path - git clone accepts both) rather than a code
string, since history scanning is inherently repo-level, not snippet-level.
"""
import json
import subprocess
import tempfile
from pathlib import Path

GITLEAKS_GIT_TIMEOUT_SECONDS = 120
GIT_CLONE_TIMEOUT_SECONDS = 60


def scan_git_repo_history(repo_url_or_path: str) -> dict:
    """Clone the given repo and scan its full commit history for secrets.

    Returns {"findings": [...], "error": None} on success, or
    {"findings": [], "error": "<message>"} if the clone/scan couldn't run -
    never raises.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        clone_path = Path(tmpdir) / "repo"
        report_path = Path(tmpdir) / "gitleaks-git-report.json"

        try:
            clone_result = subprocess.run(
                ["git", "clone", "--quiet", repo_url_or_path, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=GIT_CLONE_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"findings": [], "error": "git clone failed or timed out"}

        if clone_result.returncode != 0:
            return {"findings": [], "error": f"git clone failed: {clone_result.stderr[-500:]}"}

        try:
            subprocess.run(
                [
                    "gitleaks", "git", str(clone_path),
                    "--no-banner",
                    "--report-format", "json",
                    "--report-path", str(report_path),
                    "--exit-code", "0",
                ],
                capture_output=True,
                text=True,
                timeout=GITLEAKS_GIT_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {"findings": [], "error": "gitleaks git scan failed or timed out"}

        if not report_path.exists() or report_path.stat().st_size == 0:
            return {"findings": [], "error": None}  # no findings, not a failure

        try:
            findings = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return {"findings": [], "error": "gitleaks report was not valid JSON"}

        return {"findings": findings or [], "error": None}
