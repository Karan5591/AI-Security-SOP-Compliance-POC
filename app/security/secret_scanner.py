"""
Deterministic secret scanning via the Gitleaks CLI (installed in the Docker
image - see Dockerfile). This runs independently of the LLM/RAG path: it's
regex/entropy-based pattern matching, not semantic reasoning, so it reliably
catches hardcoded secrets even when RAG retrieval doesn't surface a relevant
SOP rule for the surrounding code (e.g. an API key with no database context).
"""
import json
import subprocess
import tempfile
from pathlib import Path

from app.security.evaluator import SecurityFinding

SECRET_RULE_ID = "SEC-001"
GITLEAKS_TIMEOUT_SECONDS = 30


def scan_for_secrets(code: str) -> list[dict]:
    """Run gitleaks against the given code via stdin, return raw findings
    (empty list if none, or if gitleaks isn't available - never raises)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "gitleaks-report.json"
        try:
            subprocess.run(
                [
                    "gitleaks",
                    "stdin",
                    "--no-banner",
                    "--report-format", "json",
                    "--report-path", str(report_path),
                    "--exit-code", "0",  # never fail the process on findings - we read the report instead
                ],
                input=code,
                capture_output=True,
                text=True,
                timeout=GITLEAKS_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # gitleaks not installed, or scan took too long - degrade gracefully,
            # the LLM/RAG path still runs independently of this.
            return []

        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        try:
            findings = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []

        return findings or []


def gitleaks_finding_to_security_finding(raw: dict) -> SecurityFinding:
    """Convert one raw gitleaks finding into our SecurityFinding shape,
    mapped to SEC-001 (the hardcoded-secrets SOP rule)."""
    rule_id = raw.get("RuleID", "unknown-secret-pattern")
    return SecurityFinding(
        status="FAIL",
        finding=f"Hardcoded secret detected ({rule_id})",
        rule_id=SECRET_RULE_ID,
        severity="Critical",
        file=raw.get("File") or None,
        line=raw.get("StartLine"),
        reason=(
            f"Gitleaks matched pattern '{rule_id}': {raw.get('Description', '')} "
            f"(entropy={raw.get('Entropy')})"
        ),
        recommendation=(
            "Move the secret to an environment variable or secrets manager, "
            "remove it from source control history, and rotate the exposed credential."
        ),
        confidence=1.0,  # deterministic pattern match, not an LLM guess
    )
