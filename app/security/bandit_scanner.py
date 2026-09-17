"""
Deterministic Python-specific static analysis via Bandit. Complements
Semgrep rather than duplicating it: Bandit only parses valid Python (it's
AST-based), so it's a no-op on JS/TS/Angular code, and it catches a few
Python-idiomatic things our Semgrep ruleset doesn't (e.g. unsafe yaml.load
severity nuance, weak-hash detection tuned for Python's hashlib usage).

Runs independently of the LLM/RAG path, same pattern as Gitleaks/Semgrep.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from app.security.evaluator import SecurityFinding

BANDIT_RULE_ID_PREFIX = "BANDIT"
BANDIT_TIMEOUT_SECONDS = 30

# Bandit's plain "you imported a risky module" notices (B403, B404, etc.) are
# LOW severity and not actionable on their own - only surface MEDIUM/HIGH
# findings, which are about actual usage patterns, not imports.
_MIN_SEVERITY = {"LOW", "MEDIUM", "HIGH"}
_SURFACE_SEVERITIES = {"MEDIUM", "HIGH"}
_SEVERITY_MAP = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


def scan_python_code(code: str) -> list[dict]:
    """Run bandit against the code. Returns [] for non-Python code (bandit
    can't parse it, degrades to no findings) or if bandit isn't available -
    never raises."""
    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = Path(tmpdir) / "snippet.py"
        code_path.write_text(code)
        report_path = Path(tmpdir) / "bandit-report.json"

        try:
            subprocess.run(
                ["bandit", "-f", "json", "-o", str(report_path), str(code_path)],
                capture_output=True,
                text=True,
                timeout=BANDIT_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        try:
            report = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []

        results = report.get("results", [])
        return [
            r for r in results
            if r.get("issue_severity") in _SURFACE_SEVERITIES
            and r.get("issue_confidence") in _SURFACE_SEVERITIES
        ]


def bandit_finding_to_security_finding(raw: dict) -> SecurityFinding:
    test_id = raw.get("test_id", "UNKNOWN")
    test_name = raw.get("test_name", "finding")
    severity = _SEVERITY_MAP.get(raw.get("issue_severity"), "Medium")

    return SecurityFinding(
        status="FAIL",
        finding=f"{test_id}: {test_name.replace('_', ' ')}",
        rule_id=f"{BANDIT_RULE_ID_PREFIX}:{test_id}",
        severity=severity,
        file=None,  # internal temp scratch path, not meaningful to the caller
        line=raw.get("line_number"),
        reason=raw.get("issue_text", "Bandit static-analysis finding"),
        recommendation=raw.get("issue_text", "Review this finding against the Bandit documentation."),
        confidence=0.85 if raw.get("issue_confidence") == "HIGH" else 0.6,
    )
