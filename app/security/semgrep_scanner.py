"""
Deterministic static-analysis scanning via Semgrep, using a local, pinned
ruleset (semgrep-rules/security-rules.yaml) rather than pulling registry
configs (p/security-audit, etc.) from semgrep.dev at scan time. This is a
deliberate choice: no runtime dependency on an external registry being
reachable, no risk of rules silently changing between scans, and it stays
consistent with pinning the Gitleaks version for reproducibility.

Runs independently of the LLM/RAG path - pattern-based rule matching, not
semantic reasoning - so it catches command injection, insecure
deserialization, unsafe eval, XSS, and weak crypto patterns regardless of
whether RAG retrieval or the LLM would have caught them.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from app.security.evaluator import SecurityFinding

SEMGREP_RULE_ID_PREFIX = "SEMGREP"
SEMGREP_TIMEOUT_SECONDS = 60
RULES_PATH = Path(__file__).resolve().parents[2] / "semgrep-rules" / "security-rules.yaml"

_SEVERITY_MAP = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

_EXTENSION_BY_TECHNOLOGY = {
    "fastapi": ".py",
    "python": ".py",
    "nodejs": ".js",
    "node": ".js",
    "angular": ".ts",
    "nginx": ".conf",
}


def _infer_extension(technology: str | None, code: str) -> str:
    """Semgrep selects which language rules to apply based on file extension,
    so we need a plausible one. Prefer the declared technology; fall back to
    sniffing the code for obvious syntax markers if it's missing/unhelpful."""
    if technology:
        ext = _EXTENSION_BY_TECHNOLOGY.get(technology.strip().lower())
        if ext:
            return ext
    if "@Component" in code or "@angular" in code:
        return ".ts"
    if "def " in code and "require(" not in code:
        return ".py"
    if "require(" in code or "=>" in code or "function(" in code:
        return ".js"
    return ".txt"  # no matching Semgrep rule targets .txt - scan will just find nothing


def scan_for_static_issues(code: str, technology: str | None = None) -> list[dict]:
    """Run the local Semgrep ruleset against the code, return raw findings
    (empty list if none, or if semgrep isn't available - never raises)."""
    ext = _infer_extension(technology, code)

    with tempfile.TemporaryDirectory() as tmpdir:
        code_path = Path(tmpdir) / f"snippet{ext}"
        code_path.write_text(code)
        report_path = Path(tmpdir) / "semgrep-report.json"

        try:
            subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", str(RULES_PATH),
                    "--json",
                    "--json-output", str(report_path),
                    "--quiet",
                    "--metrics", "off",
                    "--timeout", "20",
                    str(code_path),
                ],
                capture_output=True,
                text=True,
                timeout=SEMGREP_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if not report_path.exists() or report_path.stat().st_size == 0:
            return []

        try:
            report = json.loads(report_path.read_text())
        except json.JSONDecodeError:
            return []

        return report.get("results", [])


def semgrep_finding_to_security_finding(raw: dict) -> SecurityFinding:
    """Convert one raw semgrep result into our SecurityFinding shape.
    check_id comes back path-prefixed (e.g. '....security-rules.python-eval-exec') -
    only the last segment (the rule id we defined) is kept."""
    check_id = raw.get("check_id", "unknown-semgrep-rule")
    short_id = check_id.split(".")[-1]
    extra = raw.get("extra", {})
    message = extra.get("message", "Static analysis finding").strip()
    severity = _SEVERITY_MAP.get(extra.get("severity", "WARNING"), "Medium")

    return SecurityFinding(
        status="FAIL",
        finding=f"{short_id.replace('-', ' ')}",
        rule_id=f"{SEMGREP_RULE_ID_PREFIX}:{short_id}",
        severity=severity,
        file=None,  # the path is our internal temp scratch file, not meaningful to the caller
        line=raw.get("start", {}).get("line"),
        reason=message,
        recommendation=message,
        confidence=0.85,  # deterministic pattern match, though rule scope can still be broad
    )
