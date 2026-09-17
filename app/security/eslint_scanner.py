"""
Deterministic JS/TS/Angular static analysis via ESLint + eslint-plugin-security
+ eslint-plugin-no-unsanitized, using the pinned config/dependencies in
eslint-config/ (installed at Docker build time via `npm ci`, not fetched at
scan time). Catches things Semgrep's JS/TS rules don't: unsafe regex,
non-literal fs paths/requires, timing-attack-prone comparisons, weak random
number generation - on top of some overlap (eval, child_process, innerHTML)
which is fine, agreement between independent tools is a confidence signal,
not redundancy to eliminate.

Runs independently of the LLM/RAG path, same pattern as Gitleaks/Semgrep/Bandit.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from app.security.evaluator import SecurityFinding

ESLINT_RULE_ID_PREFIX = "ESLINT"
ESLINT_TIMEOUT_SECONDS = 45
ESLINT_CONFIG_DIR = Path(__file__).resolve().parents[2] / "eslint-config"
ESLINT_BIN = ESLINT_CONFIG_DIR / "node_modules" / ".bin" / "eslint"
ESLINT_CONFIG_PATH = ESLINT_CONFIG_DIR / "eslint.config.mjs"

# ESLint severity: 2 = error, 1 = warning
_SEVERITY_MAP = {2: "High", 1: "Medium"}

_EXTENSION_BY_TECHNOLOGY = {
    "nodejs": ".js",
    "node": ".js",
    "angular": ".ts",
}


def _infer_extension(technology: str | None, code: str) -> str | None:
    """ESLint only makes sense for JS/TS. Return None (skip scanning) for
    anything else, rather than guessing wrong and getting noisy parse errors."""
    if technology:
        ext = _EXTENSION_BY_TECHNOLOGY.get(technology.strip().lower())
        if ext:
            return ext
        if technology.strip().lower() in {"fastapi", "python", "nginx"}:
            return None  # explicitly not a JS/TS technology, don't guess
    if "@Component" in code or "@angular" in code:
        return ".ts"
    if "require(" in code or "=>" in code or "function(" in code or "const " in code:
        return ".js"
    return None


def scan_javascript_code(code: str, technology: str | None = None) -> list[dict]:
    """Run ESLint against the code. Returns [] for non-JS/TS code, or if
    ESLint isn't available - never raises."""
    ext = _infer_extension(technology, code)
    if ext is None:
        return []

    if not ESLINT_BIN.exists():
        return []

    scratch_root = ESLINT_CONFIG_DIR / ".scan-scratch"
    scratch_root.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(dir=scratch_root) as tmpdir:
        code_path = Path(tmpdir) / f"snippet{ext}"
        code_path.write_text(code)

        try:
            result = subprocess.run(
                [
                    str(ESLINT_BIN),
                    "--no-config-lookup",
                    "-c", str(ESLINT_CONFIG_PATH),
                    "-f", "json",
                    str(code_path),
                ],
                capture_output=True,
                text=True,
                timeout=ESLINT_TIMEOUT_SECONDS,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        messages = []
        for file_result in report:
            for msg in file_result.get("messages", []):
                # ruleId is None for fatal parse errors (e.g. code that isn't
                # actually valid JS/TS) - not a security finding, skip it.
                if msg.get("ruleId"):
                    messages.append(msg)
        return messages


def eslint_finding_to_security_finding(raw: dict) -> SecurityFinding:
    rule_id = raw.get("ruleId", "unknown-eslint-rule")
    short_id = rule_id.split("/")[-1]
    severity = _SEVERITY_MAP.get(raw.get("severity"), "Medium")
    message = raw.get("message", "ESLint security finding")

    return SecurityFinding(
        status="FAIL",
        finding=f"{short_id.replace('-', ' ')}",
        rule_id=f"{ESLINT_RULE_ID_PREFIX}:{short_id}",
        severity=severity,
        file=None,  # internal temp scratch path, not meaningful to the caller
        line=raw.get("line"),
        reason=message,
        recommendation=message,
        confidence=0.85 if raw.get("severity") == 2 else 0.6,
    )
