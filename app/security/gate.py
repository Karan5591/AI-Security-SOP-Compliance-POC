"""Policy and audit helpers for turning review findings into a CI decision."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from app.core.config import get_settings
from app.security.evaluator import SecurityFinding


def _normalise_severity(value: str | None) -> str:
    return (value or "UNKNOWN").strip().upper()


def is_blocking(finding: SecurityFinding) -> bool:
    """Fail closed for FAIL findings with an unknown severity."""
    if finding.status.upper() != "FAIL":
        return False
    severity = _normalise_severity(finding.severity)
    configured = {
        _normalise_severity(item)
        for item in get_settings().blocking_severities.split(",")
        if item.strip()
    }
    # A missing severity must never create a quiet path around enforcement.
    return severity == "UNKNOWN" or severity in configured


def deduplicate_findings(findings: Iterable[SecurityFinding]) -> list[SecurityFinding]:
    """Collapse repeated results from overlapping deterministic scanners."""
    result: list[SecurityFinding] = []
    seen: set[tuple] = set()
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.finding, finding.reason)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def build_gate(findings: Iterable[SecurityFinding], override_requested: bool = False) -> dict:
    """Return a serialisable gate decision before any override is applied."""
    finding_list = deduplicate_findings(findings)
    blocking = [f for f in finding_list if is_blocking(f)]
    warnings = [f for f in finding_list if f not in blocking]
    return {
        "status": "OVERRIDE_REQUIRED" if override_requested and blocking else ("BLOCKED" if blocking else "PASSED"),
        "blocking_findings": blocking,
        "warnings": warnings,
        "blocking_count": len(blocking),
        "warning_count": len(warnings),
        "evaluated_at": datetime.now(timezone.utc),
    }


def apply_override(gate: dict, override: dict | None) -> dict:
    """Mark a blocked gate as overridden after the API validates approval."""
    if not gate["blocking_findings"] or not override:
        return gate
    return {**gate, "status": "OVERRIDDEN", "override": override}
