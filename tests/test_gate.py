from app.security.evaluator import SecurityFinding
from app.security.gate import build_gate, deduplicate_findings, is_blocking


def finding(severity="High", status="FAIL"):
    return SecurityFinding(status=status, finding="test", rule_id="TEST-001", severity=severity, reason="reason")


def test_high_fail_blocks():
    assert is_blocking(finding("High"))
    assert build_gate([finding("High")])["status"] == "BLOCKED"


def test_low_fail_is_warning():
    gate = build_gate([finding("Low")])
    assert gate["status"] == "PASSED"
    assert gate["warning_count"] == 1


def test_unknown_fail_closed():
    assert is_blocking(finding(None))


def test_duplicate_findings_are_collapsed():
    assert len(deduplicate_findings([finding(), finding()])) == 1
