"""
Offline tests for the JSON-extraction/validation logic in app/security/evaluator.py.
These do NOT hit a real LLM or database - they test the parsing contract only.
"""
import json

from app.security.evaluator import SecurityAssessment, _extract_json, evaluate_code


def test_extract_json_plain():
    raw = '{"overall_status": "PASS", "findings": []}'
    assert _extract_json(raw) == {"overall_status": "PASS", "findings": []}


def test_extract_json_fenced():
    raw = '```json\n{"overall_status": "FAIL", "findings": []}\n```'
    assert _extract_json(raw) == {"overall_status": "FAIL", "findings": []}


def test_extract_json_with_prose_wrapper():
    raw = 'Here is the result:\n{"overall_status": "WARN", "findings": []}\nLet me know if you need more.'
    assert _extract_json(raw) == {"overall_status": "WARN", "findings": []}


def test_evaluate_code_happy_path(monkeypatch):
    fake_response = json.dumps(
        {
            "overall_status": "FAIL",
            "findings": [
                {
                    "status": "FAIL",
                    "finding": "SQL Injection",
                    "rule_id": "SQL-001",
                    "severity": "CRITICAL",
                    "file": "users.py",
                    "line": 12,
                    "reason": "user_id is directly interpolated into SQL",
                    "recommendation": "Use a parameterized query",
                    "confidence": 0.98,
                }
            ],
        }
    )
    monkeypatch.setattr(
        "app.security.evaluator.chat_completion",
        lambda system_prompt, user_prompt: fake_response,
    )

    result = evaluate_code(
        code='query = f"SELECT * FROM users WHERE id = {user_id}"',
        technology="fastapi",
        rules=[
            {
                "rule_id": "SQL-001",
                "category": "SQL Injection",
                "severity": "Critical",
                "requirement": "Use parameterized queries.",
                "prohibited": "String interpolation into SQL.",
                "remediation": "Rewrite using bound parameters.",
            }
        ],
    )

    assert isinstance(result, SecurityAssessment)
    assert result.overall_status == "FAIL"
    assert result.findings[0].rule_id == "SQL-001"


def test_evaluate_code_malformed_json_returns_warn(monkeypatch):
    monkeypatch.setattr(
        "app.security.evaluator.chat_completion",
        lambda system_prompt, user_prompt: "not json at all",
    )
    result = evaluate_code(code="print('hi')", technology=None, rules=[])
    assert result.overall_status == "WARN"
