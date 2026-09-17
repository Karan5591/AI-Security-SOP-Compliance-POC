"""
Turns (code + retrieved SOP rules) into a structured security assessment
by prompting the LLM and validating its JSON response.
"""
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.llm.client import chat_completion

PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "security_review.txt"

_QUALITATIVE_CONFIDENCE = {"low": 0.3, "medium": 0.6, "high": 0.9}


class SecurityFinding(BaseModel):
    status: str = Field(description="PASS, FAIL, or WARN")
    finding: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    file: str | None = None
    line: int | None = None
    reason: str | None = None
    recommendation: str | None = None
    confidence: float | None = None

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value):
        """LLMs sometimes answer 'High'/'Medium'/'Low' instead of a 0-1 number
        despite the prompt asking for a number - coerce instead of rejecting
        the whole response over one field."""
        if value is None or isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            mapped = _QUALITATIVE_CONFIDENCE.get(value.strip().lower())
            if mapped is not None:
                return mapped
            try:
                return float(value)
            except ValueError:
                return None
        return None

    @field_validator("line", mode="before")
    @classmethod
    def _coerce_line(cls, value):
        """Same tolerance for line numbers occasionally coming back as strings."""
        if value is None or isinstance(value, int):
            return value
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


class SecurityAssessment(BaseModel):
    overall_status: str  # PASS / FAIL / WARN
    findings: list[SecurityFinding]


def _format_rules_block(rules: list[dict]) -> str:
    lines = []
    for r in rules:
        lines.append(
            f"Rule {r['rule_id']} ({r['category']}, severity {r['severity']}):\n"
            f"Requirement: {r['requirement']}\n"
            + (f"Prohibited: {r['prohibited']}\n" if r.get("prohibited") else "")
            + f"Remediation: {r['remediation']}\n"
        )
    return "\n".join(lines)


def _extract_json(raw_text: str) -> dict:
    """LLMs sometimes wrap JSON in prose or code fences - pull out the JSON block."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
    candidate = fenced.group(1) if fenced else raw_text
    brace_match = re.search(r"\{.*\}", candidate, re.DOTALL)
    if brace_match:
        candidate = brace_match.group(0)
    return json.loads(candidate)


def evaluate_code(code: str, technology: str | None, rules: list[dict]) -> SecurityAssessment:
    system_prompt = PROMPT_PATH.read_text()
    rules_block = _format_rules_block(rules)
    user_prompt = (
        f"TECHNOLOGY: {technology or 'unspecified'}\n\n"
        f"CODE:\n{code}\n\n"
        f"SECURITY SOP RULES:\n{rules_block}\n\n"
        "Evaluate the code against ONLY the rules above. "
        "Return a single JSON object with keys 'overall_status' (PASS/FAIL/WARN) "
        "and 'findings' (a list of objects with status, finding, rule_id, severity, "
        "file, line, reason, recommendation, confidence). "
        "If no rule is violated, return overall_status PASS and an empty findings list. "
        "Return ONLY the JSON object, nothing else."
    )

    raw_text = chat_completion(system_prompt, user_prompt)

    try:
        parsed = _extract_json(raw_text)
        return SecurityAssessment.model_validate(parsed)
    except (json.JSONDecodeError, ValidationError) as exc:
        # Surface a WARN rather than crashing the request - the raw LLM
        # output is preserved so it can be inspected/debugged.
        return SecurityAssessment(
            overall_status="WARN",
            findings=[
                SecurityFinding(
                    status="WARN",
                    finding="LLM response could not be parsed as valid JSON",
                    reason=f"{type(exc).__name__}: {exc}. Raw response: {raw_text[:500]}",
                )
            ],
        )
