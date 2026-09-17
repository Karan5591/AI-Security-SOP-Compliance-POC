from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_api_key
from app.rag.retriever import retrieve_relevant_rules
from app.security.bandit_scanner import bandit_finding_to_security_finding, scan_python_code
from app.security.eslint_scanner import eslint_finding_to_security_finding, scan_javascript_code
from app.security.evaluator import SecurityAssessment, evaluate_code
from app.security.secret_scanner import (
    SECRET_RULE_ID,
    gitleaks_finding_to_security_finding,
    scan_for_secrets,
)
from app.security.semgrep_scanner import (
    SEMGREP_RULE_ID_PREFIX,
    scan_for_static_issues,
    semgrep_finding_to_security_finding,
)

router = APIRouter(prefix="/review", tags=["review"], dependencies=[Depends(require_api_key)])


class ReviewRequest(BaseModel):
    code: str
    technology: str | None = None  # e.g. "fastapi", "nodejs", "nginx"
    top_k: int | None = None


class ReviewResponse(BaseModel):
    assessment: SecurityAssessment
    retrieved_rule_ids: list[str]


@router.post("", response_model=ReviewResponse)
def review_code(request: ReviewRequest):
    rules = retrieve_relevant_rules(request.code, request.technology, request.top_k)
    assessment = evaluate_code(request.code, request.technology, rules)
    retrieved_ids = [r["rule_id"] for r in rules]

    # Deterministic secret scan runs independently of RAG retrieval/LLM
    # reasoning - it catches hardcoded secrets even when the retrieved SOP
    # rules don't happen to include SEC-001 for this snippet.
    secret_hits = scan_for_secrets(request.code)
    if secret_hits:
        assessment.findings = assessment.findings + [
            gitleaks_finding_to_security_finding(hit) for hit in secret_hits
        ]
        assessment.overall_status = "FAIL"
        if SECRET_RULE_ID not in retrieved_ids:
            retrieved_ids.append(SECRET_RULE_ID)

    # Deterministic static-analysis scan (command injection, insecure
    # deserialization, eval, XSS, weak crypto) - same independence from
    # RAG/LLM as the secret scan above.
    static_hits = scan_for_static_issues(request.code, request.technology)
    if static_hits:
        static_findings = [semgrep_finding_to_security_finding(hit) for hit in static_hits]
        assessment.findings = assessment.findings + static_findings
        assessment.overall_status = "FAIL"
        for f in static_findings:
            if f.rule_id not in retrieved_ids:
                retrieved_ids.append(f.rule_id)

    # Bandit: Python-specific static analysis. No-op on non-Python code (it
    # simply fails to parse and returns no findings), so safe to run always.
    bandit_hits = scan_python_code(request.code)
    if bandit_hits:
        bandit_findings = [bandit_finding_to_security_finding(hit) for hit in bandit_hits]
        assessment.findings = assessment.findings + bandit_findings
        assessment.overall_status = "FAIL"
        for f in bandit_findings:
            if f.rule_id not in retrieved_ids:
                retrieved_ids.append(f.rule_id)

    # ESLint + security plugins: JS/TS/Angular-specific static analysis.
    # No-op on non-JS/TS code (extension inference returns None and the scan
    # is skipped outright).
    eslint_hits = scan_javascript_code(request.code, request.technology)
    if eslint_hits:
        eslint_findings = [eslint_finding_to_security_finding(hit) for hit in eslint_hits]
        assessment.findings = assessment.findings + eslint_findings
        assessment.overall_status = "FAIL"
        for f in eslint_findings:
            if f.rule_id not in retrieved_ids:
                retrieved_ids.append(f.rule_id)

    return ReviewResponse(
        assessment=assessment,
        retrieved_rule_ids=retrieved_ids,
    )
