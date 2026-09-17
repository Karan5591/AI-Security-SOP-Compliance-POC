"""Batch review endpoint used by CI systems such as Jenkins."""
from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.core.config import get_settings
from app.core.security import require_api_key
from app.db.postgres import record_gate_decision
from app.rag.retriever import retrieve_relevant_rules
from app.security.bandit_scanner import bandit_finding_to_security_finding, scan_python_code
from app.security.eslint_scanner import eslint_finding_to_security_finding, scan_javascript_code
from app.security.evaluator import SecurityAssessment, SecurityFinding, evaluate_code
from app.security.gate import apply_override, build_gate
from app.security.secret_scanner import SECRET_RULE_ID, gitleaks_finding_to_security_finding, scan_for_secrets
from app.security.semgrep_scanner import scan_for_static_issues, semgrep_finding_to_security_finding

router = APIRouter(prefix="/review", tags=["review"], dependencies=[Depends(require_api_key)])


class BatchFile(BaseModel):
    filename: str = Field(min_length=1, max_length=512)
    content: str
    technology: str | None = None

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        normalised = value.replace("\\", "/")
        if normalised.startswith("/") or ".." in normalised.split("/"):
            raise ValueError("filename must be a relative repository path")
        return normalised


class OverrideRequest(BaseModel):
    authority: str = Field(min_length=2, max_length=200)
    reason: str = Field(min_length=10, max_length=2_000)
    approval_ticket: str = Field(min_length=2, max_length=200)
    expires_at: datetime


class BatchReviewRequest(BaseModel):
    files: list[BatchFile] = Field(default_factory=list)
    repository: str | None = Field(default=None, max_length=500)
    commit_sha: str | None = Field(default=None, max_length=200)
    actor: str | None = Field(default=None, max_length=200)
    request_id: str | None = Field(default=None, max_length=100)
    override: OverrideRequest | None = None


class BatchReviewResponse(BaseModel):
    request_id: str
    gate: dict
    files: list[dict]


def _technology_for(filename: str, declared: str | None) -> str | None:
    if declared:
        return declared
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    return {
        "py": "python", "js": "nodejs", "jsx": "nodejs", "ts": "typescript",
        "tsx": "typescript", "conf": "nginx", "nginx": "nginx",
    }.get(suffix)


def _review_one(item: BatchFile) -> tuple[SecurityAssessment, list[str]]:
    technology = _technology_for(item.filename, item.technology)
    rules = retrieve_relevant_rules(item.content, technology, None)
    assessment = evaluate_code(item.content, technology, rules)
    retrieved_ids = [r["rule_id"] for r in rules]
    extra: list[SecurityFinding] = []

    secret_hits = scan_for_secrets(item.content)
    extra.extend(gitleaks_finding_to_security_finding(hit) for hit in secret_hits)
    if secret_hits and SECRET_RULE_ID not in retrieved_ids:
        retrieved_ids.append(SECRET_RULE_ID)
    extra.extend(semgrep_finding_to_security_finding(hit) for hit in scan_for_static_issues(item.content, technology))
    extra.extend(bandit_finding_to_security_finding(hit) for hit in scan_python_code(item.content))
    extra.extend(eslint_finding_to_security_finding(hit) for hit in scan_javascript_code(item.content, technology))

    assessment.findings.extend(extra)
    if any(f.status.upper() == "FAIL" for f in extra):
        assessment.overall_status = "FAIL"
    # Fail closed if an LLM says FAIL but omits the corresponding finding.
    if assessment.overall_status.upper() == "FAIL" and not assessment.findings:
        assessment.findings.append(SecurityFinding(
            status="FAIL",
            finding="Unspecified security gate failure",
            rule_id=None,
            severity=None,
            reason="The reviewer returned FAIL without a structured finding.",
            recommendation="Inspect the review response before allowing the build.",
            confidence=0.0,
        ))
    return assessment, retrieved_ids


@router.post("/batch", response_model=BatchReviewResponse)
def batch_review(request: BatchReviewRequest, x_security_override_token: str | None = Header(default=None)):
    settings = get_settings()
    if len(request.files) > settings.max_batch_files:
        raise HTTPException(status_code=413, detail=f"Batch contains too many files; maximum is {settings.max_batch_files}")
    oversized = [
        item.filename for item in request.files
        if len(item.content.encode("utf-8")) > settings.max_file_bytes
    ]
    if oversized:
        raise HTTPException(status_code=413, detail={"message": "One or more files exceed the size limit", "files": oversized})

    request_id = request.request_id or str(uuid.uuid4())
    file_results: list[dict] = []
    all_findings: list[SecurityFinding] = []
    for item in request.files:
        assessment, retrieved_ids = _review_one(item)
        all_findings.extend(
            finding.model_copy(update={"file": finding.file or item.filename})
            for finding in assessment.findings
        )
        file_results.append({
            "filename": item.filename,
            "technology": _technology_for(item.filename, item.technology),
            "assessment": assessment,
            "retrieved_rule_ids": retrieved_ids,
        })

    gate = build_gate(all_findings, override_requested=request.override is not None)
    override_details = None
    if request.override is not None:
        expires = request.override.expires_at
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            raise HTTPException(status_code=422, detail="Override approval has expired")
        if not settings.security_override_token:
            raise HTTPException(status_code=503, detail="Security overrides are disabled")
        if not x_security_override_token or not secrets.compare_digest(x_security_override_token, settings.security_override_token):
            raise HTTPException(status_code=403, detail="Invalid security override token")
        override_details = request.override.model_dump(mode="json")
        override_details.update({"approved_at": datetime.now(timezone.utc).isoformat(), "request_id": request_id})
        gate = apply_override(gate, override_details)

    audit = {
        "request_id": request_id, "status": gate["status"],
        "repository": request.repository, "commit_sha": request.commit_sha, "actor": request.actor,
        "blocking_count": gate["blocking_count"], "warning_count": gate["warning_count"],
        **(override_details or {}), "gate": gate,
    }
    try:
        record_gate_decision(audit)
    except Exception:
        # Do not allow an un-audited security decision to pass CI.
        raise HTTPException(status_code=503, detail="Could not persist security gate audit record")

    return BatchReviewResponse(request_id=request_id, gate=gate, files=file_results)
