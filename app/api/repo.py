from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_api_key
from app.security.git_history_scanner import scan_git_repo_history

router = APIRouter(prefix="/repo-scan", tags=["repo-scan"], dependencies=[Depends(require_api_key)])


class RepoScanRequest(BaseModel):
    repo_url: str  # a git URL, or a local path reachable from inside the container


class RepoScanResponse(BaseModel):
    findings: list[dict]
    error: str | None


@router.post("", response_model=RepoScanResponse)
def repo_scan(request: RepoScanRequest):
    result = scan_git_repo_history(request.repo_url)
    return RepoScanResponse(findings=result["findings"], error=result["error"])
