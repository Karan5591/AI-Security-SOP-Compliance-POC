from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import require_api_key
from app.security.dependency_scanner import generate_sbom, scan_dependencies_for_cves

router = APIRouter(prefix="/dependency-scan", tags=["dependency-scan"], dependencies=[Depends(require_api_key)])


class ManifestFile(BaseModel):
    filename: str  # e.g. "requirements.txt", "package.json", "package-lock.json"
    content: str


class DependencyScanRequest(BaseModel):
    files: list[ManifestFile]


class DependencyScanResponse(BaseModel):
    sbom: dict | None
    vulnerabilities: list[dict]
    vulnerability_scan_error: str | None


@router.post("", response_model=DependencyScanResponse)
def dependency_scan(request: DependencyScanRequest):
    files = [f.model_dump() for f in request.files]

    sbom = generate_sbom(files)
    cve_result = scan_dependencies_for_cves(files)

    return DependencyScanResponse(
        sbom=sbom,
        vulnerabilities=cve_result["vulnerabilities"],
        vulnerability_scan_error=cve_result["error"],
    )
