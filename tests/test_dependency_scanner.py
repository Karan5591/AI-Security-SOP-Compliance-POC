"""
Tests for app/security/dependency_scanner.py.

generate_sbom() is tested for real output - it works fully offline (verified
during development, no vulnerability DB needed).

scan_dependencies_for_cves() is only tested for graceful degradation (never
raises, always returns the {"vulnerabilities": [...], "error": ...} shape) -
whether it actually finds CVEs depends on whether this environment can reach
Trivy's vulnerability DB registry, which varies by network. See that
function's docstring / the README for why this asymmetry exists.
"""
from app.security.dependency_scanner import generate_sbom, scan_dependencies_for_cves


def test_sbom_generation_lists_packages_with_versions():
    files = [
        {
            "filename": "requirements.txt",
            "content": "requests==2.6.0\ndjango==2.0.0\npyyaml==5.1\n",
        }
    ]
    sbom = generate_sbom(files)
    assert sbom is not None
    names_and_versions = {
        (c.get("name"), c.get("version")) for c in sbom.get("components", [])
    }
    assert ("django", "2.0.0") in names_and_versions
    assert ("pyyaml", "5.1") in names_and_versions
    assert ("requests", "2.6.0") in names_and_versions


def test_sbom_generation_handles_empty_manifest():
    files = [{"filename": "requirements.txt", "content": ""}]
    sbom = generate_sbom(files)
    assert sbom is not None  # still produces a valid (near-empty) SBOM, doesn't crash


def test_cve_scan_always_returns_well_formed_result():
    # Whether this finds real CVEs depends on network access to Trivy's DB
    # registry - only the response SHAPE and graceful-failure behavior are
    # guaranteed and tested here.
    files = [{"filename": "requirements.txt", "content": "requests==2.6.0\n"}]
    result = scan_dependencies_for_cves(files)
    assert "vulnerabilities" in result
    assert "error" in result
    assert isinstance(result["vulnerabilities"], list)
    assert result["error"] is None or isinstance(result["error"], str)
