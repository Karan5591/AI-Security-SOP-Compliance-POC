"""
Tests for app/security/git_history_scanner.py. Builds a real, throwaway git
repo per test (secret committed, then "removed" in a later commit) and
proves history scanning still finds it - the exact gap stdin-based scanning
(app/security/secret_scanner.py) has.
"""
import subprocess
import tempfile
from pathlib import Path

import pytest

from app.security.git_history_scanner import scan_git_repo_history


def _run_git(args, cwd):
    subprocess.run(["git"] + args, cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def repo_with_removed_secret():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "repo"
        repo.mkdir()
        _run_git(["init", "--quiet"], repo)
        _run_git(["config", "user.email", "test@example.com"], repo)
        _run_git(["config", "user.name", "Test"], repo)

        (repo / "config.js").write_text(
            'const LLM_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJyajk1eEtib";\n'
        )
        _run_git(["add", "config.js"], repo)
        _run_git(["commit", "--quiet", "-m", "Add config with API key"], repo)

        (repo / "config.js").write_text("const LLM_API_KEY = process.env.LLM_API_KEY;\n")
        _run_git(["add", "config.js"], repo)
        _run_git(["commit", "--quiet", "-m", "Fix: use env var"], repo)

        yield str(repo)


@pytest.fixture
def clean_repo():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir) / "repo"
        repo.mkdir()
        _run_git(["init", "--quiet"], repo)
        _run_git(["config", "user.email", "test@example.com"], repo)
        _run_git(["config", "user.name", "Test"], repo)
        (repo / "config.js").write_text("const x = process.env.API_KEY;\n")
        _run_git(["add", "config.js"], repo)
        _run_git(["commit", "--quiet", "-m", "clean commit"], repo)
        yield str(repo)


def test_finds_secret_removed_in_a_later_commit(repo_with_removed_secret):
    result = scan_git_repo_history(repo_with_removed_secret)
    assert result["error"] is None
    assert len(result["findings"]) == 1
    assert result["findings"][0]["RuleID"] == "generic-api-key"


def test_current_file_content_no_longer_contains_the_secret(repo_with_removed_secret):
    # sanity check that this really is testing HISTORY, not current content
    current_content = (Path(repo_with_removed_secret) / "config.js").read_text()
    assert "eyJ0eXAi" not in current_content


def test_no_false_positive_on_clean_history(clean_repo):
    result = scan_git_repo_history(clean_repo)
    assert result["error"] is None
    assert result["findings"] == []
