"""
Tests for app/security/bandit_scanner.py. Invokes the real bandit binary
against small snippets - fast, local, no network/LLM/DB involved.
"""
from app.security.bandit_scanner import bandit_finding_to_security_finding, scan_python_code


def test_detects_subprocess_shell_true_and_pickle():
    code = (
        "import subprocess\n"
        "import pickle\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
        "def load(data):\n"
        "    return pickle.loads(data)\n"
    )
    hits = scan_python_code(code)
    rule_ids = {h["test_id"] for h in hits}
    assert "B602" in rule_ids  # subprocess shell=True
    assert "B301" in rule_ids  # pickle.loads
    for h in hits:
        finding = bandit_finding_to_security_finding(h)
        assert finding.status == "FAIL"
        assert finding.file is None  # never leaks the internal temp path


def test_filters_out_low_severity_import_notices():
    # importing subprocess/pickle alone (no risky usage) triggers bandit's
    # LOW-severity "blacklist" import notices (B404/B403) - these should be
    # filtered out as noise, not surfaced as findings.
    code = "import subprocess\nimport pickle\n"
    hits = scan_python_code(code)
    assert hits == []


def test_no_false_positive_on_clean_code():
    code = (
        "import subprocess\n"
        "def run(filename):\n"
        "    subprocess.run(['tar', '-czf', 'out.tar.gz', filename], shell=False)\n"
    )
    hits = scan_python_code(code)
    assert hits == []


def test_degrades_gracefully_on_non_python_code():
    # bandit can't parse this - should return [] rather than raising
    js_code = "const x = eval(userInput);\n"
    hits = scan_python_code(js_code)
    assert hits == []
