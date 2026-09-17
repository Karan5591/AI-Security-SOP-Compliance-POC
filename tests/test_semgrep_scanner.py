"""
Tests for app/security/semgrep_scanner.py. These actually invoke the real
semgrep binary against small snippets (semgrep is a local, fast, pinned
dependency - no network/LLM/DB involved), so they double as a regression
check on the ruleset itself.
"""
from app.security.semgrep_scanner import (
    scan_for_static_issues,
    semgrep_finding_to_security_finding,
)


def test_detects_command_injection():
    code = (
        "import subprocess\n"
        "def run(cmd):\n"
        "    subprocess.run(f'tar -czf out.tar.gz {cmd}', shell=True)\n"
    )
    hits = scan_for_static_issues(code, technology="fastapi")
    assert len(hits) == 1
    finding = semgrep_finding_to_security_finding(hits[0])
    assert finding.rule_id == "SEMGREP:python-subprocess-shell-true"
    assert finding.status == "FAIL"
    assert finding.file is None  # never leaks the internal temp path


def test_detects_angular_xss_bypass():
    code = (
        "export class Renderer {\n"
        "  render(userContent: string) {\n"
        "    return this.sanitizer.bypassSecurityTrustHtml(userContent);\n"
        "  }\n"
        "}\n"
    )
    hits = scan_for_static_issues(code, technology="angular")
    assert len(hits) == 1
    finding = semgrep_finding_to_security_finding(hits[0])
    assert finding.rule_id == "SEMGREP:angular-bypass-security-trust"


def test_detects_node_eval_and_weak_hash():
    code = (
        "const crypto = require('crypto');\n"
        "function run(code) { return eval(code); }\n"
        "function hash(x) { return crypto.createHash('md5').update(x).digest('hex'); }\n"
    )
    hits = scan_for_static_issues(code, technology="nodejs")
    rule_ids = {h["check_id"].split(".")[-1] for h in hits}
    assert "node-eval" in rule_ids
    assert "node-weak-hash" in rule_ids


def test_no_false_positive_on_clean_code():
    code = (
        "import subprocess\n"
        "def run(filename):\n"
        "    subprocess.run(['tar', '-czf', 'out.tar.gz', filename], shell=False)\n"
    )
    hits = scan_for_static_issues(code, technology="fastapi")
    assert hits == []
