"""
Tests for app/security/eslint_scanner.py. Invokes the real ESLint binary
(installed under eslint-config/node_modules via npm ci) against small
snippets - fast, local, no network/LLM/DB involved.
"""
from app.security.eslint_scanner import eslint_finding_to_security_finding, scan_javascript_code


def test_detects_child_process_and_eval_in_js():
    code = (
        'const { exec } = require("child_process");\n'
        "function run(userInput) {\n"
        "  exec(`ls ${userInput}`);\n"
        "}\n"
        "function riskyEval(code) {\n"
        "  return eval(code);\n"
        "}\n"
    )
    hits = scan_javascript_code(code, technology="nodejs")
    rule_ids = {h["ruleId"] for h in hits}
    assert "security/detect-child-process" in rule_ids
    assert "security/detect-eval-with-expression" in rule_ids
    for h in hits:
        finding = eslint_finding_to_security_finding(h)
        assert finding.status == "FAIL"
        assert finding.file is None


def test_detects_unsafe_innerhtml_in_angular_ts():
    code = (
        "export class Renderer {\n"
        "  render(el, userContent) {\n"
        "    el.innerHTML = userContent;\n"
        "  }\n"
        "}\n"
    )
    hits = scan_javascript_code(code, technology="angular")
    assert len(hits) == 1
    finding = eslint_finding_to_security_finding(hits[0])
    assert finding.rule_id == "ESLINT:property"


def test_no_false_positive_on_clean_code():
    code = (
        'const { execFile } = require("child_process");\n'
        "function run(userInput) {\n"
        '  execFile("ls", [userInput]);\n'
        "}\n"
        "function render(el, content) {\n"
        "  el.textContent = content;\n"
        "}\n"
    )
    hits = scan_javascript_code(code, technology="nodejs")
    assert hits == []


def test_skips_non_javascript_technology():
    # Explicitly labeled Python - should be skipped outright, not scanned
    # (and definitely not produce a parse-error finding).
    code = "import subprocess\nsubprocess.run(x, shell=True)\n"
    hits = scan_javascript_code(code, technology="fastapi")
    assert hits == []
