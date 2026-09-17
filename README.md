# AI-Security-SOP-Compliance-POC

An AI-assisted security code review POC: developer code is checked against an
organisation-defined Security SOP (derived from a real audit report) using
RAG (pgvector) + an LLM (Llama 3 70B, or any OpenAI-chat-compatible model).

Covers the 5 audit findings: SQL Injection, IDOR/Broken Access Control,
outdated Nginx, missing HTTP security headers, missing custom error handling.

## Architecture (V1)

```
Security Audit Report -> SOP rules (data/sop/*.json)
                              |
                          Embeddings (sentence-transformers)
                              |
                       PostgreSQL + pgvector
                              |
Developer Code -----> RAG retrieval (top-K relevant rules)
                              |
                        Llama 3 70B (via /chat/completions)
                              |
                 Structured JSON: PASS / FAIL / WARN + findings
```

No SAST/DAST integration in V1 (see project notes for the phased plan) - this
version proves the RAG + LLM + SOP loop end to end.

## Where to put these files

If you already created `D:\NIC\AI-Security-SOP-Compliance-POC` with the
folders/venv/requirements.txt from Step 1, **replace** that folder's contents
with this one (or just extract this zip on top of it, overwriting files).
The `requirements.txt` here matches what you already installed, plus
`pytest`/`pytest-mock` for the test suite.

```
D:\NIC\AI-Security-SOP-Compliance-POC\   <- extract the zip here
├── app/
├── data/
├── prompts/
├── tests/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Setup

### 1. Environment variables

```powershell
copy .env.example .env
```

Edit `.env` and set at minimum:
- `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` - point these at your Llama 3 70B
  gateway (same one used in your existing RAG project, if you have one).
- `API_KEY` - required on every endpoint except `/health`. Generate one:
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- `DATABASE_URL` - leave as-is if using the provided `docker-compose.yml`.

### 2a. Run everything with Docker (recommended)

```powershell
docker compose up --build
```

This starts Postgres+pgvector (`db`) and the API (`api`) on
`http://localhost:8000`. The API waits for the DB healthcheck before starting.

### 2b. Run locally without Docker

You already have a venv from Step 1:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start Postgres+pgvector yourself (or run just the `db` service:
`docker compose up db`), then:

```powershell
uvicorn app.main:app --reload
```

## Usage

All endpoints except `/health` require an `X-API-Key` header matching the
`API_KEY` set in your `.env`.

### 1. Load the SOP rules into pgvector

```bash
curl -X POST http://localhost:8000/sop/ingest -H "X-API-Key: $API_KEY"
```

This reads every JSON file in `data/sop/`, embeds each rule, and stores it
in the `sop_rules` table. 25 rules are included out of the box: SQL-001..005,
BAC-001..004, HDR-001..004, ERR-001..004, SEC-001, XSS-001..004, CSRF-001..003.

Check what's loaded:

```bash
curl http://localhost:8000/sop/rules -H "X-API-Key: $API_KEY"
```

### 2. Review code

```bash
curl -X POST http://localhost:8000/review \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
        "code": "@app.get(\"/users/{user_id}\")\nasync def get_user(user_id: int):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    return await db.execute(query)",
        "technology": "fastapi"
      }'
```

Expected response shape:

```json
{
  "assessment": {
    "overall_status": "FAIL",
    "findings": [
      {
        "status": "FAIL",
        "finding": "SQL Injection",
        "rule_id": "SQL-001",
        "severity": "CRITICAL",
        "file": null,
        "line": 12,
        "reason": "user_id is directly interpolated into SQL",
        "recommendation": "Use a parameterized query",
        "confidence": 0.98
      }
    ]
  },
  "retrieved_rule_ids": ["SQL-001", "SQL-002", "SQL-004"]
}
```

Every `/review` call also runs 4 deterministic scanners alongside the
LLM/RAG path - see "Deterministic scanning layer" below. Any hit from any of
them appears in the same `findings` list and forces `overall_status` to FAIL.

### 3. Try the demo test cases

`data/test_cases/` has vulnerable/secure pairs across SQL, IDOR, headers,
errors, XSS, and CSRF, in Python, Node.js, Angular, and Nginx - paste any of
them into the `/review` request above to reproduce the FAIL -> PASS demo.

### 4. Dependency/SBOM scanning (separate from `/review`)

Different input shape - manifest files, not a code snippet:

```bash
curl -X POST http://localhost:8000/dependency-scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"files": [{"filename": "requirements.txt", "content": "requests==2.6.0\n"}]}'
```

Returns an SBOM (works fully offline) and a CVE list (needs network access
to Trivy's vulnerability DB - see the scanning layer section below for why
this one's different from the others).

### 5. Git-history secret scanning (separate from `/review`)

Scans a repo's full commit history, not just its current file contents -
catches a secret that was committed and later "removed" in a later commit:

```bash
curl -X POST http://localhost:8000/repo-scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"repo_url": "https://github.com/your-org/your-repo.git"}'
```

`repo_url` accepts a git URL or a local path reachable from inside the
container.

## Running the offline test suite

```bash
pytest tests/ -v
```

23 tests, no Docker/DB/LLM/network required for most of them (they invoke
the real Gitleaks/Semgrep/Bandit/ESLint binaries directly - fast and local).
The one exception: `test_dependency_scanner.py`'s CVE-scan test only checks
graceful degradation, not real detection, since that needs the Trivy DB
registry (see below).

## Project layout

```
app/
├── main.py                FastAPI app, lifespan (DB init/teardown)
├── core/
│   ├── config.py           Settings (env-driven)
│   └── security.py         X-API-Key auth dependency
├── db/postgres.py          pgvector schema + queries
├── rag/
│   ├── embeddings.py        sentence-transformers wrapper
│   ├── ingest.py            loads data/sop/*.json -> pgvector
│   └── retriever.py         top-K similarity search (code content only,
│                             not the technology label - see git history)
├── llm/client.py            OpenAI-chat-compatible client (Llama 3 70B)
├── security/
│   ├── evaluator.py          builds prompt, calls LLM, validates JSON
│   ├── secret_scanner.py     Gitleaks - hardcoded secrets (stdin, single snippet)
│   ├── semgrep_scanner.py    Semgrep - local pinned ruleset
│   ├── bandit_scanner.py     Bandit - Python-specific static analysis
│   ├── eslint_scanner.py     ESLint + security plugins - JS/TS/Angular
│   ├── dependency_scanner.py Trivy - SBOM + CVE scan of a manifest
│   └── git_history_scanner.py Gitleaks - full repo commit history
└── api/
    ├── sop.py               POST /sop/ingest, GET /sop/rules
    ├── review.py            POST /review
    ├── dependency.py         POST /dependency-scan
    └── repo.py                POST /repo-scan
data/
├── sop/                    the 25 SOP rules (JSON)
└── test_cases/             vulnerable/secure code pairs per finding type
prompts/security_review.txt    system prompt for the LLM reviewer
semgrep-rules/security-rules.yaml   local, pinned Semgrep ruleset
eslint-config/                 pinned ESLint + security plugin versions
tests/                         23 offline tests across all 5 scanners + evaluator
```

## Deterministic scanning layer (Phase 2)

Four scanners run on every `/review` call, independently of RAG retrieval
and the LLM - they can't hallucinate, and they don't depend on retrieval
surfacing the right SOP rule:

- **Gitleaks** (`app/security/secret_scanner.py`) - hardcoded secrets, API
  keys, tokens, credentials. Scans the submitted snippet only (stdin) - see
  `git_history_scanner.py` below for full-repo history scanning.
- **Semgrep** (`app/security/semgrep_scanner.py`) - a local, pinned ruleset
  at `semgrep-rules/security-rules.yaml` (not the semgrep.dev registry - no
  runtime dependency on external reachability). Covers command injection,
  insecure deserialization (pickle/yaml.load), eval/exec, Angular
  `bypassSecurityTrust*` XSS, `.innerHTML` XSS, and weak hashing (MD5/SHA1).
- **Bandit** (`app/security/bandit_scanner.py`) - Python-specific static
  analysis. No-op on non-Python code (fails to parse, returns no findings).
  Filters out LOW-severity "you imported a risky module" noise, only
  surfaces actual usage-pattern findings.
- **ESLint + eslint-plugin-security + eslint-plugin-no-unsanitized**
  (`app/security/eslint_scanner.py`) - JS/TS/Angular-specific: unsafe regex,
  non-literal fs paths, timing-attack-prone comparisons, weak randomness, on
  top of some deliberate overlap with Semgrep (eval, child_process,
  innerHTML) - agreement between independent tools is a confidence signal,
  not redundancy worth eliminating.

Any hit from any of these four is appended to `findings` and forces
`overall_status` to `FAIL`, regardless of what the LLM concluded.

Two more scanners exist but are **separate endpoints**, not part of
`/review` - different input shape (a manifest or a whole repo, not a code
snippet):

- **Trivy** (`app/security/dependency_scanner.py`, `POST /dependency-scan`)
  - SBOM generation (CycloneDX) works **fully offline**, verified during
  development with no network access. CVE scanning is architecturally
  different from every scanner above: it needs live access to Trivy's
  vulnerability DB registry (`ghcr.io`/`mirror.gcr.io`). That registry was
  blocked in the sandbox this was built in, so CVE scanning could only be
  verified for graceful degradation (a clear error, never a crash) - **test
  it against your actual network before relying on it**, and if it's
  blocked there too, that's a real finding worth raising (same class of
  risk as the semgrep.dev registry being blocked, which is why Semgrep uses
  a local ruleset instead - Trivy's CVE database can't be pinned locally
  the same way, it's too large and changes daily).
- **Gitleaks git-history mode**
  (`app/security/git_history_scanner.py`, `POST /repo-scan`) - scans a
  repo's full commit history, catching a secret that was committed and
  later "removed" in a subsequent commit (which the stdin-based scan above
  would miss entirely, since it only sees current file content).

## Run the complete local server lab

For the full Docker flow from GitHub checkout through Jenkins, security gating, and final image builds, follow [LOCAL_RUNBOOK.md](LOCAL_RUNBOOK.md). Jenkins is included as a Compose service.

## CI/CD enforcement

The project now includes `POST /review/batch` and a root `Jenkinsfile`. Jenkins sends changed text files to the batch endpoint. Critical and High findings block the build; Low and Medium findings are warnings. Missing severity blocks by default.

Set `SECURITY_OVERRIDE_TOKEN` on the API and store the same value as the Jenkins credential `security-override-token`. An override must include an approving authority, reason, ticket, and future UTC expiry. Decisions are append-only in `security_gate_decisions`. Never expose the override token as a normal build parameter.

The Jenkinsfile expects credentials named `security-api-url`, `security-api-key`, and `security-override-token`, plus a `build.sh` script in the application repository.

## What's deliberately NOT in there yet

- No DAST (OWASP ZAP).
- No Angular/React frontend beyond the Streamlit UI (`frontend/`).
- Trivy CVE scanning is unverified against a live vulnerability DB (see
  above) - confirm it works on your network before treating it as reliable.

## Next steps (when you're ready to expand)

1. Verify Trivy CVE scanning against your actual network; if the DB
   registry is blocked, look into an offline/air-gapped DB sync process.
2. Broaden `semgrep-rules/security-rules.yaml` and the SOP rule set further
   (SSRF, prototype pollution, JWT misconfiguration) as new gaps are found.
