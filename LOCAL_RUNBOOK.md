# Local server runbook: GitHub -> Jenkins -> security gate -> build

This guide runs the complete POC locally with Docker Compose. The services are:

- `db`: PostgreSQL with pgvector
- `api`: FastAPI review service
- `frontend`: Streamlit UI
- `jenkins`: Jenkins controller running in Docker, connected to the Docker daemon through the host socket for this local lab

The request path is:

```text
GitHub push / pull request
        |
        v
Jenkins checks out the repository
        |
        v
ci/build_security_payload.py computes changed text files
        |
        v
POST http://api:8000/review/batch
        |
        +--> RAG: embed code -> retrieve SOP rules from pgvector -> call LLM
        +--> Gitleaks secret scan
        +--> Semgrep static rules
        +--> Bandit Python scan
        +--> ESLint JavaScript/TypeScript scan
        |
        v
Policy gate: Critical/High block, Low/Medium warn, unknown severity blocks
        |
        +--> PASSED: Jenkins builds API and frontend Docker images
        +--> BLOCKED: Jenkins stops with a non-zero exit code
        +--> OVERRIDDEN: only with authority, reason, ticket, expiry, and token
        |
        v
Every decision is appended to security_gate_decisions in PostgreSQL
```

## 1. Prerequisites

Install Docker Desktop, or Docker Engine plus the Compose plugin. Give Docker at least 8 GB RAM because `sentence-transformers` and the LLM client are part of the API image. You also need a GitHub repository containing this project and a reachable OpenAI-compatible LLM endpoint, such as your Llama gateway.

Check the tools:

```bash
docker --version
docker compose version
git --version
```

## 2. Get the code from GitHub

Clone the repository and enter it:

```bash
git clone https://github.com/YOUR_ORG/AI-Security-SOP-Compliance-POC.git
cd AI-Security-SOP-Compliance-POC
```

For a private repository, Jenkins needs a GitHub SSH key or personal access token. Public repositories work without a Git credential.

## 3. Create the local environment file

Copy the template:

```bash
cp .env.example .env
```

Set real values in `.env`:

```dotenv
LLM_BASE_URL=http://host.docker.internal:8001/v1
LLM_API_KEY=your-llm-key
LLM_MODEL=llama3-70b
API_KEY=generate-a-long-random-api-key
SECURITY_OVERRIDE_TOKEN=generate-a-different-long-random-override-token
```

If the LLM is another Compose service, use its service name instead of `host.docker.internal`. On Linux, `host.docker.internal` may need this Compose addition under `api`: `extra_hosts: ["host.docker.internal:host-gateway"]`.

Generate secrets with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keep `.env` out of Git. It is already listed in `.gitignore`.

## 4. Start the server stack

Build and start everything:

```bash
docker compose up -d --build db api frontend jenkins
```

Watch startup:

```bash
docker compose ps
docker compose logs -f api
```

Open these URLs:

- API health: `http://localhost:8000/health`
- API docs: `http://localhost:8000/docs`
- Streamlit UI: `http://localhost:8501`
- Jenkins: `http://localhost:8080`

The first API build downloads Python packages and the embedding model, so it will take a while. That is normal.

## 5. Ingest the SOP rules

The API needs the organisation rules in pgvector before review requests can retrieve them. The API creates the database table during startup, but rule ingestion is explicit:

```bash
curl -X POST http://localhost:8000/sop/ingest \
  -H "X-API-Key: $(grep '^API_KEY=' .env | cut -d= -f2-)"
```

Verify the rules:

```bash
curl http://localhost:8000/sop/rules \
  -H "X-API-Key: $(grep '^API_KEY=' .env | cut -d= -f2-)"
```

You should see the loaded SOP rule objects. If the API returns a database or embedding error, inspect `docker compose logs api`.

## 6. Finish Jenkins first-time setup

Open `http://localhost:8080`. Get the initial admin password:

```bash
docker compose exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
```

Paste it into the setup screen. Create your local admin account. The custom Jenkins image installs the Git, Pipeline, credentials, and stage-view plugins during its first build.

The Jenkins container runs as root and mounts `/var/run/docker.sock` so pipeline steps can build sibling Docker images. This is acceptable for a local POC only. It gives Jenkins control over the host Docker daemon, so do not expose this controller to an untrusted network.

## 7. Add Jenkins credentials

In Jenkins, open **Manage Jenkins -> Credentials -> System -> Global credentials -> Add Credentials**. Create these three **Secret text** credentials with these exact IDs:

1. `security-api-url`: `http://api:8000`
2. `security-api-key`: the exact `API_KEY` from `.env`
3. `security-override-token`: the exact `SECURITY_OVERRIDE_TOKEN` from `.env`

The API URL must be `http://api:8000`, not `http://localhost:8000`, because Jenkins calls the API over the internal Compose network.

## 8. Create the Jenkins pipeline from GitHub

In Jenkins:

1. Click **New Item**.
2. Name it `securecode-poc`.
3. Choose **Pipeline**.
4. Under **Pipeline**, choose **Pipeline script from SCM**.
5. Choose **Git**.
6. Enter the GitHub repository URL.
7. Add the GitHub credential if the repository is private.
8. Set the branch, normally `*/main`.
9. Set the script path to `Jenkinsfile`.
10. Save and click **Build Now**.

Jenkins automatically checks out the repository before the first stage. The pipeline then computes the diff against `GIT_PREVIOUS_COMMIT` and sends the changed files to the API.

## 9. What the Jenkins stages do

### Stage 1: Build security review payload

`ci/build_security_payload.py` runs:

```bash
python3 ci/build_security_payload.py \
  --base "$GIT_PREVIOUS_COMMIT" \
  --head "$GIT_COMMIT" \
  --repository "$JOB_NAME" \
  --actor "${BUILD_USER_ID:-jenkins}"
```

It includes supported changed text files and skips binary files, deleted files, and unsupported extensions. It rejects files over `MAX_FILE_BYTES`.

### Stage 2: Security gate

Jenkins calls:

```text
POST http://api:8000/review/batch
```

The API validates the request, reviews each file, combines findings, and returns one gate status:

- `PASSED`: no Critical or High blocking finding
- `BLOCKED`: at least one Critical or High finding, or a finding with unknown severity
- `OVERRIDE_REQUIRED`: a waiver was requested but not validated
- `OVERRIDDEN`: the waiver was validated and the build may continue

If the API is unavailable, the response is not valid, or the audit record cannot be written, Jenkins fails. That is intentional fail-closed behavior.

### Stage 3: Build and test images

Only after a passing gate, Jenkins builds:

```text
ai-security-poc-api:<build-tag>
ai-security-poc-frontend:<build-tag>
```

It runs the API image test suite inside the built image, then tags both images as `latest` for local use. The API image includes the tests and all scanner binaries, so the CI test environment matches the server image much more closely.

## 10. Test a safe change

Change a harmless file:

```bash
printf '\n# harmless change\n' >> README.md
git add README.md
git commit -m "docs: local pipeline smoke test"
git push origin main
```

Trigger Jenkins, or enable SCM polling/webhooks later. Because README files are not in the supported security payload extensions, the payload may contain no reviewable files. For a real smoke test, edit a Python or JavaScript file safely:

```python
# comment-only change
```

The expected result is `PASSED`, followed by both Docker image builds.

## 11. Test a blocked change

Create a temporary branch and add a deliberately unsafe Python line:

```python
import subprocess
subprocess.run(user_input, shell=True)
```

Commit and push it. Jenkins should show a Semgrep or Bandit finding, the API should return `BLOCKED`, and the image-build stage should not run.

Remove the test vulnerability before merging.

## 12. Test an approved override

Start a Jenkins build with these parameters:

```text
SECURITY_OVERRIDE=true
SECURITY_OVERRIDE_AUTHORITY=security-authority@example.com
SECURITY_OVERRIDE_TICKET=SEC-1234
SECURITY_OVERRIDE_REASON=Temporary exception while the vendor patch is deployed
SECURITY_OVERRIDE_EXPIRES_AT=2026-09-17T18:00:00Z
```

The API also requires the server-side `security-override-token` credential. A valid, unexpired override returns `OVERRIDDEN`, records the waiver fields, and allows image building. An expired, incomplete, or incorrectly signed override fails.

## 13. Run repository and dependency scans

These are repository-level checks and should run once per pipeline, not once per changed file:

```bash
# Dependency manifest scan
curl -X POST http://localhost:8000/dependency-scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"files":[{"filename":"requirements.txt","content":"requests==2.6.0\n"}]}'

# Full Git history secret scan
curl -X POST http://localhost:8000/repo-scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{"repo_url":"https://github.com/YOUR_ORG/YOUR_REPO.git"}'
```

For production, add a separate Jenkins stage for these endpoints and restrict repository URLs to an allowlist. The current repo-scan endpoint should not be exposed publicly without SSRF protection.

## 14. Troubleshooting

### Jenkins cannot reach the API

Use `http://api:8000`, not `localhost`. Check:

```bash
docker compose exec jenkins curl -f http://api:8000/health
docker compose logs api jenkins
```

### The API cannot reach the LLM

`localhost` inside the API container means the API container itself. Use `host.docker.internal` for an LLM running on the host, or the Compose service name for an LLM running in Docker.

### Docker permission or socket errors in Jenkins

This local image runs Jenkins as root. Check that the host socket is available:

```bash
docker compose exec jenkins docker version
```

If Docker Desktop is used, ensure file sharing and Docker socket access are enabled.

### Jenkins pipeline says credentials are missing

The IDs are case-sensitive. Recreate the three secret-text credentials exactly as `security-api-url`, `security-api-key`, and `security-override-token`.

### No changed files are reviewed

The first build may not have `GIT_PREVIOUS_COMMIT`. The pipeline falls back to the repository root commit. If a build still produces an empty payload, make a Python, JavaScript, TypeScript, or Nginx config change and rerun.

### Rules are empty

Run `/sop/ingest` once after the database volume is created. The data lives in `secsop_pgdata`.

## 15. Stop and reset the lab

Stop containers but keep database and Jenkins state:

```bash
docker compose down
```

Remove containers and all local state, including credentials, rules, and Jenkins jobs:

```bash
docker compose down -v
```

Rebuild after code or Dockerfile changes:

```bash
docker compose build --no-cache api frontend jenkins
docker compose up -d db api frontend jenkins
```
