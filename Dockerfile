FROM python:3.12-slim

WORKDIR /code

# Keep this first layer minimal and stable - curl only. Anything added here
# invalidates every layer below it, including the pip install layers.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Split into two layers on purpose: requirements-core.txt (heavy, stable -
# torch via sentence-transformers) is installed first and its cache survives
# indefinitely as long as THIS file - and every layer above it - doesn't
# change. requirements-tools.txt (semgrep, bandit, pytest - expected to keep
# growing as more scanners are added) is installed as its own separate
# layer, so adding a new tool there never invalidates the core layer / never
# re-downloads torch again.
COPY requirements-core.txt .
RUN pip install --no-cache-dir -r requirements-core.txt

COPY requirements-tools.txt .
RUN pip install --no-cache-dir -r requirements-tools.txt

# nodejs/npm run ESLint (app/security/eslint_scanner.py) - Debian's own apt
# package (Node 18.x) satisfies ESLint 9's >=18.18 requirement, so no
# external NodeSource repo is needed. Placed AFTER the pip install layers
# on purpose - same reasoning as Gitleaks/Trivy below: this can change
# independently without ever touching the torch cache above it.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Gitleaks: deterministic secret scanner used by app/security/secret_scanner.py.
# Pinned version for reproducibility - bump deliberately, don't track :latest.
# Placed AFTER the pip install layer on purpose: this layer changes far more
# often (version bumps) than the pip layer does, and putting it after means
# editing it never invalidates the expensive torch/sentence-transformers cache.
ARG GITLEAKS_VERSION=8.30.1
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && gitleaks version

# Trivy: dependency/SBOM scanner used by app/security/dependency_scanner.py.
# The binary itself is pinned/self-contained like Gitleaks, but CVE scanning
# (not SBOM generation) needs runtime network access to Trivy's vulnerability
# DB registry - see that file's docstring.
ARG TRIVY_VERSION=0.74.0
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# ESLint + security plugins: pinned via eslint-config/package-lock.json (npm ci,
# not npm install - exact reproducible versions, no registry drift). Only the
# package.json/lockfile are copied here, so this layer's cache survives future
# edits to eslint.config.mjs (copied separately below, after the app code).
COPY eslint-config/package.json eslint-config/package-lock.json ./eslint-config/
RUN cd eslint-config && npm ci --no-fund --no-audit

COPY app ./app
COPY data ./data
COPY prompts ./prompts
COPY semgrep-rules ./semgrep-rules
COPY tests ./tests
COPY eslint-config/eslint.config.mjs ./eslint-config/eslint.config.mjs

# Fail the build (not a runtime request) if the ruleset YAML is ever broken
RUN semgrep scan --config ./semgrep-rules/security-rules.yaml --validate

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
