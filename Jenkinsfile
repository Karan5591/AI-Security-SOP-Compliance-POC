pipeline {
    agent any
    options { timestamps(); disableConcurrentBuilds(); skipDefaultCheckout(false) }

    parameters {
        string(name: 'TARGET_REPO_URL', defaultValue: 'https://github.com/Karan5591/rag-project.git', description: 'The repository to scan and build')
        string(name: 'TARGET_BRANCH', defaultValue: 'main', description: 'The branch to build')

        booleanParam(name: 'SECURITY_OVERRIDE', defaultValue: false, description: 'Use an approved security waiver')
        string(name: 'SECURITY_OVERRIDE_AUTHORITY', defaultValue: '', description: 'Approving authority or role')
        string(name: 'SECURITY_OVERRIDE_TICKET', defaultValue: '', description: 'Change or waiver ticket')
        text(name: 'SECURITY_OVERRIDE_REASON', defaultValue: '', description: 'Why the build must proceed')
        string(name: 'SECURITY_OVERRIDE_EXPIRES_AT', defaultValue: '', description: 'UTC ISO-8601 expiry, e.g. 2026-09-17T18:00:00Z')
    }

    environment {
        SECURITY_API_URL = credentials('security-api-url')
        SECURITY_API_KEY = credentials('security-api-key')
    }

    stages {
        stage('Clone Target Repo') {
            steps {
                // Using double quotes here so Groovy can interpolate the TARGET parameters
                sh """
                    set -eu
                    rm -rf target-repo
                    git clone --branch "${params.TARGET_BRANCH}" "${params.TARGET_REPO_URL}" target-repo
                """
            }
        }

        stage('Build security review payload') {
            steps {
                // Scans target-repo itself (the repo named by TARGET_REPO_URL), not the
                // outer Jenkins job checkout -- GIT_PREVIOUS_COMMIT/GIT_COMMIT belong to
                // whatever repo this job's own SCM config points at, which is not
                // necessarily the repo we were asked to review.
                sh '''
                    set -eu
                    python3 ci/build_security_payload.py \
                      --repo-dir target-repo \
                      --repository "${TARGET_REPO_URL}" \
                      --actor "${BUILD_USER_ID:-jenkins}" > security-request.json
                '''
            }
        }

        stage('Security gate') {
            steps {
                withCredentials([string(credentialsId: 'security-override-token', variable: 'SECURITY_OVERRIDE_TOKEN')]) {
                    sh '''
                        set -eu
                        OVERRIDE_ARGS=""
                        if [ "\${SECURITY_OVERRIDE}" = "true" ]; then
                          : "\${SECURITY_OVERRIDE_AUTHORITY:?authority is required}"
                          : "\${SECURITY_OVERRIDE_TICKET:?ticket is required}"
                          : "\${SECURITY_OVERRIDE_REASON:?reason is required}"
                          : "\${SECURITY_OVERRIDE_EXPIRES_AT:?expiry is required}"
                          python3 - <<'PY'
import json, os
from pathlib import Path
p = Path('security-request.json')
payload = json.loads(p.read_text())
payload['override'] = {
    'authority': os.environ['SECURITY_OVERRIDE_AUTHORITY'],
    'reason': os.environ['SECURITY_OVERRIDE_REASON'],
    'approval_ticket': os.environ['SECURITY_OVERRIDE_TICKET'],
    'expires_at': os.environ['SECURITY_OVERRIDE_EXPIRES_AT'],
}
p.write_text(json.dumps(payload))
PY
                          OVERRIDE_ARGS="-H X-Security-Override-Token:\${SECURITY_OVERRIDE_TOKEN}"
                        fi
                        curl --fail-with-body --silent --show-error \
                          --request POST "\${SECURITY_API_URL}/review/batch" \
                          --header "Content-Type: application/json" \
                          --header "X-API-Key: \${SECURITY_API_KEY}" \
                          \${OVERRIDE_ARGS} --data-binary @security-request.json > security-result.json
                        cat security-result.json
                        STATUS="\$(python3 -c 'import json; print(json.load(open("security-result.json"))["gate"]["status"])')"
                        case "\$STATUS" in
                          PASSED|OVERRIDDEN) ;;
                          *) echo "Security gate blocked or failed: \$STATUS"; exit 1 ;;
                        esac
                    '''
                }
            }
        }

        stage('Build target repo image (optional)') {
            // Not every scanned repo is containerized, and building isn't part of the
            // security review -- the gate already passed by the time we get here. This
            // stage is a best-effort convenience: build a Docker image only if the
            // target repo actually provides one, named after that repo (not a fixed
            // name that only made sense for security-sop-poc itself). Missing
            // Dockerfiles are logged and skipped, never treated as a failure.
            steps {
                sh '''
                    set -eu
                    cd target-repo
                    REPO_NAME="$(basename -s .git "${TARGET_REPO_URL}")"

                    if [ -f Dockerfile ]; then
                      docker build --tag "${REPO_NAME}:${BUILD_TAG}" .
                      docker tag "${REPO_NAME}:${BUILD_TAG}" "${REPO_NAME}:latest"
                      echo "Built ${REPO_NAME}:${BUILD_TAG}"
                    else
                      echo "No Dockerfile at the root of ${REPO_NAME} -- skipping build. This is expected for non-containerized or source-only repos."
                    fi

                    if [ -f Dockerfile.frontend ]; then
                      docker build --tag "${REPO_NAME}-frontend:${BUILD_TAG}" --file Dockerfile.frontend .
                      docker tag "${REPO_NAME}-frontend:${BUILD_TAG}" "${REPO_NAME}-frontend:latest"
                      echo "Built ${REPO_NAME}-frontend:${BUILD_TAG}"
                    fi
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-request.json,security-result.json', allowEmptyArchive: true, fingerprint: true
        }
    }
}