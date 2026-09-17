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
        API_IMAGE = "ai-security-poc-api:${BUILD_TAG}"
        FRONTEND_IMAGE = "ai-security-poc-frontend:${BUILD_TAG}"
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
                sh '''
                    set -eu
                    cd target-repo
                    BASE="$(git rev-parse HEAD~1 2>/dev/null || git rev-list --max-parents=0 HEAD)"
                    HEAD="$(git rev-parse HEAD)"
            python3 ../ci/build_security_payload.py \
              --base "$BASE" \
              --head "$HEAD" \
              --repository "${TARGET_REPO_URL}" \
              --actor "${BUILD_USER_ID:-jenkins}" \
              > ../security-request.json
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

        stage('Build and test images') {
            steps {
                sh '''
                    set -eu
                    cd target-repo
                    docker build --tag "\${API_IMAGE}" .
                    docker run --rm "\${API_IMAGE}" pytest tests -q
                    docker build --tag "\${FRONTEND_IMAGE}" --file Dockerfile.frontend .
                    docker tag "\${API_IMAGE}" ai-security-poc-api:latest
                    docker tag "\${FRONTEND_IMAGE}" ai-security-poc-frontend:latest
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