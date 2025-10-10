pipeline {
  agent any
  environment { PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache" }
  stages {
    stage('Checkout'){ steps { checkout scm } }
    stage('Setup venv'){
      steps {
        sh '''
          python3 -m venv .venv
          . .venv/bin/activate
          python -m pip install --upgrade pip wheel
          pip install --cache-dir "$PIP_CACHE_DIR" -r requirements.txt
        '''
      }
    }
    stage('Fetch CTI'){
      steps {
        withCredentials([string(credentialsId: 'otx-api-key', variable: 'OTX_API_KEY')]){
          sh '''
            . .venv/bin/activate
            python cti/otx_fetch.py
          '''
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'out/**/*', allowEmptyArchive: true
    }
  }
}
