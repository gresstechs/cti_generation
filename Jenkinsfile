pipeline {
  agent any
  
  environment { 
    PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
    GRAFANA_CSV_DIR = "/var/lib/grafana/csv"
  }
  
  stages {
    stage('Checkout'){ 
      steps { 
        checkout scm 
      } 
    }
    
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
    
    stage('Copy to Grafana'){
      steps {
        sh '''
          echo "=========================================="
          echo "Copying files to Grafana..."
          echo "=========================================="
          
          # Copy all CSV and JSON files
          echo "Copying CSV files..."
          cp out/cti_pulses_*.csv "$GRAFANA_CSV_DIR/" 2>/dev/null || echo "⚠️  No pulses CSV found"
          cp out/cti_indicators_*.csv "$GRAFANA_CSV_DIR/" 2>/dev/null || echo "⚠️  No indicators CSV found"
          
          echo "Copying JSON files..."
          cp out/cti_grafana_*.json "$GRAFANA_CSV_DIR/" 2>/dev/null || echo "⚠️  No grafana JSON found"
          cp out/cti_summary_*.json "$GRAFANA_CSV_DIR/" 2>/dev/null || echo "⚠️  No summary JSON found"
          cp out/cti_raw_*.json "$GRAFANA_CSV_DIR/" 2>/dev/null || echo "⚠️  No raw JSON found"
          
          # Set correct permissions
          echo "Setting file permissions..."
          sudo chown grafana:grafana "$GRAFANA_CSV_DIR"/* 2>/dev/null || true
          sudo chmod 644 "$GRAFANA_CSV_DIR"/* 2>/dev/null || true
          
          # List copied files
          echo ""
          echo "Files in Grafana CSV directory:"
          ls -lh "$GRAFANA_CSV_DIR"/ | grep cti_
          
          echo ""
          echo "✅ Files copied successfully!"
        '''
      }
    }
  }
  
  post {
    always {
      archiveArtifacts artifacts: 'out/**/*', allowEmptyArchive: true
    }
    
    success {
      echo "✅ Pipeline completed successfully!"
      echo "📊 Data available in Grafana at: http://your-ec2-ip:3000"
    }
    
    failure {
      echo "❌ Pipeline failed. Check logs above."
    }
  }
}