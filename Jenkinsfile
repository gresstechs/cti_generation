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
          
          # Create directory if it doesn't exist
          mkdir -p "$GRAFANA_CSV_DIR"
          
          # First, DELETE ALL old files completely
          echo "Removing ALL old files..."
          sudo rm -f "$GRAFANA_CSV_DIR"/cti_* 2>/dev/null || true
          
          # Copy all CSV files
          echo "Copying CSV files..."
          for file in out/cti_*.csv; do
            if [ -f "$file" ]; then
              echo "  Copying: $(basename $file)"
              sudo cp "$file" "$GRAFANA_CSV_DIR/"
            fi
          done
          
          # Copy all JSON files
          echo "Copying JSON files..."
          for file in out/cti_*.json; do
            if [ -f "$file" ]; then
              echo "  Copying: $(basename $file)"
              sudo cp "$file" "$GRAFANA_CSV_DIR/"
            fi
          done
          
          # Set correct permissions
          echo ""
          echo "Setting file permissions..."
          sudo chown grafana:grafana "$GRAFANA_CSV_DIR"/* 2>/dev/null || true
          sudo chmod 644 "$GRAFANA_CSV_DIR"/* 2>/dev/null || true
          
          # List final files
          echo ""
          echo "Files in Grafana CSV directory:"
          ls -lh "$GRAFANA_CSV_DIR"/ | grep "cti_"
          
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