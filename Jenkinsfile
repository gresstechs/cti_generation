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
          
          # Create directory if it doesn't exist (Jenkins user should have access)
          mkdir -p "$GRAFANA_CSV_DIR" 2>/dev/null || {
            echo "⚠️  Cannot create $GRAFANA_CSV_DIR directly. Trying alternative location..."
            GRAFANA_CSV_DIR="${WORKSPACE}/grafana-data"
            mkdir -p "$GRAFANA_CSV_DIR"
            echo "Using alternative directory: $GRAFANA_CSV_DIR"
          }
          
          # Remove old CTI files if we have permission
          echo "Cleaning old CTI files..."
          rm -f "$GRAFANA_CSV_DIR"/cti_* 2>/dev/null || {
            echo "⚠️  Limited permissions - some old files may remain"
          }
          
          # Copy all CSV files
          echo "Copying CSV files..."
          copied_csv=0
          for file in out/cti_*.csv; do
            if [ -f "$file" ]; then
              echo "  Copying: $(basename $file)"
              cp "$file" "$GRAFANA_CSV_DIR/" && copied_csv=$((copied_csv + 1)) || {
                echo "  ❌ Failed to copy $file"
              }
            fi
          done
          
          # Copy all JSON files  
          echo "Copying JSON files..."
          copied_json=0
          for file in out/cti_*.json; do
            if [ -f "$file" ]; then
              echo "  Copying: $(basename $file)"
              cp "$file" "$GRAFANA_CSV_DIR/" && copied_json=$((copied_json + 1)) || {
                echo "  ❌ Failed to copy $file"
              }
            fi
          done
          
          # Set permissions if possible (without sudo)
          echo ""
          echo "Setting file permissions (if possible)..."
          chmod 644 "$GRAFANA_CSV_DIR"/cti_* 2>/dev/null || {
            echo "⚠️  Could not set file permissions - running with current user permissions"
          }
          
          # List final files
          echo ""
          echo "Files in target directory ($GRAFANA_CSV_DIR):"
          ls -lh "$GRAFANA_CSV_DIR"/ | grep "cti_" || echo "No CTI files found"
          
          echo ""
          echo "✅ File copy completed!"
          echo "📊 Copied: $copied_csv CSV files, $copied_json JSON files"
          echo "📁 Location: $GRAFANA_CSV_DIR"
        '''
      }
    }
  }
  
  post {
    always {
      archiveArtifacts artifacts: 'out/**/*', allowEmptyArchive: true
      
      script {
        // Check if files were copied to Grafana directory
        def grafanaFiles = sh(
          script: 'ls /var/lib/grafana/csv/cti_* 2>/dev/null | wc -l || echo "0"',
          returnStdout: true
        ).trim()
        
        if (grafanaFiles == "0") {
          echo "📝 MANUAL SETUP REQUIRED:"
          echo "   Files are available in: ${WORKSPACE}/grafana-data/"
          echo "   To manually copy to Grafana:"
          echo "   sudo cp ${WORKSPACE}/grafana-data/cti_* /var/lib/grafana/csv/"
          echo "   sudo chown grafana:grafana /var/lib/grafana/csv/cti_*"
          echo "   sudo chmod 644 /var/lib/grafana/csv/cti_*"
        }
      }
    }
    
    success {
      echo "✅ Pipeline completed successfully!"
      echo "📊 Data available in Jenkins artifacts and prepared for Grafana"
      echo "🌐 Access Grafana at: http://your-ec2-ip:3000"
    }
    
    failure {
      echo "❌ Pipeline failed. Check logs above."
      echo "📁 Artifacts may still be available in Jenkins workspace"
    }
  }
}