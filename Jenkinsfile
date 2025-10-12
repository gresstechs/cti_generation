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
          echo "Copying and renaming files for Grafana..."
          echo "=========================================="
          
          GRAFANA_CSV_DIR="/var/lib/grafana/csv"
          mkdir -p "$GRAFANA_CSV_DIR"
          
          # Copy and RENAME to fixed filenames (removes timestamp)
          echo "Processing files..."
          
          # Copy pulses CSV with fixed name
          for file in out/cti_pulses_*.csv; do
            if [ -f "$file" ]; then
              echo "  Copying pulses: $file → cti_pulses_latest.csv"
              cp "$file" "$GRAFANA_CSV_DIR/cti_pulses_latest.csv"
            fi
          done
          
          # Copy indicators CSV with fixed name
          for file in out/cti_indicators_*.csv; do
            if [ -f "$file" ]; then
              echo "  Copying indicators: $file → cti_indicators_latest.csv"
              cp "$file" "$GRAFANA_CSV_DIR/cti_indicators_latest.csv"
            fi
          done
          
          # Copy grafana JSON with fixed name
          for file in out/cti_grafana_*.json; do
            if [ -f "$file" ]; then
              echo "  Copying grafana data: $file → cti_grafana_latest.json"
              cp "$file" "$GRAFANA_CSV_DIR/cti_grafana_latest.json"
            fi
          done
          
          # Copy summary JSON with fixed name
          for file in out/cti_summary_*.json; do
            if [ -f "$file" ]; then
              echo "  Copying summary: $file → cti_summary_latest.json"
              cp "$file" "$GRAFANA_CSV_DIR/cti_summary_latest.json"
            fi
          done
          
          echo ""
          echo "Setting permissions..."
          chmod 644 "$GRAFANA_CSV_DIR"/cti_*_latest.* 2>/dev/null || true
          
          echo ""
          echo "Files in Grafana directory:"
          ls -lh "$GRAFANA_CSV_DIR"/cti_*_latest.*
          
          echo ""
          echo "✅ Files updated successfully!"
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
          script: 'ls /var/lib/grafana/csv/cti_*_latest.* 2>/dev/null | wc -l || echo "0"',
          returnStdout: true
        ).trim()
        
        if (grafanaFiles == "0") {
          echo "📝 MANUAL SETUP REQUIRED:"
          echo "   Files are available in: ${WORKSPACE}/out/"
          echo "   To manually copy to Grafana with fixed names:"
          echo "   cp ${WORKSPACE}/out/cti_pulses_*.csv /var/lib/grafana/csv/cti_pulses_latest.csv"
          echo "   cp ${WORKSPACE}/out/cti_indicators_*.csv /var/lib/grafana/csv/cti_indicators_latest.csv"
          echo "   cp ${WORKSPACE}/out/cti_grafana_*.json /var/lib/grafana/csv/cti_grafana_latest.json"
          echo "   cp ${WORKSPACE}/out/cti_summary_*.json /var/lib/grafana/csv/cti_summary_latest.json"
          echo "   chmod 644 /var/lib/grafana/csv/cti_*_latest.*"
        } else {
          echo "✅ Successfully copied ${grafanaFiles} files to Grafana with fixed names"
        }
      }
    }
    
    success {
      echo "✅ Pipeline completed successfully!"
      echo "📊 Data available in Jenkins artifacts and copied to Grafana with fixed filenames"
      echo "🌐 Access Grafana at: http://your-ec2-ip:3000"
      echo "📁 Fixed filenames: cti_pulses_latest.csv, cti_indicators_latest.csv, etc."
    }
    
    failure {
      echo "❌ Pipeline failed. Check logs above."
      echo "📁 Artifacts may still be available in Jenkins workspace"
    }
  }
}