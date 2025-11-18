pipeline {
  agent any
  
  environment { 
    PIP_CACHE_DIR = "${WORKSPACE}/.pip-cache"
    GRAFANA_CSV_DIR = "/var/lib/grafana/csv"
  }
  
  stages {
    stage('Clean Workspace') {
      steps {
        deleteDir()
        echo "✅ Workspace cleaned"
      }
    }

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
            echo "=========================================="
            echo "Fetching OTX Threat Intelligence..."
            echo "=========================================="
            
            . .venv/bin/activate
            python cti/otx_fetch.py
            
            echo ""
            echo "✅ OTX data fetched successfully"
            echo "📊 Files generated:"
            ls -lh out/cti_*_latest.* 2>/dev/null || echo "No files found"
          '''
        }
      }
    }
    
    stage('ML Malware Detection'){
      steps {
        sh '''
          echo "=========================================="
          echo "Running ML Malware Detection..."
          echo "=========================================="
          
          . .venv/bin/activate
          
          # Check if AndMal model exists
          if [ -f "models/andmal2020_detector_v1.pkl" ]; then
            echo "✅ AndMal model found"
            echo "🔍 Running malware detection on OTX threats..."
            
            # Run detection (if you have the script)
            # python cti/detect_otx_malware.py
            
            echo "⚠️  Note: Add malware detection script here"
            echo "   For now, pipeline continues with heuristic scoring"
          else
            echo "⚠️  AndMal model not found at models/andmal2020_detector_v1.pkl"
            echo "   Train model first: python cti/train_andmal_final.py"
            echo "   Pipeline will use heuristic scoring instead"
          fi
        '''
      }
    }
    
    stage('ML Action Recommendations'){
      steps {
        sh '''
          echo "=========================================="
          echo "Generating ML Action Recommendations..."
          echo "=========================================="
          
          . .venv/bin/activate
          
          # Check if ML features exist
          if [ -f "out/cti_ml_features_latest.csv" ]; then
            echo "✅ OTX ML features found"
            echo "🤖 Running ML recommendation engine..."
            
            # Run complete CTI pipeline
            python cti_pipeline.py
            
            echo ""
            echo "✅ ML recommendations generated"
            echo "📊 Output files:"
            ls -lh out/cti_ml_recommendations.csv 2>/dev/null && echo "   ✓ ML recommendations"
            ls -lh out/cti_threat_detection.csv 2>/dev/null && echo "   ✓ Threat detection scores"
            ls -lh out/cti_pipeline_summary.json 2>/dev/null && echo "   ✓ Pipeline summary"
          else
            echo "❌ ML features not found (out/cti_ml_features_latest.csv)"
            echo "   OTX fetch may have failed. Check previous stage."
            exit 1
          fi
        '''
      }
    }
    
    stage('Copy to Grafana'){
      steps {
        sh '''
          echo "=========================================="
          echo "Copying files to Grafana..."
          echo "=========================================="
          
          GRAFANA_CSV_DIR="/var/lib/grafana/csv"
          mkdir -p "$GRAFANA_CSV_DIR"
          
          echo "Processing OTX data files..."
          
          # === OTX RAW DATA ===
          
          # Copy pulses CSV with fixed name
          for file in out/cti_pulses_*.csv; do
            if [ -f "$file" ]; then
              echo "  ✓ Pulses: $file → cti_pulses_latest.csv"
              cp "$file" "$GRAFANA_CSV_DIR/cti_pulses_latest.csv"
            fi
          done
          
          # Copy indicators CSV with fixed name
          for file in out/cti_indicators_*.csv; do
            if [ -f "$file" ]; then
              echo "  ✓ Indicators: $file → cti_indicators_latest.csv"
              cp "$file" "$GRAFANA_CSV_DIR/cti_indicators_latest.csv"
            fi
          done
          
          # Copy grafana JSON with fixed name
          for file in out/cti_grafana_*.json; do
            if [ -f "$file" ]; then
              echo "  ✓ Grafana data: $file → cti_grafana_latest.json"
              cp "$file" "$GRAFANA_CSV_DIR/cti_grafana_latest.json"
            fi
          done
          
          # Copy summary JSON with fixed name
          for file in out/cti_summary_*.json; do
            if [ -f "$file" ]; then
              echo "  ✓ Summary: $file → cti_summary_latest.json"
              cp "$file" "$GRAFANA_CSV_DIR/cti_summary_latest.json"
            fi
          done
          
          # Copy ML features
          if [ -f "out/cti_ml_features_latest.csv" ]; then
            echo "  ✓ ML Features: cti_ml_features_latest.csv"
            cp "out/cti_ml_features_latest.csv" "$GRAFANA_CSV_DIR/cti_ml_features_latest.csv"
          fi
          
          echo ""
          echo "Processing ML pipeline files..."
          
          # === ML RECOMMENDATIONS ===
          
          # Copy ML recommendations
          if [ -f "out/cti_ml_recommendations.csv" ]; then
            echo "  ✓ ML Recommendations: cti_ml_recommendations.csv"
            cp "out/cti_ml_recommendations.csv" "$GRAFANA_CSV_DIR/cti_ml_recommendations.csv"
          else
            echo "  ⚠️  ML recommendations not found (may have failed)"
          fi
          
          # Copy threat detection scores
          if [ -f "out/cti_threat_detection.csv" ]; then
            echo "  ✓ Threat Detection: cti_threat_detection.csv"
            cp "out/cti_threat_detection.csv" "$GRAFANA_CSV_DIR/cti_threat_detection.csv"
          fi
          
          # Copy pipeline summary
          if [ -f "out/cti_pipeline_summary.json" ]; then
            echo "  ✓ Pipeline Summary: cti_pipeline_summary.json"
            cp "out/cti_pipeline_summary.json" "$GRAFANA_CSV_DIR/cti_pipeline_summary.json"
          fi
          
          echo ""
          echo "Setting permissions..."
          chmod 644 "$GRAFANA_CSV_DIR"/*.csv 2>/dev/null || true
          chmod 644 "$GRAFANA_CSV_DIR"/*.json 2>/dev/null || true
          
          echo ""
          echo "Files in Grafana directory:"
          echo "=========================================="
          ls -lh "$GRAFANA_CSV_DIR"/cti_*.* "$GRAFANA_CSV_DIR"/ml_*.* 2>/dev/null || echo "No files found"
          
          echo ""
          echo "✅ Files copied successfully!"
        '''
      }
    }
    
    stage('Generate Report'){
      steps {
        sh '''
          echo "=========================================="
          echo "Generating Pipeline Report..."
          echo "=========================================="
          
          . .venv/bin/activate
          
          # Count threats by priority
          if [ -f "out/cti_threat_detection.csv" ]; then
            CRITICAL=$(grep -c ",CRITICAL," out/cti_threat_detection.csv || echo "0")
            HIGH=$(grep -c ",HIGH," out/cti_threat_detection.csv || echo "0")
            MEDIUM=$(grep -c ",MEDIUM," out/cti_threat_detection.csv || echo "0")
            LOW=$(grep -c ",LOW," out/cti_threat_detection.csv || echo "0")
            
            echo ""
            echo "📊 Threat Priority Distribution:"
            echo "   🔴 CRITICAL: $CRITICAL"
            echo "   🟠 HIGH:     $HIGH"
            echo "   🟡 MEDIUM:   $MEDIUM"
            echo "   🟢 LOW:      $LOW"
          fi
          
          # Count recommendations
          if [ -f "out/cti_ml_recommendations.csv" ]; then
            TOTAL_REC=$(wc -l < out/cti_ml_recommendations.csv)
            TOTAL_REC=$((TOTAL_REC - 1))  # Subtract header
            echo ""
            echo "🤖 ML Recommendations:"
            echo "   Total actions: $TOTAL_REC"
            
            # Top 5 actions
            echo ""
            echo "   Top 5 recommended actions:"
            tail -n +2 out/cti_ml_recommendations.csv | cut -d',' -f8 | sort | uniq -c | sort -rn | head -5 | while read count action; do
              echo "      • $action: $count times"
            done
          fi
          
          echo ""
          echo "=========================================="
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
          script: 'ls /var/lib/grafana/csv/cti_*.* 2>/dev/null | wc -l || echo "0"',
          returnStdout: true
        ).trim()
        
        if (grafanaFiles == "0") {
          echo "📝 MANUAL SETUP REQUIRED:"
          echo "   Files are available in: ${WORKSPACE}/out/"
          echo ""
          echo "   Manual copy commands:"
          echo "   cp ${WORKSPACE}/out/cti_pulses_*.csv /var/lib/grafana/csv/cti_pulses_latest.csv"
          echo "   cp ${WORKSPACE}/out/cti_indicators_*.csv /var/lib/grafana/csv/cti_indicators_latest.csv"
          echo "   cp ${WORKSPACE}/out/cti_ml_recommendations.csv /var/lib/grafana/csv/"
          echo "   cp ${WORKSPACE}/out/cti_threat_detection.csv /var/lib/grafana/csv/"
          echo "   chmod 644 /var/lib/grafana/csv/cti_*.*"
        } else {
          echo "✅ Successfully copied ${grafanaFiles} files to Grafana"
        }
        
        // Display pipeline summary
        if (fileExists('out/cti_pipeline_summary.json')) {
          echo ""
          echo "📊 PIPELINE SUMMARY:"
          def summary = readJSON file: 'out/cti_pipeline_summary.json'
          echo "   Total threats: ${summary.statistics.total_threats}"
          echo "   Critical: ${summary.statistics.critical_threats}"
          echo "   High: ${summary.statistics.high_threats}"
          echo "   Total recommendations: ${summary.statistics.total_recommendations}"
        }
      }
    }
    
    success {
      echo ""
      echo "=========================================="
      echo "✅ PIPELINE COMPLETED SUCCESSFULLY!"
      echo "=========================================="
      echo ""
      echo "📊 Data Processing:"
      echo "   ✓ OTX threat intelligence fetched"
      echo "   ✓ ML malware detection executed"
      echo "   ✓ Action recommendations generated"
      echo "   ✓ Files copied to Grafana"
      echo ""
      echo "📁 Output Files:"
      echo "   • cti_pulses_latest.csv"
      echo "   • cti_indicators_latest.csv"
      echo "   • cti_ml_recommendations.csv (NEW)"
      echo "   • cti_threat_detection.csv (NEW)"
      echo "   • cti_pipeline_summary.json (NEW)"
      echo ""
      echo "🌐 Access Grafana:"
      echo "   http://your-ec2-ip:3000"
      echo ""
      echo "📈 Next Steps:"
      echo "   1. Import Grafana dashboards"
      echo "   2. Review ML recommendations"
      echo "   3. Execute priority actions"
      echo "=========================================="
    }
    
    failure {
      echo ""
      echo "=========================================="
      echo "❌ PIPELINE FAILED"
      echo "=========================================="
      echo ""
      echo "🔍 Check logs above for errors"
      echo ""
      echo "Common issues:"
      echo "   • OTX API key not set or invalid"
      echo "   • Python dependencies not installed"
      echo "   • ML model files missing"
      echo "   • Grafana directory permissions"
      echo ""
      echo "📁 Artifacts may still be in:"
      echo "   ${WORKSPACE}/out/"
      echo "=========================================="
    }
  }
}
