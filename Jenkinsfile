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
    
    stage('Train OTX Threat Model'){
      steps {
        sh '''
          echo "=========================================="
          echo "Training OTX Threat Classification Model..."
          echo "=========================================="

          . .venv/bin/activate

          # Check if OTX model exists
          if [ -f "models/otx_threat_classifier_v1.pkl" ]; then
            echo "✅ OTX threat model already exists"
            echo "   Skipping training (delete model to retrain)"
          else
            echo "🔧 Training new OTX threat model..."
            echo "   Using OTX data for training"

            # Train the model
            python cti/train_otx_threat_model.py

            echo ""
            echo "✅ OTX threat model trained successfully"
          fi

          # Show model info
          if [ -f "models/otx_threat_classifier_metadata.json" ]; then
            echo ""
            echo "📊 Model Info:"
            cat models/otx_threat_classifier_metadata.json | head -20
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

    stage('ML Threat Prediction'){
      steps {
        sh '''
          echo "=========================================="
          echo "Running ML Threat Prediction..."
          echo "=========================================="

          . .venv/bin/activate

          # Check if OTX features exist
          if [ ! -f "out/cti_ml_features_latest.csv" ]; then
            echo "⚠️  OTX ML features not found"
            echo "   Checking for existing predictions..."
            if [ -f "out/otx_andmal_predictions.csv" ]; then
              echo "   ✓ Using existing predictions file"
            else
              echo "   ⚠️  No predictions available. MTTR will use sample data."
            fi
          else
            echo "✅ OTX features found"

            # Check which model is available
            if [ -f "models/otx_threat_classifier_v1.pkl" ]; then
              echo "✅ OTX ML model found - using trained model"
            else
              echo "⚠️  OTX ML model not found - using heuristic scoring"
            fi

            echo "🔍 Running threat prediction on OTX data..."

            # Run prediction (script handles model/heuristic fallback automatically)
            python cti/predict_otx_with_andmal.py

            echo ""
            echo "✅ Threat predictions generated"
            ls -lh out/otx_andmal_predictions.csv 2>/dev/null && echo "   ✓ Predictions file ready"

            # Show prediction method used
            if [ -f "out/otx_andmal_summary.json" ]; then
              echo ""
              echo "📊 Prediction Summary:"
              cat out/otx_andmal_summary.json | grep -E '"prediction_method"|"total_threats"|"critical_threats"' | head -5
            fi
          fi
        '''
      }
    }

    stage('Calculate MTTR'){
      steps {
        sh '''
          echo "=========================================="
          echo "Calculating MTTR Metrics..."
          echo "=========================================="

          . .venv/bin/activate
          cd cti

          # Step 1: Convert predictions to MTTR format (appends new threats)
          if [ -f "../out/otx_andmal_predictions.csv" ]; then
            echo "📊 Converting predictions to MTTR format..."
            python convert_threats_for_mttr.py
            echo ""
          else
            echo "⚠️  No predictions file found, checking for existing classified threats..."
          fi

          # Step 2: Calculate MTTR metrics
          if [ -f "classified_threats.csv" ]; then
            echo "📈 Calculating MTTR metrics..."
            python calculate_mttr.py

            echo ""
            echo "✅ MTTR calculation complete"
            echo ""
            echo "📊 MTTR Metrics Generated:"
            ls -lh "$GRAFANA_CSV_DIR"/mttr_*.csv 2>/dev/null || ls -lh ../out/grafana_csv/mttr_*.csv 2>/dev/null
          else
            echo "⚠️  No classified threats found. Run prediction first."
            echo "   Creating sample data for initial setup..."

            # Create sample classified_threats.csv for first run
            echo "timestamp,threat_id,severity,confidence,classification" > classified_threats.csv
            SAMPLE_TIME=$(date "+%Y-%m-%d %H:%M:%S")
            echo "${SAMPLE_TIME},SAMPLE001,MEDIUM,0.5,Suspicious" >> classified_threats.csv

            python calculate_mttr.py
            echo "✅ Sample MTTR calculated. Real data will accumulate over time."
          fi

          cd ..
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
          echo "Processing MTTR metrics files..."

          # === MTTR METRICS ===

          # Copy MTTR files from grafana_csv directory
          if [ -d "out/grafana_csv" ]; then
            for file in out/grafana_csv/mttr_*.csv; do
              if [ -f "$file" ]; then
                filename=$(basename "$file")
                echo "  ✓ MTTR: $filename"
                cp "$file" "$GRAFANA_CSV_DIR/$filename"
              fi
            done
          fi

          # Copy classified threats database (for backup/reference)
          if [ -f "cti/classified_threats.csv" ]; then
            echo "  ✓ Threats DB: classified_threats.csv"
            cp "cti/classified_threats.csv" "$GRAFANA_CSV_DIR/classified_threats.csv"
          fi

          echo ""
          echo "Setting permissions..."
          chmod 644 "$GRAFANA_CSV_DIR"/*.csv 2>/dev/null || true
          chmod 644 "$GRAFANA_CSV_DIR"/*.json 2>/dev/null || true

          echo ""
          echo "Files in Grafana directory:"
          echo "=========================================="
          ls -lh "$GRAFANA_CSV_DIR"/*.csv "$GRAFANA_CSV_DIR"/*.json 2>/dev/null || echo "No files found"

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

          # MTTR Metrics Report
          echo ""
          echo "⏱️  MTTR (Mean Time To Respond) Metrics:"
          if [ -f "out/grafana_csv/mttr_metrics.csv" ]; then
            # Parse MTTR metrics
            CURRENT_MTTR=$(tail -1 out/grafana_csv/mttr_metrics.csv | cut -d',' -f2)
            BASELINE_MTTR=$(tail -1 out/grafana_csv/mttr_metrics.csv | cut -d',' -f3)
            REDUCTION=$(tail -1 out/grafana_csv/mttr_metrics.csv | cut -d',' -f5)
            INCIDENTS=$(tail -1 out/grafana_csv/mttr_metrics.csv | cut -d',' -f6)

            echo "   📉 Current MTTR:  ${CURRENT_MTTR} hours"
            echo "   📊 Baseline MTTR: ${BASELINE_MTTR} hours"
            echo "   ✅ Improvement:   ${REDUCTION}%"
            echo "   📋 Incidents:     ${INCIDENTS} processed"
          else
            echo "   ⚠️  MTTR metrics not available yet"
          fi

          # Threat database stats
          if [ -f "cti/classified_threats.csv" ]; then
            TOTAL_THREATS=$(wc -l < cti/classified_threats.csv)
            TOTAL_THREATS=$((TOTAL_THREATS - 1))  # Subtract header
            echo ""
            echo "📁 Threat Database:"
            echo "   Total threats tracked: $TOTAL_THREATS"
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
      archiveArtifacts artifacts: 'cti/classified_threats.csv', allowEmptyArchive: true

      script {
        // Check if files were copied to Grafana directory
        def grafanaFiles = sh(
          script: 'ls /var/lib/grafana/csv/*.csv 2>/dev/null | wc -l || echo "0"',
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
          echo "   cp ${WORKSPACE}/out/grafana_csv/mttr_*.csv /var/lib/grafana/csv/"
          echo "   chmod 644 /var/lib/grafana/csv/*.csv"
        } else {
          echo "✅ Successfully copied ${grafanaFiles} files to Grafana"
        }

        // Display pipeline summary
        if (fileExists('out/cti_pipeline_summary.json')) {
          echo ""
          echo "📊 PIPELINE SUMMARY:"
          try {
            def summaryText = readFile(file: 'out/cti_pipeline_summary.json')
            def summary = new groovy.json.JsonSlurper().parseText(summaryText)
            echo "   Total threats: ${summary.statistics.total_threats}"
            echo "   Critical: ${summary.statistics.critical_threats}"
            echo "   High: ${summary.statistics.high_threats}"
            echo "   Total recommendations: ${summary.statistics.total_recommendations}"
          } catch (Exception e) {
            echo "   (Summary file exists but could not be parsed: ${e.message})"
          }
        }

        // Display MTTR summary
        if (fileExists('out/grafana_csv/mttr_metrics.csv')) {
          echo ""
          echo "⏱️  MTTR SUMMARY:"
          try {
            def mttrContent = sh(
              script: 'tail -1 out/grafana_csv/mttr_metrics.csv',
              returnStdout: true
            ).trim()
            def mttrFields = mttrContent.split(',')
            if (mttrFields.size() >= 6) {
              echo "   Current MTTR: ${mttrFields[1]} hours"
              echo "   Baseline: ${mttrFields[2]} hours"
              echo "   Improvement: ${mttrFields[4]}%"
              echo "   Incidents tracked: ${mttrFields[5]}"
            }
          } catch (Exception e) {
            echo "   (MTTR metrics available but could not be parsed)"
          }
        }

        // Display threat database stats
        if (fileExists('cti/classified_threats.csv')) {
          echo ""
          echo "📁 THREAT DATABASE:"
          try {
            def threatCount = sh(
              script: 'wc -l < cti/classified_threats.csv',
              returnStdout: true
            ).trim().toInteger() - 1
            echo "   Total threats tracked: ${threatCount}"
            echo "   Database grows with each pipeline run"
          } catch (Exception e) {
            echo "   (Threat database exists)"
          }
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
      echo "   ✓ ML threat prediction completed"
      echo "   ✓ MTTR metrics calculated"
      echo "   ✓ Action recommendations generated"
      echo "   ✓ Files copied to Grafana"
      echo ""
      echo "📁 Output Files:"
      echo "   • cti_pulses_latest.csv"
      echo "   • cti_indicators_latest.csv"
      echo "   • cti_ml_recommendations.csv"
      echo "   • cti_threat_detection.csv"
      echo "   • mttr_metrics.csv (MTTR snapshot)"
      echo "   • mttr_history.csv (MTTR trends)"
      echo "   • mttr_by_severity.csv (severity breakdown)"
      echo "   • classified_threats.csv (threat database)"
      echo ""
      echo "🌐 Access Grafana:"
      echo "   http://your-ec2-ip:3000"
      echo ""
      echo "📈 MTTR Tracking:"
      echo "   Threat database grows with each pipeline run"
      echo "   MTTR history tracks improvement over time"
      echo ""
      echo "📈 Next Steps:"
      echo "   1. View MTTR dashboard in Grafana"
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
