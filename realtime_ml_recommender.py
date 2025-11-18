#!/usr/bin/env python3
"""
Real-Time ML Action Recommender - Integrated with OTX Data
Processes actual OTX pulses and generates ML-based action recommendations
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import json
import os
import sys
from datetime import datetime

# Import model paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cti'))
from cti.model_utils import REALTIME_RECOMMENDER_PATH

class RealTimeMLRecommender:
    """ML-based action recommendation system for OTX threats"""
    
    def __init__(self):
        self.action_model = None
        self.scaler = StandardScaler()
        self.action_encoder = LabelEncoder()
        
        # Possible actions the model can recommend
        self.possible_actions = [
            'BLOCK_IPS',
            'BLOCK_DOMAINS',
            'BLOCK_HASHES',
            'ISOLATE_SYSTEMS',
            'ACTIVATE_IR',
            'THREAT_HUNT',
            'SCAN_ENDPOINTS',
            'ANALYZE_MALWARE',
            'REVIEW_LOGS',
            'UPDATE_SIGNATURES',
            'MONITOR_ALERTS',
            'DOCUMENT_INCIDENT',
            'NOTIFY_TEAM',
            'ESCALATE_CISO',
            'CAPTURE_FORENSICS',
            'RESET_CREDENTIALS',
            'PATCH_SYSTEMS',
            'NETWORK_SEGMENT'
        ]
        
        self.action_encoder.fit(self.possible_actions)
    
    def extract_threat_features(self, threat_data):
        """Extract features from OTX threat data for ML prediction"""
        features = []
        
        # Threat characteristics
        features.append(threat_data.get('malware_probability', 0.5))  # From AndMal detector
        features.append(threat_data.get('confidence', 50) / 100)
        
        # Indicator features
        features.append(threat_data.get('indicator_count', 0))
        features.append(threat_data.get('ip_count', 0))
        features.append(threat_data.get('domain_count', 0))
        features.append(threat_data.get('hash_count', 0))
        features.append(threat_data.get('url_count', 0))
        features.append(threat_data.get('file_count', 0))
        
        # Indicator ratios
        total_iocs = max(threat_data.get('indicator_count', 1), 1)
        features.append(threat_data.get('ip_count', 0) / total_iocs)
        features.append(threat_data.get('domain_count', 0) / total_iocs)
        features.append(threat_data.get('hash_count', 0) / total_iocs)
        
        # Threat intelligence context
        features.append(1 if threat_data.get('has_adversary', 0) else 0)
        features.append(1 if threat_data.get('has_malware', 0) else 0)
        features.append(threat_data.get('attack_ids_count', 0))
        
        # TLP level
        tlp_map = {'white': 0, 'green': 1, 'amber': 2, 'red': 3}
        features.append(tlp_map.get(threat_data.get('tlp', 'white'), 0))
        
        # Temporal features
        features.append(threat_data.get('pulse_age_hours', 0))
        features.append(threat_data.get('subscription_count', 0) / 100)  # Normalize
        
        # Diversity & complexity
        indicator_diversity = sum([
            threat_data.get('ip_count', 0) > 0,
            threat_data.get('domain_count', 0) > 0,
            threat_data.get('hash_count', 0) > 0,
            threat_data.get('url_count', 0) > 0,
            threat_data.get('file_count', 0) > 0
        ])
        features.append(indicator_diversity)
        
        # Similarity score
        features.append(self._calculate_similarity_score(threat_data))
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_similarity_score(self, threat_data):
        """Calculate similarity to known threat patterns"""
        similarity = 0.0
        
        if threat_data.get('has_adversary'):
            similarity += 0.3
        if threat_data.get('has_malware'):
            similarity += 0.3
        if threat_data.get('indicator_count', 0) > 50:
            similarity += 0.2
        
        diversity = sum([
            threat_data.get('ip_count', 0) > 0,
            threat_data.get('domain_count', 0) > 0,
            threat_data.get('hash_count', 0) > 0
        ])
        if diversity >= 2:
            similarity += 0.2
        
        return min(similarity, 1.0)
    
    def train_from_synthetic_data(self, n_samples=1000):
        """Train model on synthetic data (improves as real incidents are added)"""
        print("\n🤖 Training ML Recommender on synthetic incident data...")
        print("   (Model will improve as you add real incident feedback)")
        
        np.random.seed(42)
        
        X = []
        y_actions = []
        
        for i in range(n_samples):
            malware_prob = np.random.random()
            
            # Simulate threat
            threat = {
                'malware_probability': malware_prob,
                'confidence': np.random.randint(50, 100),
                'indicator_count': np.random.randint(1, 200),
                'ip_count': np.random.randint(0, 100),
                'domain_count': np.random.randint(0, 100),
                'hash_count': np.random.randint(0, 50),
                'url_count': np.random.randint(0, 30),
                'file_count': np.random.randint(0, 20),
                'has_adversary': int(np.random.random() > 0.7),
                'has_malware': int(np.random.random() > 0.6),
                'attack_ids_count': np.random.randint(0, 10),
                'tlp': np.random.choice(['white', 'green', 'amber', 'red']),
                'pulse_age_hours': np.random.random() * 48,
                'subscription_count': np.random.randint(0, 500)
            }
            
            # Determine action based on threat characteristics
            if malware_prob >= 0.9 and threat['indicator_count'] > 50:
                action = np.random.choice(['ACTIVATE_IR', 'ISOLATE_SYSTEMS', 'CAPTURE_FORENSICS'])
            elif malware_prob >= 0.7:
                if threat['ip_count'] > 20:
                    action = 'BLOCK_IPS'
                elif threat['domain_count'] > 20:
                    action = 'BLOCK_DOMAINS'
                elif threat['hash_count'] > 10:
                    action = 'BLOCK_HASHES'
                else:
                    action = 'THREAT_HUNT'
            elif malware_prob >= 0.5:
                action = np.random.choice(['MONITOR_ALERTS', 'REVIEW_LOGS', 'SCAN_ENDPOINTS'])
            else:
                action = np.random.choice(['DOCUMENT_INCIDENT', 'MONITOR_ALERTS'])
            
            features = self.extract_threat_features(threat)
            X.append(features[0])
            y_actions.append(action)
        
        X = np.array(X)
        y_encoded = self.action_encoder.transform(y_actions)
        
        # Train model
        X_scaled = self.scaler.fit_transform(X)
        
        self.action_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
        
        self.action_model.fit(X_scaled, y_encoded)
        
        print(f"   ✅ Model trained on {len(X)} synthetic incidents")
        
        # Feature importance
        feature_names = [
            'malware_prob', 'confidence', 'total_iocs', 
            'ip_count', 'domain_count', 'hash_count', 'url_count', 'file_count',
            'ip_ratio', 'domain_ratio', 'hash_ratio',
            'has_adversary', 'has_malware', 'attack_ids',
            'tlp_level', 'pulse_age', 'subscriptions', 'diversity', 'similarity'
        ]
        
        importances = self.action_model.feature_importances_
        top_features = sorted(zip(feature_names, importances), 
                            key=lambda x: x[1], reverse=True)[:5]
        
        print(f"\n   Top 5 features driving recommendations:")
        for i, (feature, importance) in enumerate(top_features, 1):
            print(f"      {i}. {feature}: {importance:.4f}")
    
    def predict_actions_realtime(self, threat_data, top_k=5):
        """Predict top K actions for a threat in real-time"""
        
        if self.action_model is None:
            print("⚠️  Model not trained. Training now...")
            self.train_from_synthetic_data()
        
        # Extract features
        features = self.extract_threat_features(threat_data)
        features_scaled = self.scaler.transform(features)
        
        # Get action probabilities
        action_probs = self.action_model.predict_proba(features_scaled)[0]
        
        # Get top K actions
        top_k_indices = np.argsort(action_probs)[-top_k:][::-1]
        
        recommendations = []
        for idx in top_k_indices:
            action = self.action_encoder.classes_[idx]
            probability = action_probs[idx]
            
            action_details = self._get_action_details(action, threat_data, probability)
            recommendations.append(action_details)
        
        return recommendations
    
    def _get_action_details(self, action, threat_data, confidence):
        """Get detailed information about recommended action"""
        
        action_info = {
            'BLOCK_IPS': {
                'category': 'BLOCKING',
                'description': f"Block {threat_data.get('ip_count', 0)} malicious IP addresses",
                'tools': ['Firewall', 'IPS', 'Network Access Control'],
                'estimated_time': '5-15 minutes',
                'priority': 1 if threat_data.get('malware_probability', 0) > 0.7 else 2
            },
            'BLOCK_DOMAINS': {
                'category': 'BLOCKING',
                'description': f"Block {threat_data.get('domain_count', 0)} malicious domains",
                'tools': ['DNS Filter', 'Web Proxy', 'Firewall'],
                'estimated_time': '5-15 minutes',
                'priority': 1 if threat_data.get('malware_probability', 0) > 0.7 else 2
            },
            'BLOCK_HASHES': {
                'category': 'ENDPOINT_PROTECTION',
                'description': f"Block {threat_data.get('hash_count', 0)} malicious file hashes",
                'tools': ['EDR', 'Antivirus', 'File Integrity Monitoring'],
                'estimated_time': '10-20 minutes',
                'priority': 2
            },
            'ISOLATE_SYSTEMS': {
                'category': 'INCIDENT_RESPONSE',
                'description': 'Isolate affected systems from network',
                'tools': ['Network Access Control', 'EDR', 'Switch Management'],
                'estimated_time': '5-10 minutes',
                'priority': 1
            },
            'ACTIVATE_IR': {
                'category': 'INCIDENT_RESPONSE',
                'description': 'Activate incident response team and procedures',
                'tools': ['IR Platform', 'Communication Tools', 'Ticketing'],
                'estimated_time': '15-30 minutes',
                'priority': 1
            },
            'THREAT_HUNT': {
                'category': 'THREAT_HUNTING',
                'description': f"Hunt for TTPs related to this threat",
                'tools': ['EDR', 'SIEM', 'Network Traffic Analysis'],
                'estimated_time': '1-2 hours',
                'priority': 2
            },
            'SCAN_ENDPOINTS': {
                'category': 'ENDPOINT_PROTECTION',
                'description': 'Scan all endpoints for malware indicators',
                'tools': ['Antivirus', 'EDR', 'Vulnerability Scanner'],
                'estimated_time': '30-60 minutes',
                'priority': 2
            },
            'ANALYZE_MALWARE': {
                'category': 'MALWARE_RESPONSE',
                'description': 'Analyze malware samples in sandbox',
                'tools': ['Sandbox', 'Reverse Engineering Tools', 'YARA'],
                'estimated_time': '2-4 hours',
                'priority': 3
            },
            'REVIEW_LOGS': {
                'category': 'INVESTIGATION',
                'description': 'Review security logs for IOC matches',
                'tools': ['SIEM', 'Log Management', 'Threat Intelligence Platform'],
                'estimated_time': '30-60 minutes',
                'priority': 3
            },
            'UPDATE_SIGNATURES': {
                'category': 'PREVENTION',
                'description': 'Update security signatures and rules',
                'tools': ['IPS', 'Antivirus', 'EDR', 'SIEM'],
                'estimated_time': '15-30 minutes',
                'priority': 3
            },
            'MONITOR_ALERTS': {
                'category': 'MONITORING',
                'description': 'Configure enhanced monitoring and alerts',
                'tools': ['SIEM', 'Security Monitoring', 'Alerting Platform'],
                'estimated_time': '20-40 minutes',
                'priority': 3
            },
            'DOCUMENT_INCIDENT': {
                'category': 'DOCUMENTATION',
                'description': 'Document incident details and response',
                'tools': ['Ticketing System', 'Wiki', 'Knowledge Base'],
                'estimated_time': '15-30 minutes',
                'priority': 4
            },
            'NOTIFY_TEAM': {
                'category': 'COMMUNICATION',
                'description': 'Notify security team and stakeholders',
                'tools': ['Email', 'Slack', 'Teams', 'SMS'],
                'estimated_time': '5-10 minutes',
                'priority': 2
            },
            'ESCALATE_CISO': {
                'category': 'ESCALATION',
                'description': 'Escalate to CISO and executive leadership',
                'tools': ['Communication Platform', 'Executive Dashboard'],
                'estimated_time': '10-15 minutes',
                'priority': 1
            },
            'CAPTURE_FORENSICS': {
                'category': 'FORENSICS',
                'description': 'Capture forensic evidence for investigation',
                'tools': ['Forensic Tools', 'Memory Dumper', 'Disk Imager'],
                'estimated_time': '1-3 hours',
                'priority': 2
            },
            'RESET_CREDENTIALS': {
                'category': 'CONTAINMENT',
                'description': 'Reset potentially compromised credentials',
                'tools': ['Active Directory', 'IAM', 'Password Manager'],
                'estimated_time': '30-60 minutes',
                'priority': 2
            },
            'PATCH_SYSTEMS': {
                'category': 'REMEDIATION',
                'description': 'Patch vulnerable systems immediately',
                'tools': ['Patch Management', 'WSUS', 'Configuration Management'],
                'estimated_time': '1-4 hours',
                'priority': 2
            },
            'NETWORK_SEGMENT': {
                'category': 'CONTAINMENT',
                'description': 'Implement additional network segmentation',
                'tools': ['Firewall', 'Network Access Control', 'VLAN Management'],
                'estimated_time': '2-6 hours',
                'priority': 3
            }
        }
        
        details = action_info.get(action, {
            'category': 'GENERAL',
            'description': action.replace('_', ' ').title(),
            'tools': ['Security Tools'],
            'estimated_time': '30 minutes',
            'priority': 3
        })
        
        details['action'] = action
        details['ml_confidence'] = float(confidence)
        details['confidence_level'] = (
            'HIGH' if confidence > 0.7 else
            'MEDIUM' if confidence > 0.4 else
            'LOW'
        )
        details['recommended_order'] = details['priority']
        
        return details
    
    def save_model(self, output_dir='models'):
        """Save trained model"""
        os.makedirs(output_dir, exist_ok=True)
        
        model_data = {
            'action_model': self.action_model,
            'action_encoder': self.action_encoder,
            'scaler': self.scaler,
            'possible_actions': self.possible_actions,
            'trained_at': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, f'{output_dir}/realtime_ml_recommender.pkl')
        print(f"\n💾 Model saved: {output_dir}/realtime_ml_recommender.pkl")
    
    def load_model(self, model_path=None):
        """Load trained model"""
        if model_path is None:
            model_path = REALTIME_RECOMMENDER_PATH

        if not os.path.exists(model_path):
            print(f"⚠️  Model not found at {model_path}")
            print("   Training new model...")
            self.train_from_synthetic_data()
            self.save_model()
            return

        model_data = joblib.load(model_path)
        self.action_model = model_data['action_model']
        self.action_encoder = model_data['action_encoder']
        self.scaler = model_data['scaler']
        self.possible_actions = model_data['possible_actions']
        print(f"✅ Loaded ML recommender from {model_path}")


def process_otx_data_with_ml_recommendations():
    """
    Main function: Load OTX data and generate ML recommendations
    """
    print("="*70)
    print("REAL-TIME ML ACTION RECOMMENDER - PROCESSING OTX DATA")
    print("="*70)
    
    # Check for OTX ML features
    ml_features_file = 'out/cti_ml_features_latest.csv'
    
    if not os.path.exists(ml_features_file):
        print(f"\n❌ Error: {ml_features_file} not found")
        print("   Run otx_fetch.py first to collect OTX data")
        return
    
    # Load OTX data
    print(f"\n📂 Loading OTX threat data from {ml_features_file}...")
    otx_df = pd.read_csv(ml_features_file)
    print(f"   ✅ Loaded {len(otx_df)} OTX threats")
    
    # Initialize ML recommender
    recommender = RealTimeMLRecommender()
    
    # Load or train model
    if os.path.exists(REALTIME_RECOMMENDER_PATH):
        recommender.load_model(REALTIME_RECOMMENDER_PATH)
    else:
        print("\n🤖 No existing model found. Training new model...")
        recommender.train_from_synthetic_data(n_samples=1000)
        recommender.save_model()
    
    # Process each threat
    print(f"\n🔮 Generating ML recommendations for {len(otx_df)} threats...")
    
    all_recommendations = []
    
    for idx, threat in otx_df.iterrows():
        # Convert OTX data to threat_data format
        threat_data = {
            'pulse_id': threat['pulse_id'],
            'pulse_name': threat['pulse_name'],
            'malware_probability': 0.5,  # Default (will be replaced by AndMal detector)
            'confidence': 50,
            'indicator_count': threat['indicator_count'],
            'ip_count': threat['ip_count'],
            'domain_count': threat['domain_count'],
            'hash_count': threat['hash_count'],
            'url_count': threat['url_count'],
            'file_count': threat['file_count'],
            'has_adversary': threat['has_adversary'],
            'adversary': threat.get('adversary', ''),
            'has_malware': threat['has_malware'],
            'malware_families': threat.get('malware_families', ''),
            'attack_ids_count': threat['attack_ids_count'],
            'tlp': threat['tlp'],
            'tlp_level': threat['tlp_level'],
            'pulse_age_hours': threat['pulse_age_hours'],
            'subscription_count': 0  # Not in ML features, use default
        }
        
        # Get ML recommendations
        recommendations = recommender.predict_actions_realtime(threat_data, top_k=5)
        
        # Save recommendations
        for rec in recommendations:
            all_recommendations.append({
                'pulse_id': threat['pulse_id'],
                'pulse_name': threat['pulse_name'],
                'tlp': threat['tlp'],
                'adversary': threat.get('adversary', ''),
                'malware_families': threat.get('malware_families', ''),
                'indicator_count': threat['indicator_count'],
                'action': rec['action'],
                'action_category': rec['category'],
                'action_description': rec['description'],
                'ml_confidence': rec['ml_confidence'],
                'confidence_level': rec['confidence_level'],
                'priority': rec['priority'],
                'estimated_time': rec['estimated_time'],
                'tools_required': ', '.join(rec['tools']),
                'timestamp': datetime.now().isoformat()
            })
    
    # Save recommendations
    rec_df = pd.DataFrame(all_recommendations)
    output_file = 'out/ml_action_recommendations.csv'
    rec_df.to_csv(output_file, index=False)
    
    print(f"\n✅ Generated {len(all_recommendations)} ML-based action recommendations")
    print(f"💾 Saved to: {output_file}")
    
    # Summary statistics
    print(f"\n📊 Recommendation Summary:")
    print(f"   Total threats analyzed: {len(otx_df)}")
    print(f"   Total actions recommended: {len(all_recommendations)}")
    print(f"   Avg actions per threat: {len(all_recommendations) / len(otx_df):.1f}")
    
    print(f"\n   Top 5 Recommended Actions:")
    top_actions = rec_df['action'].value_counts().head(5)
    for action, count in top_actions.items():
        print(f"      {action}: {count} times")
    
    print(f"\n   Actions by Category:")
    categories = rec_df['action_category'].value_counts()
    for category, count in categories.items():
        print(f"      {category}: {count}")
    
    print(f"\n   Confidence Distribution:")
    conf_dist = rec_df['confidence_level'].value_counts()
    for level, count in conf_dist.items():
        print(f"      {level}: {count}")
    
    # Create summary JSON
    summary = {
        'timestamp': datetime.now().isoformat(),
        'model': 'RealTimeMLRecommender',
        'total_threats': len(otx_df),
        'total_recommendations': len(all_recommendations),
        'avg_recommendations_per_threat': round(len(all_recommendations) / len(otx_df), 2),
        'top_actions': top_actions.to_dict(),
        'action_categories': categories.to_dict(),
        'confidence_distribution': conf_dist.to_dict()
    }
    
    summary_file = 'out/ml_recommendations_summary.json'
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"💾 Summary saved to: {summary_file}")
    
    # Show sample recommendations
    print(f"\n" + "="*70)
    print("SAMPLE RECOMMENDATIONS (Top 3 Threats)")
    print("="*70)
    
    for i, (pulse_id, group) in enumerate(rec_df.groupby('pulse_id').head(3).groupby('pulse_id')):
        if i >= 3:
            break
        
        pulse_name = group.iloc[0]['pulse_name']
        print(f"\n🎯 Threat {i+1}: {pulse_name}")
        print(f"   TLP: {group.iloc[0]['tlp']} | IOCs: {group.iloc[0]['indicator_count']}")
        
        for j, rec in group.iterrows():
            print(f"\n   [{rec['priority']}] {rec['action']}")
            print(f"      {rec['action_description']}")
            print(f"      ML Confidence: {rec['ml_confidence']:.1%} ({rec['confidence_level']})")
            print(f"      Time: {rec['estimated_time']} | Tools: {rec['tools_required']}")
    
    print(f"\n" + "="*70)
    print("✅ ML RECOMMENDATION GENERATION COMPLETE!")
    print("="*70)
    print(f"\n📁 Output Files:")
    print(f"   • {output_file}")
    print(f"   • {summary_file}")
    print(f"\n🚀 Next: Copy to Grafana for visualization")
    print(f"   cp {output_file} /var/lib/grafana/csv/ml_action_recommendations.csv")
    print("="*70)


if __name__ == "__main__":
    process_otx_data_with_ml_recommendations()