#!/usr/bin/env python3
"""
CTI Action Recommendation Engine
Provides actionable recommendations based on ML predictions and threat intelligence
"""

import os
import pandas as pd
import json
from datetime import datetime

class ActionRecommendationEngine:
    """
    Generates actionable recommendations for SOC teams based on:
    - ML malware probability
    - Threat priority
    - Indicator types (IPs, domains, hashes)
    - Known adversaries and malware families
    - TLP restrictions
    """
    
    def __init__(self):
        self.action_matrix = self._build_action_matrix()
    
    def _build_action_matrix(self):
        """Define action recommendations based on threat characteristics"""
        return {
            'CRITICAL': {
                'immediate_actions': [
                    'BLOCK all indicators in firewall/IPS immediately',
                    'ISOLATE affected systems from network',
                    'ACTIVATE incident response team',
                    'NOTIFY CISO and security leadership',
                    'CAPTURE forensic evidence (memory dumps, logs)',
                    'REVIEW security alerts from last 72 hours'
                ],
                'investigation_actions': [
                    'HUNT for IOCs across entire environment',
                    'ANALYZE network traffic for C2 communication',
                    'CHECK for lateral movement indicators',
                    'REVIEW access logs for compromised accounts',
                    'SCAN all endpoints with updated signatures'
                ],
                'containment_actions': [
                    'RESET credentials for potentially compromised accounts',
                    'PATCH vulnerable systems immediately',
                    'IMPLEMENT additional network segmentation',
                    'ENABLE enhanced monitoring on critical assets'
                ],
                'communication_actions': [
                    'BRIEF executive team on threat',
                    'COORDINATE with threat intelligence team',
                    'CONSIDER law enforcement notification',
                    'PREPARE incident summary for stakeholders'
                ],
                'timeline': 'IMMEDIATE (0-15 minutes)',
                'escalation': 'Executive Leadership, CISO, IR Team'
            },
            
            'HIGH': {
                'immediate_actions': [
                    'BLOCK indicators in security controls',
                    'ALERT SOC analysts for investigation',
                    'MONITOR for signs of compromise',
                    'REVIEW recent security events',
                    'PRIORITIZE threat hunting activities'
                ],
                'investigation_actions': [
                    'SEARCH SIEM for IOC matches',
                    'ANALYZE endpoint detection logs',
                    'CHECK email security for phishing attempts',
                    'REVIEW web proxy logs',
                    'CORRELATE with other threat intelligence'
                ],
                'containment_actions': [
                    'UPDATE security rules and signatures',
                    'INCREASE monitoring on high-value targets',
                    'VALIDATE backup integrity',
                    'REVIEW access control policies'
                ],
                'communication_actions': [
                    'NOTIFY security team leadership',
                    'UPDATE threat intelligence platform',
                    'SHARE IOCs with security tools',
                    'DOCUMENT investigation findings'
                ],
                'timeline': 'URGENT (15-60 minutes)',
                'escalation': 'SOC Manager, Security Team Lead'
            },
            
            'MEDIUM': {
                'immediate_actions': [
                    'ADD indicators to watchlist',
                    'CONFIGURE alerts for IOC detection',
                    'ASSIGN to analyst for review',
                    'QUEUE for threat hunting'
                ],
                'investigation_actions': [
                    'RESEARCH threat actor and campaigns',
                    'ANALYZE indicator context',
                    'CHECK for related threats',
                    'REVIEW threat intelligence reports',
                    'ASSESS potential impact'
                ],
                'containment_actions': [
                    'UPDATE threat intelligence feeds',
                    'ENHANCE detection rules',
                    'PLAN preventive measures',
                    'SCHEDULE security assessments'
                ],
                'communication_actions': [
                    'LOG in ticketing system',
                    'SHARE with SOC team',
                    'UPDATE threat dashboard',
                    'DOCUMENT in knowledge base'
                ],
                'timeline': 'STANDARD (1-4 hours)',
                'escalation': 'SOC Analyst, Tier 2 Security'
            },
            
            'LOW': {
                'immediate_actions': [
                    'DOCUMENT in threat intelligence database',
                    'ADD to monitoring baseline',
                    'SCHEDULE routine review'
                ],
                'investigation_actions': [
                    'RESEARCH threat context',
                    'EVALUATE relevance to environment',
                    'CATEGORIZE threat type',
                    'ASSESS false positive likelihood'
                ],
                'containment_actions': [
                    'MAINTAIN awareness',
                    'UPDATE threat models',
                    'REVIEW periodically',
                    'INCLUDE in threat briefings'
                ],
                'communication_actions': [
                    'LOG for records',
                    'SHARE in daily briefing',
                    'UPDATE threat catalog'
                ],
                'timeline': 'ROUTINE (4-24 hours)',
                'escalation': 'SOC Analyst'
            }
        }
    
    def get_specific_actions(self, threat_data):
        """
        Generate specific action recommendations based on threat characteristics
        
        Args:
            threat_data: dict with threat details
        
        Returns:
            dict with detailed action recommendations
        """
        priority = threat_data.get('priority', 'MEDIUM')
        malware_prob = threat_data.get('malware_probability', 0)
        indicator_count = threat_data.get('indicator_count', 0)
        has_adversary = bool(threat_data.get('adversary'))
        has_malware = bool(threat_data.get('malware_families'))
        tlp = threat_data.get('tlp', 'white')
        
        # Get base actions for priority
        base_actions = self.action_matrix.get(priority, self.action_matrix['MEDIUM'])
        
        # Customize based on threat characteristics
        specific_actions = []
        
        # === BLOCKING ACTIONS ===
        if indicator_count > 0:
            if priority in ['CRITICAL', 'HIGH']:
                specific_actions.append({
                    'category': 'BLOCKING',
                    'action': f'Block {indicator_count} indicators',
                    'details': 'Immediately add all IPs, domains, and hashes to security controls',
                    'tools': ['Firewall', 'IPS/IDS', 'EDR', 'Email Gateway', 'Web Proxy'],
                    'priority': 1,
                    'estimated_time': '5-15 minutes'
                })
            else:
                specific_actions.append({
                    'category': 'MONITORING',
                    'action': f'Monitor {indicator_count} indicators',
                    'details': 'Add to watchlist and configure alerts',
                    'tools': ['SIEM', 'Threat Intelligence Platform'],
                    'priority': 3,
                    'estimated_time': '15-30 minutes'
                })
        
        # === ADVERSARY-SPECIFIC ACTIONS ===
        if has_adversary:
            specific_actions.append({
                'category': 'THREAT_HUNTING',
                'action': f'Hunt for {threat_data["adversary"]} TTPs',
                'details': f'Search for known tactics, techniques, and procedures used by {threat_data["adversary"]}',
                'tools': ['EDR', 'SIEM', 'Network Traffic Analysis'],
                'priority': 2,
                'estimated_time': '1-2 hours',
                'references': [
                    f'MITRE ATT&CK: Search for {threat_data["adversary"]} profile',
                    'Review historical campaigns',
                    'Check for infrastructure overlaps'
                ]
            })
        
        # === MALWARE-SPECIFIC ACTIONS ===
        if has_malware:
            malware_families = threat_data['malware_families'].split(',')
            specific_actions.append({
                'category': 'MALWARE_RESPONSE',
                'action': f'Respond to {len(malware_families)} malware families',
                'details': f'Activate response procedures for: {threat_data["malware_families"]}',
                'tools': ['Antivirus', 'EDR', 'Sandbox', 'Memory Analysis'],
                'priority': 1,
                'estimated_time': '30-60 minutes',
                'tasks': [
                    'Update AV signatures',
                    'Scan all endpoints',
                    'Check for persistence mechanisms',
                    'Review process execution logs',
                    'Analyze file system changes'
                ]
            })
        
        # === NETWORK ACTIONS ===
        ip_count = threat_data.get('ip_count', 0)
        domain_count = threat_data.get('domain_count', 0)
        
        if ip_count > 0 or domain_count > 0:
            specific_actions.append({
                'category': 'NETWORK_DEFENSE',
                'action': f'Network protection: {ip_count} IPs, {domain_count} domains',
                'details': 'Implement network-level defenses',
                'tools': ['Firewall', 'DNS Filter', 'IPS', 'Network Access Control'],
                'priority': 2,
                'estimated_time': '10-20 minutes',
                'tasks': [
                    f'Block {ip_count} malicious IPs' if ip_count > 0 else None,
                    f'Sinkhole {domain_count} malicious domains' if domain_count > 0 else None,
                    'Review firewall logs for connections',
                    'Check DNS query logs',
                    'Analyze NetFlow data'
                ]
            })
        
        # === FILE HASH ACTIONS ===
        hash_count = threat_data.get('hash_count', 0)
        if hash_count > 0:
            specific_actions.append({
                'category': 'ENDPOINT_PROTECTION',
                'action': f'Endpoint scanning for {hash_count} malicious hashes',
                'details': 'Search and quarantine malicious files',
                'tools': ['EDR', 'Antivirus', 'File Integrity Monitoring'],
                'priority': 2,
                'estimated_time': '20-40 minutes',
                'tasks': [
                    'Add hashes to blacklist',
                    'Scan all endpoints',
                    'Quarantine detected files',
                    'Analyze file origins',
                    'Review execution history'
                ]
            })
        
        # === HIGH PROBABILITY SPECIFIC ===
        if malware_prob >= 0.9:
            specific_actions.append({
                'category': 'INCIDENT_RESPONSE',
                'action': 'Activate Incident Response Protocol',
                'details': f'High-confidence malware detected ({malware_prob:.1%})',
                'tools': ['IR Playbook', 'Forensics Tools', 'Communication Platform'],
                'priority': 1,
                'estimated_time': '2-4 hours',
                'tasks': [
                    'Declare security incident',
                    'Assemble IR team',
                    'Preserve evidence',
                    'Document timeline',
                    'Prepare status reports'
                ]
            })
        
        # === TLP-BASED SHARING ===
        sharing_action = self._get_sharing_recommendation(tlp)
        specific_actions.append(sharing_action)
        
        # === DOCUMENTATION ===
        specific_actions.append({
            'category': 'DOCUMENTATION',
            'action': 'Document and track response',
            'details': 'Maintain audit trail of all actions taken',
            'tools': ['Ticketing System', 'SIEM', 'Wiki/Knowledge Base'],
            'priority': 4,
            'estimated_time': '15-30 minutes',
            'tasks': [
                'Create incident ticket',
                'Log all actions taken',
                'Record timeline of events',
                'Document lessons learned',
                'Update runbooks if needed'
            ]
        })
        
        # Sort by priority
        specific_actions.sort(key=lambda x: x['priority'])
        
        return {
            'threat_summary': {
                'name': threat_data.get('pulse_name'),
                'priority': priority,
                'malware_probability': malware_prob,
                'timeline': base_actions['timeline'],
                'escalation': base_actions['escalation']
            },
            'base_actions': base_actions,
            'specific_actions': specific_actions,
            'total_estimated_time': self._calculate_total_time(specific_actions),
            'recommended_order': [a['action'] for a in specific_actions]
        }
    
    def _get_sharing_recommendation(self, tlp):
        """Get sharing recommendations based on TLP"""
        sharing_rules = {
            'red': {
                'action': 'Restricted sharing (TLP:RED)',
                'details': 'Information cannot be shared outside recipient organization',
                'allowed': 'Internal security team only',
                'forbidden': 'External sharing, automated feeds, public disclosure'
            },
            'amber': {
                'action': 'Limited sharing (TLP:AMBER)',
                'details': 'Share only with organizations in your sector/community',
                'allowed': 'Partner organizations, ISACs, trusted peers',
                'forbidden': 'Public disclosure, open-source intelligence'
            },
            'green': {
                'action': 'Community sharing (TLP:GREEN)',
                'details': 'Share within cybersecurity community',
                'allowed': 'Security community, threat intelligence platforms',
                'forbidden': 'General public disclosure'
            },
            'white': {
                'action': 'Public disclosure allowed (TLP:WHITE)',
                'details': 'Can be shared publicly without restrictions',
                'allowed': 'Public reports, social media, open-source feeds',
                'forbidden': 'None'
            }
        }
        
        rules = sharing_rules.get(tlp, sharing_rules['white'])
        
        return {
            'category': 'INFORMATION_SHARING',
            'action': rules['action'],
            'details': rules['details'],
            'tools': ['Threat Intelligence Platform', 'ISAC Portal', 'Email'],
            'priority': 5,
            'estimated_time': '10-15 minutes',
            'sharing_rules': {
                'allowed': rules['allowed'],
                'forbidden': rules['forbidden']
            }
        }
    
    def _calculate_total_time(self, actions):
        """Calculate total estimated time for all actions"""
        total_minutes = 0
        for action in actions:
            time_str = action.get('estimated_time', '0 minutes')
            # Parse "X-Y minutes" or "X-Y hours"
            if 'hour' in time_str:
                times = [int(x) for x in time_str.split()[0].split('-')]
                total_minutes += sum(times) / len(times) * 60
            else:
                times = [int(x) for x in time_str.split()[0].split('-')]
                total_minutes += sum(times) / len(times)
        
        hours = int(total_minutes // 60)
        minutes = int(total_minutes % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"


def generate_action_recommendations_csv(predictions_file, output_file):
    """Generate detailed action recommendations CSV from predictions"""
    
    print("\n" + "="*70)
    print("GENERATING ACTION RECOMMENDATIONS")
    print("="*70)
    
    # Load predictions
    df = pd.read_csv(predictions_file)
    print(f"\n📂 Loaded {len(df)} predictions")
    
    # Initialize recommendation engine
    engine = ActionRecommendationEngine()
    
    # Generate recommendations
    recommendations = []
    
    for idx, row in df.iterrows():
        threat_data = row.to_dict()
        actions = engine.get_specific_actions(threat_data)
        
        # Flatten for CSV
        for action in actions['specific_actions']:
            recommendations.append({
                'pulse_id': row['pulse_id'],
                'pulse_name': row['pulse_name'],
                'priority': row['priority'],
                'malware_probability': row['malware_probability'],
                'action_category': action['category'],
                'action': action['action'],
                'action_details': action['details'],
                'tools_required': ', '.join(action['tools']),
                'action_priority': action['priority'],
                'estimated_time': action['estimated_time'],
                'timeline': actions['threat_summary']['timeline'],
                'escalate_to': actions['threat_summary']['escalation']
            })
    
    # Convert to DataFrame
    rec_df = pd.DataFrame(recommendations)
    
    # Save
    rec_df.to_csv(output_file, index=False)
    print(f"\n✅ Saved {len(recommendations)} action recommendations to: {output_file}")
    
    # Summary
    print(f"\n📊 Action Summary:")
    print(f"   Total actions: {len(recommendations)}")
    print(f"   By category:")
    for category, count in rec_df['action_category'].value_counts().items():
        print(f"      {category}: {count}")
    
    return rec_df


if __name__ == "__main__":
    # Example usage
    example_threat = {
        'pulse_name': 'APT28 Campaign 2024',
        'priority': 'CRITICAL',
        'malware_probability': 0.94,
        'indicator_count': 156,
        'ip_count': 45,
        'domain_count': 38,
        'hash_count': 23,
        'adversary': 'APT28',
        'malware_families': 'Emotet,TrickBot',
        'tlp': 'red'
    }
    
    engine = ActionRecommendationEngine()
    recommendations = engine.get_specific_actions(example_threat)
    
    print("\n" + "="*70)
    print("EXAMPLE: ACTION RECOMMENDATIONS FOR APT28 CAMPAIGN")
    print("="*70)
    
    print(f"\n🎯 Threat: {recommendations['threat_summary']['name']}")
    print(f"   Priority: {recommendations['threat_summary']['priority']}")
    print(f"   Malware Probability: {recommendations['threat_summary']['malware_probability']:.1%}")
    print(f"   Timeline: {recommendations['threat_summary']['timeline']}")
    print(f"   Escalate to: {recommendations['threat_summary']['escalation']}")
    print(f"   Total Est. Time: {recommendations['total_estimated_time']}")
    
    print(f"\n📋 SPECIFIC ACTIONS ({len(recommendations['specific_actions'])} total):")
    
    for i, action in enumerate(recommendations['specific_actions'], 1):
        print(f"\n{i}. [{action['category']}] {action['action']}")
        print(f"   Details: {action['details']}")
        print(f"   Tools: {', '.join(action['tools'])}")
        print(f"   Priority: {action['priority']} | Time: {action['estimated_time']}")
        if 'tasks' in action and action['tasks']:
            print(f"   Tasks:")
            for task in action['tasks']:
                if task:
                    print(f"      • {task}")
    
    print("\n" + "="*70)
    
    # Generate for all predictions
    if os.path.exists('out/otx_andmal_predictions.csv'):
        generate_action_recommendations_csv(
            'out/otx_andmal_predictions.csv',
            'out/action_recommendations.csv'
        )