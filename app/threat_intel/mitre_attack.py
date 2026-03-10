"""
MITRE ATT&CK Framework Integration
Maps detected attack patterns to MITRE ATT&CK techniques for threat intelligence
"""

from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class MitreAttackMapper:
    """
    Maps attack patterns to MITRE ATT&CK techniques
    Provides context about attack tactics and mitigation strategies
    """
    
    def __init__(self):
        # Map attack categories to MITRE ATT&CK technique IDs
        self.technique_mappings = {
            'brute_force': {
                'techniques': ['T1110'],
                'tactics': ['Credential Access'],
                'severity': 'HIGH'
            },
            'credential_access': {
                'techniques': ['T1110', 'T1187', 'T1056'],
                'tactics': ['Credential Access'],
                'severity': 'HIGH'
            },
            'reconnaissance': {
                'techniques': ['T1592', 'T1589', 'T1590'],
                'tactics': ['Reconnaissance'],
                'severity': 'MEDIUM'
            },
            'lateral_movement': {
                'techniques': ['T1021', 'T1091'],
                'tactics': ['Lateral Movement'],
                'severity': 'CRITICAL'
            },
            'exfiltration': {
                'techniques': ['T1020', 'T1030', 'T1048'],
                'tactics': ['Exfiltration'],
                'severity': 'CRITICAL'
            },
            'defense_evasion': {
                'techniques': ['T1548', 'T1197', 'T1036'],
                'tactics': ['Defense Evasion'],
                'severity': 'HIGH'
            },
            'persistence': {
                'techniques': ['T1098', 'T1197', 'T1547'],
                'tactics': ['Persistence'],
                'severity': 'HIGH'
            },
            'command_control': {
                'techniques': ['T1071', 'T1092', 'T1571'],
                'tactics': ['Command and Control'],
                'severity': 'CRITICAL'
            }
        }
        
        # MITRE ATT&CK technique details
        self.technique_details = {
            'T1110': {
                'name': 'Brute Force',
                'url': 'https://attack.mitre.org/techniques/T1110/',
                'description': 'Adversary attempts to access accounts through repeated logins',
                'mitigation': 'Implement account lockout after failed attempts, MFA, strong password policies'
            },
            'T1187': {
                'name': 'Forced Authentication',
                'url': 'https://attack.mitre.org/techniques/T1187/',
                'description': 'Adversary coerces targets to authenticate to attacker-controlled server',
                'mitigation': 'Disable LLMNR and NetBIOS, implement network segmentation'
            },
            'T1592': {
                'name': 'Gather Victim Host Information',
                'url': 'https://attack.mitre.org/techniques/T1592/',
                'description': 'Adversary gathers information about target systems',
                'mitigation': 'Limit public information exposure, implement network monitoring'
            },
            'T1021': {
                'name': 'Remote Services',
                'url': 'https://attack.mitre.org/techniques/T1021/',
                'description': 'Adversary uses remote services for lateral movement',
                'mitigation': 'Disable unnecessary remote services, implement MFA, restrict network access'
            },
            'T1048': {
                'name': 'Exfiltration Over Alternative Protocol',
                'url': 'https://attack.mitre.org/techniques/T1048/',
                'description': 'Adversary exfiltrates data using non-standard protocols',
                'mitigation': 'Implement DLP, network segmentation, egress filtering'
            },
            'T1036': {
                'name': 'Masquerading',
                'url': 'https://attack.mitre.org/techniques/T1036/',
                'description': 'Adversary disguises malware to evade detection',
                'mitigation': 'Implement file hashing, code signing verification, behavioral monitoring'
            }
        }
    
    def map_attack_to_techniques(self, attack_category: str) -> Dict:
        """
        Map attack category to MITRE ATT&CK techniques
        
        Args:
            attack_category: Category of attack detected
        
        Returns:
            Dictionary with MITRE ATT&CK techniques and details
        """
        if attack_category not in self.technique_mappings:
            return {'error': f'Unknown attack category: {attack_category}'}
        
        mapping = self.technique_mappings[attack_category]
        techniques = []
        
        for technique_id in mapping['techniques']:
            details = self.technique_details.get(technique_id, {})
            techniques.append({
                'id': technique_id,
                'name': details.get('name', 'Unknown'),
                'url': details.get('url', ''),
                'description': details.get('description', ''),
                'mitigation': details.get('mitigation', '')
            })
        
        return {
            'attack_category': attack_category,
            'severity': mapping['severity'],
            'tactics': mapping['tactics'],
            'techniques': techniques,
            'detection_context': self._get_detection_guidance(attack_category)
        }
    
    def _get_detection_guidance(self, attack_category: str) -> str:
        """Get guidance on detecting specific attack type"""
        
        guidance_map = {
            'brute_force': 'Monitor for multiple failed authentication attempts, account lockouts, and unusual login patterns from single source',
            'credential_access': 'Monitor credential dumping tools, phishing campaigns, and social engineering attempts',
            'reconnaissance': 'Monitor network scanning tools, DNS queries for internal resources, and information gathering',
            'lateral_movement': 'Monitor network traffic between systems, RDP/SSH connections, and privilege escalation attempts',
            'exfiltration': 'Monitor large data transfers, DNS tunneling, and data moving to external networks',
            'defense_evasion': 'Monitor process injection, DLL loading anomalies, and removal of security tools',
            'persistence': 'Monitor scheduled tasks, registry modifications, and startup folder changes',
            'command_control': 'Monitor unusual network connections, DNS queries to suspicious domains, and C2 beacon traffic'
        }
        
        return guidance_map.get(attack_category, 'Monitor for suspicious activity')
    
    def get_all_tactics(self) -> List[Dict]:
        """
        Get list of all MITRE ATT&CK tactics
        
        Returns:
            List of tactics with associated techniques
        """
        unique_tactics = set()
        for mapping in self.technique_mappings.values():
            unique_tactics.update(mapping['tactics'])
        
        return sorted(list(unique_tactics))
    
    def correlate_attacks(self, attack_categories: List[str]) -> Dict:
        """
        Correlate multiple attacks to identify attack campaigns
        
        Args:
            attack_categories: List of detected attack categories
        
        Returns:
            Correlation analysis with severity and recommended actions
        """
        all_techniques = set()
        max_severity = 'LOW'
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        
        for category in attack_categories:
            if category in self.technique_mappings:
                mapping = self.technique_mappings[category]
                all_techniques.update(mapping['techniques'])
                
                # Update max severity
                category_severity = mapping['severity']
                if severity_order.get(category_severity, 0) > severity_order.get(max_severity, 0):
                    max_severity = category_severity
        
        return {
            'detected_categories': attack_categories,
            'total_techniques': len(all_techniques),
            'correlated_severity': max_severity,
            'recommendation': self._get_incident_recommendation(max_severity),
            'suggests_campaign': len(attack_categories) > 2
        }
    
    def _get_incident_recommendation(self, severity: str) -> str:
        """Get recommended incident response action based on severity"""
        
        recommendations = {
            'CRITICAL': 'Immediate incident response required. Isolate affected systems, escalate to security team, engage law enforcement if needed',
            'HIGH': 'Escalate to security team immediately. Begin investigation and implement containment measures',
            'MEDIUM': 'Alert security team. Monitor for escalation and implement mitigating controls',
            'LOW': 'Document and monitor. Review logs for related activities'
        }
        
        return recommendations.get(severity, 'Review and assess')
