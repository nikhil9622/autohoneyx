"""
Honeypot Evasion Detection
Detects when attackers are trying to avoid honeypot traps using various techniques
"""

import re
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class HoneypotEvasionDetector:
    """
    Detects evasion techniques used by sophisticated attackers
    Identifies reconnaissance, fingerprinting, and anti-honeypot tactics
    """
    
    def __init__(self):
        # Evasion patterns and their scoring
        self.evasion_patterns = {
            'timeout_detection': {
                'description': 'Attempts to detect honeypot through timeout behavior',
                'patterns': [
                    r'timeout|sleep|\bwait\b|delay',
                    r'ping.*127\.0\.0\.1|ping.*localhost',
                    r'date.*time|uptime',
                    r'sleep\s*\d+',
                    r'time\.time\(\)|time\.perf_counter'
                ],
                'score': 0.6,
                'severity': 'MEDIUM'
            },
            'fingerprint_detection': {
                'description': 'Attempts to fingerprint honeypot against known tools',
                'patterns': [
                    r'\bhoneypot\b|\bhoneyclient\b|\bdecoy\b',
                    r'\bsuricata\b|\bsnort\b|\bbro\b|\bzeek\b|\bcowrie\b',
                    r'\bdocker\b|\bvm\b|\bvirtualbox\b|\bvmware\b|\bvirtualmachine\b',
                    r'is_docker|in_docker|in_vm|check_sandbox',
                    r'cpuid.*hyperv|hyperv-specific',
                    r'gethostname.*docker',
                    r'/.dockerenv|/proc/1/cgroup.*docker'
                ],
                'score': 0.8,
                'severity': 'HIGH'
            },
            'evasion_commands': {
                'description': 'Reconnaissance commands to identify honeypot environment',
                'patterns': [
                    r'\bwhoami\b|\buname\s*-a|\bid\b',
                    r'\bpsycopg\b|\bpython.*socket',
                    r'\bnc\s*-zv|\btelnet\b.*\s+22',
                    r'\bnmap\b|\bmasscan\b|\bnetdiscover\b',
                    r'traceroute|tracert|pathping',
                    r'\bips list\b|\barp -a\b',
                    r'ifconfig|ipconfig /all',
                    r'netstat -an|ss -an|netstat -tulpn'
                ],
                'score': 0.7,
                'severity': 'HIGH'
            },
            'anti_analysis': {
                'description': 'Attempts to disable or evade security monitoring',
                'patterns': [
                    r'disable.*monitoring|kill.*process',
                    r'disable.*firewall|disable.*av|disable.*antivirus',
                    r'UAC.*disable|registry.*delete.*security',
                    r'taskkill.*svchost|taskkill.*systemd',
                    r'stop.*antivirus|service.*stop.*protection'
                ],
                'score': 0.9,
                'severity': 'CRITICAL'
            },
            'logic_bombs': {
                'description': 'Attempts to harm honeypot if detected',
                'patterns': [
                    r'if.*detect.*honeypot.*then',
                    r'if is_honeypot.*delete|if in_sandbox.*wipe',
                    r'system\(.*rm -rf|system\(.*format',
                    r'Process.*GetCurrentProcess.*Exit'
                ],
                'score': 0.95,
                'severity': 'CRITICAL'
            }
        }
    
    def detect_evasion_attempts(
        self,
        user_input: str,
        user_agent: str = None,
        source_ip: str = None
    ) -> Dict:
        """
        Detect if attacker is trying to evade honeypot
        
        Args:
            user_input: User command or request body
            user_agent: HTTP user agent string
            source_ip: Source IP address
        
        Returns:
            Dictionary with evasion analysis
        """
        
        combined_input = str(user_input or '') + ' ' + str(user_agent or '')
        
        evasion_score = 0.0
        detected_techniques = []
        matched_patterns = []
        
        # Analyze against each evasion pattern category
        for technique, config in self.evasion_patterns.items():
            technique_score = 0.0
            
            for pattern in config['patterns']:
                try:
                    if re.search(pattern, combined_input, re.IGNORECASE):
                        technique_score = config['score']
                        matched_patterns.append({
                            'technique': technique,
                            'pattern': pattern,
                            'severity': config['severity']
                        })
                        break  # Only count once per technique
                except re.error:
                    logger.warning(f"Invalid regex pattern: {pattern}")
                    continue
            
            if technique_score > 0:
                evasion_score += technique_score
                detected_techniques.append({
                    'technique': technique,
                    'description': config['description'],
                    'score': technique_score,
                    'severity': config['severity']
                })
        
        # Normalize score to 0-1
        aggregated_score = min(evasion_score / len(self.evasion_patterns), 1.0) if self.evasion_patterns else 0.0
        
        return {
            'is_evasion_attempt': aggregated_score > 0.4,
            'evasion_score': round(aggregated_score, 2),
            'risk_level': self._score_to_risk_level(aggregated_score),
            'techniques_detected': detected_techniques,
            'matched_patterns': matched_patterns,
            'recommendation': self._get_evasion_recommendation(aggregated_score),
            'source_ip': source_ip
        }
    
    def _score_to_risk_level(self, score: float) -> str:
        """Convert evasion score to risk level"""
        if score > 0.8:
            return 'CRITICAL'
        elif score > 0.6:
            return 'HIGH'
        elif score > 0.4:
            return 'MEDIUM'
        elif score > 0.2:
            return 'LOW'
        else:
            return 'INFO'
    
    def _get_evasion_recommendation(self, score: float) -> str:
        """Get recommended action based on evasion score"""
        
        if score > 0.8:
            return 'Immediate alerts: Sophisticated attacker detected. Capture all interaction data and escalate'
        elif score > 0.6:
            return 'High priority: Attacker attempting evasion. Increase monitoring and prepare incident response'
        elif score > 0.4:
            return 'Medium priority: Some evasion signs detected. Enhance logging and continue honeypot engagement'
        elif score > 0.2:
            return 'Low priority: Minor evasion characteristics. Monitor for escalation'
        else:
            return 'Standard monitoring: Continue normal honeypot operation'
    
    def analyze_pattern_evolution(self, historical_attempts: List[Dict]) -> Dict:
        """
        Analyze evolution of evasion attempts over time
        Identifies if attacker is learning and adapting
        
        Args:
            historical_attempts: List of previous evasion detection results
        
        Returns:
            Analysis of evasion sophistication trend
        """
        
        if not historical_attempts or len(historical_attempts) < 2:
            return {'status': 'insufficient_data', 'recommendation': 'Collect more samples'}
        
        scores = [attempt.get('evasion_score', 0) for attempt in historical_attempts]
        techniques = [attempt.get('detected_techniques', []) for attempt in historical_attempts]
        
        # Calculate trend
        score_trend = 'increasing' if scores[-1] > scores[0] else 'decreasing' if scores[-1] < scores[0] else 'stable'
        
        # Count unique techniques
        unique_techniques = set()
        for attempt_techniques in techniques:
            for tech in attempt_techniques:
                unique_techniques.add(tech.get('technique'))
        
        return {
            'total_attempts': len(historical_attempts),
            'evasion_trend': score_trend,
            'average_score': round(sum(scores) / len(scores), 2),
            'max_score': round(max(scores), 2),
            'unique_techniques_used': len(unique_techniques),
            'attacker_evolution': 'LEARNING' if score_trend == 'increasing' else 'RETREATING',
            'recommendation': 'This appears to be a learning adversary - isolate honeypot for safety' if score_trend == 'increasing' else 'Attacker skill appears to be declining'
        }
