"""
Kill Chain & Severity Scoring Engine
Week 3-4 Implementation: MITRE ATT&CK Mapping + Kill Chain Reconstruction
Maps incidents to kill chain phases and assigns dynamic severity scores
"""

import json
import requests
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import logging
from enum import Enum
from app.database import get_db_session
from app.models import AttackLog, KillChainEvent, Alert

logger = logging.getLogger(__name__)

class KillChainPhase(Enum):
    """Lockheed Martin Kill Chain phases"""
    RECONNAISSANCE = ("reconnaissance", 0.2, "Early phase: attacker gathering info")
    WEAPONIZATION = ("weaponization", 0.3, "Attacker prepares tools/exploits")
    DELIVERY = ("delivery", 0.4, "Malware/tool delivered to target")
    EXPLOITATION = ("exploitation", 0.6, "Attacker exploits vulnerability")
    INSTALLATION = ("installation", 0.7, "Malware/backdoor installed")
    COMMAND_CONTROL = ("command_and_control", 0.8, "Attacker establishes C2")
    ACTIONS_ON_OBJECTIVES = ("actions_on_objectives", 1.0, "Data exfil, lateral move, etc")
    
    def __init__(self, name: str, base_severity: float, description: str):
        self.phase_name = name
        self.base_severity = base_severity
        self.description = description

class MitreTactic(Enum):
    """MITRE ATT&CK Tactics (Enterprise)"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class KillChainMapper:
    """
    Maps honeytoken triggers to MITRE ATT&CK framework.
    Calculates severity based on kill chain phase and attack context.
    """
    
    # MITRE ATT&CK techniques database (simplified)
    MITRE_TECHNIQUES = {
        'reconnaissance': {
            'search_open_websites': ('T1589', 'Active Scanning'),
            'account_discovery': ('T1087', 'Account Discovery'),
            'network_scanning': ('T1046', 'Network Service Scanning'),
        },
        'initial_access': {
            'phishing': ('T1566', 'Phishing'),
            'valid_accounts': ('T1078', 'Valid Accounts'),
            'supply_chain_compromise': ('T1195', 'Supply Chain Compromise'),
        },
        'credential_access': {
            'brute_force': ('T1110', 'Brute Force'),
            'credential_stuffing': ('T1110.004', 'Credential Stuffing'),
            'exploitation_for_creds': ('T1212', 'Exploitation for Credential Access'),
            'honeypot_access': ('T1110', 'Brute Force / Honeytoken Access'),
        },
        'discovery': {
            'account_discovery': ('T1087', 'Account Discovery'),
            'permission_groups_discovery': ('T1087', 'Permission Groups Discovery'),
            'software_discovery': ('T1518', 'Software Discovery'),
        },
        'lateral_movement': {
            'remote_services': ('T1021', 'Remote Services'),
            'use_alternate_auth': ('T1550', 'Use Alternate Authentication Material'),
            'ssh_authorized_keys': ('T1098.004', 'SSH Authorized Keys'),
        },
        'command_control': {
            'dns': ('T1071.004', 'DNS'),
            'application_layer_protocol': ('T1071', 'Application Layer Protocol'),
            'encrypted_channel': ('T1573', 'Encrypted Channel'),
        },
        'exfiltration': {
            'data_exfiltration': ('T1020', 'Data Exfiltration via Privileged Port'),
            'exfil_over_unencrypted': ('T1048.003', 'Exfiltration Over Unencrypted'),
        }
    }
    
    # Attack indicators to tactic mapping
    ATTACK_INDICATORS = {
        'aws_key': ('credential_access', 'CRITICAL', 'AWS credentials compromise'),
        'db_credential': ('credential_access', 'CRITICAL', 'Database credentials used'),
        'api_key': ('credential_access', 'HIGH', 'API key unauthorized access'),
        'ssh_key': ('lateral_movement', 'CRITICAL', 'SSH key unauthorized'),
        'github_token': ('credential_access', 'CRITICAL', 'GitHub token compromise'),
        'database_query': ('discovery', 'MEDIUM', 'Unauthorized DB discovery'),
        'file_access': ('collection', 'HIGH', 'Unauthorized file collection'),
        'command_exec': ('execution', 'CRITICAL', 'Command execution detected'),
    }
    
    def __init__(self):
        self.cache = {}  # MITRE ATT&CK data cache
        self.severity_multipliers = {
            'repeat_offender': 1.3,      # Repeated attacker = higher severity
            'unusual_time': 1.2,          # Off-hours access
            'geographic_anomaly': 1.4,   # Access from new location
            'escalated_privileges': 1.5, # If credentials used for escalation
            'lateral_movement_detected': 1.4,
        }
    
    def classify_attack(self, attack_log: AttackLog) -> Tuple[str, str, float]:
        """
        Classify attack to tactic and technique.
        
        Returns:
            (tactic, technique_id, confidence_score)
        """
        # Analyze attack log characteristics
        metadata = attack_log.attack_metadata or {}
        classification = attack_log.classification or ''
        
        # Simple classifier (extensible to ML model)
        tactic = 'credential_access'  # Default to most common
        confidence = 0.7
        
        # Check for specific indicators
        if 'ssh' in classification.lower() or 'ssh_key' in str(metadata):
            tactic = 'lateral_movement'
            confidence = 0.85
        elif 'database' in classification.lower():
            tactic = 'discovery'
            confidence = 0.75
        elif 'api' in classification.lower():
            tactic = 'credential_access'
            confidence = 0.8
        elif 'command' in classification.lower():
            tactic = 'execution'
            confidence = 0.9
        
        # Get MITRE technique
        if tactic in self.MITRE_TECHNIQUES:
            techniques = self.MITRE_TECHNIQUES[tactic]
            technique_key = list(techniques.keys())[0]
            technique_id, technique_name = techniques[technique_key]
        else:
            technique_id, technique_name = 'T0001', 'Unknown'
        
        return tactic, f"{technique_id} - {technique_name}", confidence
    
    def map_to_kill_chain(self, attack_log: AttackLog) -> KillChainPhase:
        """
        Map attack to kill chain phase.
        Later phases (command control, actions on objectives) = higher severity
        """
        metadata = attack_log.attack_metadata or {}
        severity = attack_log.severity or 'MEDIUM'
        classification = attack_log.classification or ''
        
        # Map based on attack type and severity
        if severity == 'CRITICAL':
            if 'command' in classification.lower() or 'execute' in classification.lower():
                return KillChainPhase.COMMAND_CONTROL
            elif 'exfil' in classification.lower() or 'lateral' in classification.lower():
                return KillChainPhase.ACTIONS_ON_OBJECTIVES
            else:
                return KillChainPhase.INSTALLATION
        
        elif severity == 'HIGH':
            if 'credential' in classification.lower():
                return KillChainPhase.EXPLOITATION
            else:
                return KillChainPhase.DELIVERY
        
        else:  # MEDIUM or LOW
            if 'scan' in classification.lower() or 'discovery' in classification.lower():
                return KillChainPhase.RECONNAISSANCE
            else:
                return KillChainPhase.WEAPONIZATION
    
    def calculate_severity_score(self, attack_log: AttackLog, 
                                anomaly_score: Optional[float] = None,
                                is_repeat_offender: bool = False,
                                geographic_anomaly: bool = False) -> Tuple[float, str]:
        """
        Calculate dynamic severity score based on multiple factors.
        
        Factors:
        - Kill chain phase (reconnaissance < actions_on_objectives)
        - Anomaly score (if provided)
        - Attack frequency (repeat offender)
        - Geographic anomalies
        - Credential type accessed
        
        Returns:
            (severity_score: 0-1, severity_level: CRITICAL/HIGH/MEDIUM/LOW)
        """
        # Start with kill chain phase base severity
        kill_chain = self.map_to_kill_chain(attack_log)
        base_score = kill_chain.base_severity
        
        # Apply anomaly factor
        if anomaly_score is not None:
            base_score = base_score * (0.5 + anomaly_score)  # Weight by anomaly
        
        # Apply multipliers
        multiplier = 1.0
        reasons = []
        
        if is_repeat_offender:
            multiplier *= self.severity_multipliers['repeat_offender']
            reasons.append("Repeat attacker")
        
        if geographic_anomaly:
            multiplier *= self.severity_multipliers['geographic_anomaly']
            reasons.append("Geographic anomaly detected")
        
        if attack_log.timestamp:
            hour = attack_log.timestamp.hour
            if hour < 6 or hour > 22:  # Off-hours access
                multiplier *= self.severity_multipliers['unusual_time']
                reasons.append("Off-hours access")
        
        final_score = min(1.0, base_score * multiplier)
        
        # Categorize
        if final_score >= 0.8:
            level = 'CRITICAL'
        elif final_score >= 0.6:
            level = 'HIGH'
        elif final_score >= 0.4:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return final_score, level, reasons
    
    def generate_kill_chain_event(self, attack_log: AttackLog,
                                 anomaly_score: Optional[float] = None) -> KillChainEvent:
        """Create and return a kill chain event record"""
        tactic, technique, confidence = self.classify_attack(attack_log)
        kill_chain = self.map_to_kill_chain(attack_log)
        severity_score, _, _ = self.calculate_severity_score(
            attack_log, 
            anomaly_score=anomaly_score
        )
        
        event = KillChainEvent(
            attack_log_id=str(attack_log.id),
            mitre_tactic=tactic,
            mitre_technique=technique,
            kill_chain_phase=kill_chain.phase_name,
            severity_score=severity_score,
            confidence=confidence,
            mapped_at=datetime.utcnow()
        )
        return event
    
    def store_kill_chain_event(self, event: KillChainEvent) -> bool:
        """Store kill chain event in database"""
        session = get_db_session()
        try:
            session.add(event)
            session.commit()
            logger.info(f"Stored kill chain event: {event.mitre_tactic}")
            return True
        except Exception as e:
            logger.error(f"Error storing kill chain event: {e}")
            return False
        finally:
            session.close()
    
    def get_kill_chain_report(self, start_time: datetime, 
                             end_time: datetime) -> Dict:
        """Generate kill chain report for time period"""
        session = get_db_session()
        try:
            events = session.query(KillChainEvent).filter(
                KillChainEvent.mapped_at >= start_time,
                KillChainEvent.mapped_at <= end_time
            ).all()
            
            # Aggregate by tactic
            tactic_counts = {}
            phase_counts = {}
            max_severity = 0
            
            for event in events:
                tactic = event.mitre_tactic
                phase = event.kill_chain_phase
                
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                phase_counts[phase] = phase_counts.get(phase, 0) + 1
                max_severity = max(max_severity, float(event.severity_score or 0))
            
            return {
                'total_events': len(events),
                'tactic_distribution': tactic_counts,
                'phase_distribution': phase_counts,
                'max_severity': max_severity,
                'time_period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Error generating kill chain report: {e}")
            return {}
        finally:
            session.close()


# Global instance
kill_chain_mapper = None

def init_kill_chain_mapper():
    """Initialize the global kill chain mapper"""
    global kill_chain_mapper
    kill_chain_mapper = KillChainMapper()
    logger.info("Kill chain mapper initialized")

def get_kill_chain_mapper() -> KillChainMapper:
    """Get or initialize the kill chain mapper"""
    global kill_chain_mapper
    if kill_chain_mapper is None:
        init_kill_chain_mapper()
    return kill_chain_mapper
