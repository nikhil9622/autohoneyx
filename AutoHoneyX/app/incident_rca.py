"""
Incident Timeline & Root Cause Analysis (RCA) Engine
Week 10-11 Implementation: Build event timelines and identify attack patterns
Correlates events to reconstruct attack narrative and suggest root causes
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import networkx as nx

from app.database import get_db_session
from app.models import (
    AttackLog, 
    IncidentTimeline, 
    ForensicArtifact,
    KillChainEvent,
    Honeytoken
)

logger = logging.getLogger(__name__)

class TimelineEvent:
    """Represents a single event in incident timeline"""
    
    def __init__(self, event_type: str, timestamp: datetime, 
                 description: str, severity: str, related_data: Dict = None):
        self.event_type = event_type
        self.timestamp = timestamp
        self.description = description
        self.severity = severity
        self.related_data = related_data or {}

class IncidentTimelineBuilder:
    """
    Builds comprehensive timelines of incidents.
    Shows attack progression from initial access to impact.
    """
    
    # Event type definitions
    EVENT_TYPES = {
        'token_created': 'Honeytoken created',
        'token_injected': 'Honeytoken injected into system',
        'token_accessed': 'Honeytoken accessed/triggered',
        'anomaly_detected': 'Anomalous access pattern detected',
        'kill_chain_mapped': 'Attack mapped to kill chain',
        'artifact_collected': 'Forensic artifact collected',
        'alert_raised': 'Alert generated',
        'escalation': 'Privilege escalation detected',
        'lateral_movement': 'Lateral movement detected',
        'data_exfil': 'Data exfiltration detected',
    }
    
    def __init__(self):
        self.session = get_db_session()
    
    def build_timeline(self, honeytoken_id: str, 
                      time_window_hours: int = 24) -> List[IncidentTimeline]:
        """
        Build timeline for a specific honeytoken trigger.
        Reconstructs events surrounding the token access.
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            # Fetch all related events
            honeytoken = self.session.query(Honeytoken).filter(
                Honeytoken.id == honeytoken_id
            ).first()
            
            if not honeytoken:
                logger.warning(f"Honeytoken {honeytoken_id} not found")
                return []
            
            attack_logs = self.session.query(AttackLog).filter(
                AttackLog.honeytoken_id == honeytoken_id,
                AttackLog.timestamp >= cutoff_time
            ).order_by(AttackLog.timestamp).all()
            
            timeline_events = []
            sequence = 0
            
            # Event 1: Token creation
            if honeytoken.created_at:
                sequence += 1
                timeline_events.append(IncidentTimeline(
                    event_sequence=sequence,
                    event_type='token_created',
                    event_description=f"Honeytoken created: {honeytoken.token_type}",
                    event_timestamp=honeytoken.created_at,
                    related_artifacts={
                        'token_id': honeytoken.token_id,
                        'token_type': honeytoken.token_type,
                        'location': honeytoken.location_file
                    }
                ))
            
            # Event 2: Token injection (if applicable)
            # This would be tracked separately in injection logs
            sequence += 1
            timeline_events.append(IncidentTimeline(
                event_sequence=sequence,
                event_type='token_injected',
                event_description=f"Honeytoken injected into location",
                event_timestamp=honeytoken.created_at + timedelta(seconds=5),
                related_artifacts={'file_path': honeytoken.location_file}
            ))
            
            # Event 3: Token access events
            kill_chains = self.session.query(KillChainEvent).filter(
                KillChainEvent.attack_log_id.in_([log.id for log in attack_logs])
            ).all()
            
            for log in attack_logs:
                sequence += 1
                
                # Find corresponding kill chain
                kc = next((kc for kc in kill_chains if str(kc.attack_log_id) == str(log.id)), None)
                
                timeline_events.append(IncidentTimeline(
                    event_sequence=sequence,
                    event_type='token_accessed',
                    event_description=(
                        f"Token accessed from {log.source_ip} via {log.honeypot_type} "
                        f"(User-Agent: {log.user_agent[:50] if log.user_agent else 'unknown'})"
                    ),
                    event_timestamp=log.timestamp,
                    related_artifacts={
                        'source_ip': log.source_ip,
                        'honeypot_type': log.honeypot_type,
                        'severity': log.severity,
                        'kill_chain_phase': kc.kill_chain_phase if kc else None,
                        'mitre_tactic': kc.mitre_tactic if kc else None
                    }
                ))
            
            # Store timeline events
            for event in timeline_events:
                event.attack_log_id = str(attack_logs[0].id) if attack_logs else None
                self.session.add(event)
            
            self.session.commit()
            
            logger.info(f"Built timeline with {len(timeline_events)} events")
            return timeline_events
            
        except Exception as e:
            logger.error(f"Error building timeline: {e}")
            return []
    
    def get_timeline_for_source_ip(self, source_ip: str, 
                                  days: int = 7) -> List[Dict[str, Any]]:
        """Get timeline of all activities from a specific source IP"""
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            attacks = self.session.query(AttackLog).filter(
                AttackLog.source_ip == source_ip,
                AttackLog.timestamp >= cutoff
            ).order_by(AttackLog.timestamp).all()
            
            timeline = []
            for i, attack in enumerate(attacks, 1):
                timeline.append({
                    'sequence': i,
                    'timestamp': attack.timestamp.isoformat(),
                    'type': 'attack',
                    'honeypot': attack.honeypot_type,
                    'severity': attack.severity,
                    'description': f"{attack.honeypot_type.upper()} honeypot access"
                })
            
            return timeline
            
        except Exception as e:
            logger.error(f"Error getting timeline for {source_ip}: {e}")
            return []


class RCAEngine:
    """
    Root Cause Analysis Engine
    Identifies patterns, attack chains, and likely root causes of incidents
    """
    
    def __init__(self):
        self.session = get_db_session()
    
    def analyze_attack(self, attack_log: AttackLog) -> Dict[str, Any]:
        """
        Analyze a single attack and provide RCA suggestions
        
        Returns dict with:
        - root_causes: list of likely root causes
        - attack_pattern: identified pattern
        - recommendations: mitigation recommendations
        - confidence: 0-1 confidence score
        """
        try:
            rca_data = {
                'root_causes': [],
                'attack_pattern': '',
                'recommendations': [],
                'confidence': 0.0,
                'indicators': []
            }
            
            # Get context: similar attacks
            similar_attacks = self.session.query(AttackLog).filter(
                AttackLog.honeypot_type == attack_log.honeypot_type,
                AttackLog.severity == attack_log.severity,
                AttackLog.timestamp >= datetime.utcnow() - timedelta(days=7)
            ).all()
            
            # Analyze IP reputation
            source_ip_history = self.session.query(AttackLog).filter(
                AttackLog.source_ip == attack_log.source_ip
            ).all()
            
            if len(source_ip_history) > 10:
                rca_data['root_causes'].append({
                    'cause': 'Compromised or malicious IP',
                    'indicator': f'{len(source_ip_history)} attacks from this IP',
                    'severity': 'HIGH'
                })
                rca_data['confidence'] += 0.3
            
            # Analyze credential access patterns
            if 'credential' in str(attack_log.classification).lower():
                # Check if same credentials used elsewhere
                rca_data['root_causes'].append({
                    'cause': 'Credential compromise',
                    'indicator': 'Honeytoken indicates credential theft',
                    'severity': 'CRITICAL'
                })
                rca_data['recommendations'].append({
                    'action': 'Reset all credentials from affected scope',
                    'priority': 'CRITICAL',
                    'timeframe': 'Immediate'
                })
                rca_data['confidence'] += 0.4
            
            # Analyze timing patterns
            hourly_attacks = self._analyze_temporal_pattern(attack_log)
            if hourly_attacks > 5:
                rca_data['indicators'].append(f"High-frequency attacks: {hourly_attacks}/hour")
                rca_data['confidence'] += 0.15
            
            # Analyze user agent
            if attack_log.user_agent:
                if self._is_suspicious_user_agent(attack_log.user_agent):
                    rca_data['root_causes'].append({
                        'cause': 'Automated attack tool detected',
                        'indicator': f'Suspicious user agent: {attack_log.user_agent[:50]}',
                        'severity': 'MEDIUM'
                    })
                    rca_data['confidence'] += 0.2
            
            # Attack pattern classification
            pattern = self._classify_attack_pattern(
                attack_log, 
                similar_attacks,
                source_ip_history
            )
            rca_data['attack_pattern'] = pattern
            
            # Normalize confidence to 0-1
            rca_data['confidence'] = min(1.0, rca_data['confidence'])
            
            return rca_data
            
        except Exception as e:
            logger.error(f"Error in RCA analysis: {e}")
            return {
                'root_causes': [],
                'attack_pattern': 'Unknown',
                'recommendations': [],
                'confidence': 0.0,
                'indicators': [str(e)]
            }
    
    def _analyze_temporal_pattern(self, attack_log: AttackLog) -> int:
        """Analyze attack frequency in the last hour"""
        try:
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            count = self.session.query(AttackLog).filter(
                AttackLog.source_ip == attack_log.source_ip,
                AttackLog.timestamp >= one_hour_ago
            ).count()
            return count
        except Exception:
            return 0
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent matches known suspicious patterns"""
        suspicious_patterns = [
            'curl', 'wget', 'python', 'java', 'scanner', 'crawler',
            'bot', 'nmap', 'metasploit', 'sqlmap', 'nikto', 'burp'
        ]
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in suspicious_patterns)
    
    def _classify_attack_pattern(self, attack_log: AttackLog,
                                similar_attacks: List[AttackLog],
                                history: List[AttackLog]) -> str:
        """Classify the type of attack pattern"""
        
        if len(history) > 50:
            return "Persistent threat - Multiple attempts over time"
        elif len(history) > 10:
            return "Targeted attack - Repeated attempts suggest reconnaissance"
        elif len(similar_attacks) > 3:
            return "Campaign attack - Similar attacks across multiple honeypots"
        elif attack_log.severity == 'CRITICAL':
            return "Opportunistic attack - High severity single attempt"
        else:
            return "Low-risk probe - Isolated access attempt"
    
    def correlate_incidents(self, 
                           source_ip: str,
                           time_window_hours: int = 24) -> Dict[str, Any]:
        """
        Correlate multiple incidents from same source.
        Build attack narrative.
        """
        try:
            cutoff = datetime.utcnow() - timedelta(hours=time_window_hours)
            
            attacks = self.session.query(AttackLog).filter(
                AttackLog.source_ip == source_ip,
                AttackLog.timestamp >= cutoff
            ).order_by(AttackLog.timestamp).all()
            
            if not attacks:
                return {'status': 'no_attacks'}
            
            # Build attack chain
            chain = {
                'source_ip': source_ip,
                'attack_count': len(attacks),
                'time_span': (attacks[-1].timestamp - attacks[0].timestamp).total_seconds() / 60,  # minutes
                'honeypots_targeted': list(set(a.honeypot_type for a in attacks)),
                'severities': list(set(a.severity for a in attacks)),
                'attack_sequence': []
            }
            
            for i, attack in enumerate(attacks):
                chain['attack_sequence'].append({
                    'sequence': i + 1,
                    'timestamp': attack.timestamp.isoformat(),
                    'honeypot': attack.honeypot_type,
                    'method': attack.request_method or 'unknown',
                    'severity': attack.severity
                })
            
            # Generate narrative
            narrative = self._generate_narrative(chain)
            chain['narrative'] = narrative
            
            return chain
            
        except Exception as e:
            logger.error(f"Error correlating incidents: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _generate_narrative(self, chain: Dict) -> str:
        """Generate human-readable attack narrative"""
        honeypots = ', '.join(chain['honeypots_targeted'])
        time_span = chain['time_span']
        
        narrative = (
            f"Attacker from {chain['source_ip']} launched {chain['attack_count']} "
            f"attacks over {time_span:.1f} minutes targeting {honeypots}. "
        )
        
        if chain['attack_count'] > 10:
            narrative += "Pattern suggests automated scanning or brute force."
        elif 'ssh' in honeypots and 'web' in honeypots:
            narrative += "Pattern suggests lateral movement exploration."
        elif any(s == 'CRITICAL' for s in chain['severities']):
            narrative += "High-severity access detected; likely escalation attempt."
        
        return narrative


# Global instances
timeline_builder = None
rca_engine = None

def init_timeline_builders():
    """Initialize global timeline and RCA engines"""
    global timeline_builder, rca_engine
    timeline_builder = IncidentTimelineBuilder()
    rca_engine = RCAEngine()
    logger.info("Timeline and RCA engines initialized")

def get_timeline_builder() -> IncidentTimelineBuilder:
    """Get or initialize timeline builder"""
    global timeline_builder
    if timeline_builder is None:
        init_timeline_builders()
    return timeline_builder

def get_rca_engine() -> RCAEngine:
    """Get or initialize RCA engine"""
    global rca_engine
    if rca_engine is None:
        init_timeline_builders()
    return rca_engine
