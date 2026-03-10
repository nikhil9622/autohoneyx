"""
Incident Analysis Orchestrator
Coordinates all analysis engines: anomaly detection, kill chain mapping,
forensic collection, timeline building, and automated response
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from app.database import get_db_session
from app.models import AttackLog, Alert, AnomalyDetection, KillChainEvent

# Import all analysis engines
from app.anomaly_detector import get_anomaly_engine
from app.kill_chain_analyzer import get_kill_chain_mapper
from app.siem_connector import get_siem_manager
from app.forensics_collector import get_forensics_collector
from app.incident_rca import get_timeline_builder, get_rca_engine
from app.playbook_engine import get_playbook_engine

logger = logging.getLogger(__name__)

class IncidentOrchestrator:
    """
    Master orchestrator for incident analysis and response.
    Coordinates all detection, analysis, and response engines.
    """
    
    def __init__(self):
        self.anomaly_engine = get_anomaly_engine()
        self.kill_chain_mapper = get_kill_chain_mapper()
        self.siem_manager = get_siem_manager()
        self.forensics_collector = get_forensics_collector()
        self.timeline_builder = get_timeline_builder()
        self.rca_engine = get_rca_engine()
        self.playbook_engine = get_playbook_engine()
        self.session = get_db_session()
    
    async def process_attack(self, attack_log: AttackLog) -> Dict[str, Any]:
        """
        Full incident processing pipeline.
        Runs all analysis engines in coordinated sequence.
        
        Returns comprehensive incident analysis report
        """
        logger.info(f"Processing attack from {attack_log.source_ip}")
        
        analysis_report = {
            'attack_id': str(attack_log.id),
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': attack_log.source_ip,
            'stages': {}
        }
        
        try:
            # Stage 1: Anomaly Detection
            logger.info("Stage 1: Running anomaly detection...")
            anomaly_score, is_anomalous, anomaly_reason = self.anomaly_engine.detect(attack_log)
            self.anomaly_engine.store_results(
                attack_log, 
                anomaly_score, 
                is_anomalous, 
                anomaly_reason
            )
            
            analysis_report['stages']['anomaly_detection'] = {
                'score': anomaly_score,
                'is_anomalous': is_anomalous,
                'reason': anomaly_reason
            }
            logger.info(f"Anomaly score: {anomaly_score:.3f} (anomalous: {is_anomalous})")
            
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            analysis_report['stages']['anomaly_detection'] = {'error': str(e)}
        
        try:
            # Stage 2: Kill Chain Mapping & Severity Scoring
            logger.info("Stage 2: Mapping to kill chain...")
            kill_chain_event = self.kill_chain_mapper.generate_kill_chain_event(
                attack_log,
                anomaly_score=anomaly_score if 'anomaly_score' in analysis_report.get('stages', {}).get('anomaly_detection', {}) else None
            )
            self.kill_chain_mapper.store_kill_chain_event(kill_chain_event)
            
            severity_score, severity_level, severity_reasons = self.kill_chain_mapper.calculate_severity_score(
                attack_log,
                anomaly_score=anomaly_score if 'anomaly_score' in analysis_report.get('stages', {}).get('anomaly_detection', {}) else None
            )
            
            analysis_report['stages']['kill_chain_mapping'] = {
                'mitre_tactic': kill_chain_event.mitre_tactic,
                'mitre_technique': kill_chain_event.mitre_technique,
                'kill_chain_phase': kill_chain_event.kill_chain_phase,
                'severity_score': severity_score,
                'severity_level': severity_level,
                'severity_factors': severity_reasons
            }
            logger.info(f"Kill chain phase: {kill_chain_event.kill_chain_phase} (severity: {severity_level})")
            
        except Exception as e:
            logger.error(f"Kill chain mapping error: {e}")
            analysis_report['stages']['kill_chain_mapping'] = {'error': str(e)}
        
        try:
            # Stage 3: Forensic Artifact Collection
            logger.info("Stage 3: Collecting forensic artifacts...")
            artifacts = self.forensics_collector.collect_all(attack_log)
            artifact_count = self.forensics_collector.store_artifacts(artifacts)
            
            analysis_report['stages']['forensics'] = {
                'artifacts_collected': len(artifacts),
                'artifact_types': [a.artifact_type for a in artifacts]
            }
            logger.info(f"Collected {len(artifacts)} forensic artifacts")
            
        except Exception as e:
            logger.error(f"Forensic collection error: {e}")
            analysis_report['stages']['forensics'] = {'error': str(e)}
        
        try:
            # Stage 4: Timeline & RCA Analysis
            logger.info("Stage 4: Building incident timeline and RCA...")
            
            # Get honeytoken for this attack
            honeytoken = self.session.query(AttackLog).first()
            if honeytoken:
                timeline_events = self.timeline_builder.build_timeline(
                    str(attack_log.id),
                    time_window_hours=24
                )
                
                rca_analysis = self.rca_engine.analyze_attack(attack_log)
                
                # Get correlated incidents
                correlations = self.rca_engine.correlate_incidents(
                    attack_log.source_ip,
                    time_window_hours=24
                )
                
                analysis_report['stages']['timeline_and_rca'] = {
                    'timeline_events': len(timeline_events),
                    'root_causes': rca_analysis['root_causes'],
                    'attack_pattern': rca_analysis['attack_pattern'],
                    'confidence': rca_analysis['confidence'],
                    'recommendations': rca_analysis['recommendations'],
                    'correlated_incidents': correlations.get('attack_count', 0)
                }
                logger.info(f"Identified attack pattern: {rca_analysis['attack_pattern']}")
            
        except Exception as e:
            logger.error(f"Timeline/RCA error: {e}")
            analysis_report['stages']['timeline_and_rca'] = {'error': str(e)}
        
        try:
            # Stage 5: SIEM Event Forwarding
            logger.info("Stage 5: Forwarding to SIEM platforms...")
            kill_chain = analysis_report['stages'].get('kill_chain_mapping', {})
            anomaly_data = {
                'score': analysis_report['stages'].get('anomaly_detection', {}).get('score'),
                'is_anomalous': analysis_report['stages'].get('anomaly_detection', {}).get('is_anomalous')
            }
            
            siem_success = self.siem_manager.send_event(
                attack_log,
                kill_chain_event if 'kill_chain_event' in locals() else None,
                anomaly_data
            )
            
            analysis_report['stages']['siem_forwarding'] = {
                'success': siem_success,
                'platforms': list(self.siem_manager.connectors.keys())
            }
            logger.info(f"SIEM forwarding: {siem_success}")
            
        except Exception as e:
            logger.error(f"SIEM forwarding error: {e}")
            analysis_report['stages']['siem_forwarding'] = {'error': str(e)}
        
        try:
            # Stage 6: Automated Response via Playbooks
            logger.info("Stage 6: Evaluating automated response...")
            response_taken = False
            
            # Determine if automated response is needed
            severity_level = analysis_report['stages'].get('kill_chain_mapping', {}).get('severity_level', 'MEDIUM')
            
            if severity_level == 'CRITICAL':
                # Execute immediate response playbook
                playbook_engine = get_playbook_engine()
                
                try:
                    execution = await playbook_engine.execute_playbook(
                        'credential_compromise_response',
                        'immediate_response'
                    )
                    response_taken = True
                    analysis_report['stages']['automated_response'] = {
                        'playbook': 'credential_compromise_response',
                        'status': execution.execution_status,
                        'actions_executed': len(execution.results.get('actions', []))
                    }
                    logger.info(f"Executed playbook: {execution.execution_status}")
                    
                except Exception as pb_error:
                    logger.warning(f"Playbook execution skipped: {pb_error}")
            
            analysis_report['stages']['automated_response'] = {
                'response_triggered': response_taken,
                'severity_level': severity_level
            }
            
        except Exception as e:
            logger.error(f"Automated response error: {e}")
            analysis_report['stages']['automated_response'] = {'error': str(e)}
        
        # Create high-level alert
        try:
            alert = self._create_alert(attack_log, analysis_report)
            if alert:
                self.session.add(alert)
                self.session.commit()
                analysis_report['alert_created'] = True
                logger.info(f"Alert created: {alert.severity} - {alert.title}")
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
        
        logger.info(f"Incident processing complete: {analysis_report}")
        return analysis_report
    
    def _create_alert(self, attack_log: AttackLog, 
                     analysis_report: Dict) -> Optional[Alert]:
        """Create high-level alert from analysis report"""
        try:
            kill_chain = analysis_report['stages'].get('kill_chain_mapping', {})
            rca = analysis_report['stages'].get('timeline_and_rca', {})
            
            severity_level = kill_chain.get('severity_level', 'MEDIUM')
            attack_pattern = rca.get('attack_pattern', 'Unknown pattern')
            
            alert = Alert(
                honeytoken_id=attack_log.honeytoken_id,
                attack_log_id=str(attack_log.id),
                source_ip=attack_log.source_ip,
                alert_type='attack_detected',
                severity=severity_level,
                title=f"{severity_level} - {attack_pattern}",
                message=(
                    f"Attack from {attack_log.source_ip} on {attack_log.honeypot_type}. "
                    f"Pattern: {attack_pattern}. "
                    f"MITRE: {kill_chain.get('mitre_tactic', 'Unknown')}. "
                    f"Confidence: {rca.get('confidence', 0):.1%}"
                ),
                alert_metadata={
                    'analysis_complete': True,
                    'stages_executed': list(analysis_report['stages'].keys()),
                    'mitre_tactic': kill_chain.get('mitre_tactic'),
                    'kill_chain_phase': kill_chain.get('kill_chain_phase')
                }
            )
            return alert
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    async def batch_process_attacks(self, attack_logs: List[AttackLog]) -> List[Dict]:
        """Process multiple attacks in parallel"""
        tasks = [self.process_attack(log) for log in attack_logs]
        return await asyncio.gather(*tasks, return_exceptions=True)


# Global instance
orchestrator = None

def init_orchestrator():
    """Initialize the global incident orchestrator"""
    global orchestrator
    orchestrator = IncidentOrchestrator()
    logger.info("Incident orchestrator initialized")

def get_orchestrator() -> IncidentOrchestrator:
    """Get or initialize the orchestrator"""
    global orchestrator
    if orchestrator is None:
        init_orchestrator()
    return orchestrator

async def process_incident(attack_log: AttackLog) -> Dict:
    """Process a single incident through full pipeline"""
    orchestrator = get_orchestrator()
    return await orchestrator.process_attack(attack_log)
